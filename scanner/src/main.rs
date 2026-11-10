use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgGroup, Parser, ValueEnum};

use ca_bundle_scanner::profile::{Profile, Role};
use ca_bundle_scanner::report::{self, LocationResult, LocationStatus};
use ca_bundle_scanner::scan::Limits;
use ca_bundle_scanner::{deps, run, Config};

#[derive(Clone, Copy, ValueEnum)]
enum ProfileName {
    /// eMudhra October 2026: 16 compromised CA certificates, distrusted roots, AAA cross-sign root.
    Emudhra,
}

/// Find compromised or distrusted CA certificates in trust stores, bundles,
/// binaries and archives.
///
/// Exit codes: 0 clean, 1 finding needs action, 2 usage error,
/// 3 incomplete (nothing found, but something in scope could not be inspected).
#[derive(Parser)]
#[command(name = "ca-bundle-scanner", version, about, long_about)]
#[command(group(ArgGroup::new("certs").required(true).multiple(true)
    .args(["cert", "root_cert", "fingerprint", "profile"])))]
struct Args {
    /// PEM or DER certificate(s) to search for, treated as compromised (repeatable).
    #[arg(short = 'c', long = "cert", value_name = "FILE")]
    cert: Vec<PathBuf>,
    /// Root certificate(s) whose presence means distrusted trust (repeatable).
    #[arg(short = 'r', long = "root-cert", value_name = "FILE")]
    root_cert: Vec<PathBuf>,
    /// SHA-256 fingerprint to search for; colons allowed (repeatable).
    #[arg(short = 'f', long = "fingerprint", value_name = "HEX")]
    fingerprint: Vec<String>,
    /// Built-in certificate profile.
    #[arg(long, value_enum)]
    profile: Option<ProfileName>,

    /// Scan a binary, archive or other file for embedded certificates (repeatable).
    #[arg(short = 'b', long = "scan-binary", value_name = "PATH")]
    scan_binary: Vec<PathBuf>,
    /// Scan an additional file or directory, recursively (repeatable).
    #[arg(short = 'p', long = "scan-path", value_name = "PATH")]
    scan_path: Vec<PathBuf>,
    /// Skip the built-in system and per-user locations.
    #[arg(long)]
    no_system: bool,
    /// Also walk $HOME for certificate files (virtualenvs, caches, projects).
    #[arg(long)]
    scan_home: bool,
    /// Resolve system locations under DIR (an unpacked container image or mounted disk).
    #[arg(long, value_name = "DIR")]
    root: Option<PathBuf>,
    /// Files scanned in parallel (default: CPU count, at most 4).
    #[arg(long, value_name = "N")]
    jobs: Option<usize>,

    /// Skip dependency analysis of `-p` project folders that hold lockfiles.
    #[arg(long)]
    no_deps: bool,
    /// Dependency analysis: resolve dependencies and download each bundled CA store
    /// to inspect it (uses the network); affected dependencies then need action.
    #[arg(long, conflicts_with = "no_deps")]
    deps_online: bool,
    /// Dependency analysis: count dev/test dependencies as shipped.
    #[arg(long)]
    deps_include_dev: bool,
    /// Download cache for --deps-online (default: $XDG_CACHE_HOME/ca-certs-in-code).
    #[arg(long, value_name = "DIR")]
    deps_cache_dir: Option<PathBuf>,

    /// Print only the result and findings (no progress).
    #[arg(short, long)]
    quiet: bool,
    /// Print one JSON document on stdout.
    #[arg(short, long)]
    json: bool,
}

fn build_profile(a: &Args) -> Result<Profile, String> {
    let mut p = match a.profile {
        Some(ProfileName::Emudhra) => Profile::emudhra().map_err(|e| e.to_string())?,
        None => Profile::new("custom"),
    };
    for f in &a.cert {
        p.add_file(f, Role::Compromised)
            .map_err(|e| e.to_string())?;
    }
    for f in &a.root_cert {
        p.add_file(f, Role::DistrustedRoot)
            .map_err(|e| e.to_string())?;
    }
    for fp in &a.fingerprint {
        p.add_fingerprint(fp, Role::Compromised)
            .map_err(|e| e.to_string())?;
    }
    p.finalize();
    Ok(p)
}

fn progress_line(l: &LocationResult) {
    let status = match l.status {
        LocationStatus::Missing => "missing".to_string(),
        LocationStatus::Error => format!("ERROR ({} error(s))", l.errors),
        LocationStatus::Scanned if l.action_findings > 0 => {
            format!("FOUND {} (action required)", l.action_findings)
        }
        LocationStatus::Scanned if l.findings > 0 => {
            format!("{} informational finding(s)", l.findings)
        }
        LocationStatus::Scanned if l.errors > 0 => format!("incomplete ({} error(s))", l.errors),
        LocationStatus::Scanned if l.files == 0 && l.duplicates > 0 => {
            "already covered by an earlier location".to_string()
        }
        LocationStatus::Scanned => format!("clean ({} file(s))", l.files),
    };
    eprintln!("  {}: {} ... {status}", l.label, l.path);
}

fn main() -> ExitCode {
    let a = Args::parse();
    // Decoder panics are caught per file and reported as errors; keep stderr tidy.
    std::panic::set_hook(Box::new(|_| {}));

    let profile = match build_profile(&a) {
        Ok(p) if !p.is_empty() => p,
        Ok(_) => {
            eprintln!("error: no certificates loaded");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let chatty = !a.quiet && !a.json;
    if chatty {
        if profile.text.headline.is_empty() {
            eprintln!(
                "ca-bundle-scanner: searching for {} certificate(s)",
                profile.targets.len()
            );
        } else {
            eprintln!("ca-bundle-scanner: {}", profile.text.headline);
        }
        eprintln!(
            "  {} compromised, {} distrusted, {} cross-sign root, {} informational; OS: {}\n",
            profile.count(Role::Compromised),
            profile.count(Role::DistrustedRoot),
            profile.count(Role::CrossSignRoot),
            profile.count(Role::InfoRoot),
            std::env::consts::OS
        );
    }
    let jobs = a.jobs.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get().min(4))
            .unwrap_or(1)
    });
    let cfg = Config {
        profile,
        limits: Limits::default(),
        system: !a.no_system,
        home_scan: a.scan_home,
        root: a.root.clone(),
        paths: a.scan_path.clone(),
        binaries: a.scan_binary.clone(),
        jobs: jobs.max(1),
        env: std::env::vars().collect(),
        os: std::env::consts::OS.to_string(),
        deps: deps::Options {
            mode: if a.no_deps {
                deps::Mode::Off
            } else if a.deps_online {
                deps::Mode::Online
            } else {
                deps::Mode::Offline
            },
            include_dev: a.deps_include_dev,
            cache_dir: a.deps_cache_dir.clone(),
        },
    };
    let mut progress = |l: &LocationResult| {
        if chatty {
            progress_line(l)
        }
    };
    let report = run(&cfg, &mut progress);
    let verdict = report.verdict();

    let stdout = io::stdout();
    let mut out = stdout.lock();
    let res = if a.json {
        report::write_json(&mut out, &report, &cfg.profile)
    } else {
        let mut err = io::stderr().lock();
        let _ = writeln!(err);
        let _ = report::write_issues(&mut err, &report);
        report::write_text(&mut out, &report, &cfg.profile)
    };
    if let Err(e) = res.and_then(|_| out.flush()) {
        if e.kind() != io::ErrorKind::BrokenPipe {
            eprintln!("error: writing output: {e}");
        }
    }
    ExitCode::from(verdict.exit_code() as u8)
}
