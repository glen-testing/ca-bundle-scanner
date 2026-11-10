//! ca-bundle-scanner: find compromised or distrusted CA certificates in trust
//! stores, bundles, binaries and archives.

pub mod builtin;
pub mod der;
pub mod detect;
pub mod literal;
pub mod locations;
pub mod pem;
pub mod profile;
pub mod report;
pub mod scan;
pub mod util;
#[cfg(windows)]
mod winstore;

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use walkdir::WalkDir;

use locations::{Kind as LocKind, Location};
use profile::Profile;
use report::{Context, Finding, Issue, LocationResult, LocationStatus, Report, Severity};
use scan::{FileScan, Limits};

pub struct Config {
    pub profile: Profile,
    pub limits: Limits,
    pub system: bool,
    pub home_scan: bool,
    pub root: Option<PathBuf>,
    pub paths: Vec<PathBuf>,
    pub binaries: Vec<PathBuf>,
    pub jobs: usize,
    pub env: locations::Env,
    pub os: String,
}

/// Directory names never descended into by the home scan.
const HOME_SKIP: &[&str] = &[
    "node_modules",
    ".git",
    "__pycache__",
    "target",
    ".npm",
    ".yarn",
    ".cache/pip",
    ".cargo/registry",
    ".cargo/git",
    ".rustup/toolchains",
    ".gradle/caches",
    ".m2/repository",
];
const HOME_SCAN_MAX_DEPTH: usize = 12;
/// Depth for `-p` directory walks.
const EXPLICIT_DEPTH: usize = 32;
/// Files at least this large are memory-mapped instead of read.
const MMAP_MIN: u64 = 1 << 20;

#[derive(Default)]
struct FileResult {
    findings: Vec<Finding>,
    issues: Vec<Issue>,
    scanned: bool,
}

/// Identity of a file across symlinks and duplicate paths.
#[derive(Hash, PartialEq, Eq)]
enum FileKey {
    #[cfg(unix)]
    Inode(u64, u64),
    #[cfg(not(unix))]
    Path(PathBuf),
}

fn file_key(path: &Path, meta: &std::fs::Metadata) -> FileKey {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = path;
        FileKey::Inode(meta.dev(), meta.ino())
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        FileKey::Path(std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()))
    }
}

fn panic_text(p: Box<dyn std::any::Any + Send>) -> String {
    p.downcast_ref::<&str>()
        .map(|s| s.to_string())
        .or_else(|| p.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "unknown panic".into())
}

/// Run `f`; a panic (e.g. inside a decoder) becomes an error issue and the
/// findings collected before it are kept.
fn guarded(fs: &mut FileScan<'_>, path: &str, f: impl FnOnce(&mut FileScan<'_>)) {
    if let Err(p) = catch_unwind(AssertUnwindSafe(|| f(fs))) {
        fs.issues.push(Issue {
            path: path.to_string(),
            severity: Severity::Error,
            message: format!(
                "internal error while scanning ({}); results for this file are partial",
                panic_text(p)
            ),
        });
    }
}

/// Scan one file from disk; a panic inside a decoder is reported, not fatal.
fn scan_file(path: &Path, context: Context, profile: &Profile, limits: &Limits) -> FileResult {
    let display = path.display().to_string();
    let mut res = FileResult::default();
    let err = |res: &mut FileResult, message: String| {
        res.issues.push(Issue {
            path: display.clone(),
            severity: Severity::Error,
            message,
        })
    };
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            err(&mut res, format!("unreadable: {e}"));
            return res;
        }
    };
    let len = match file.metadata() {
        Ok(m) => m.len(),
        Err(e) => {
            err(&mut res, format!("unreadable: {e}"));
            return res;
        }
    };
    if len > limits.max_file {
        err(
            &mut res,
            format!(
                "{} MiB exceeds the {} MiB file limit; not scanned",
                len >> 20,
                limits.max_file >> 20
            ),
        );
        return res;
    }
    let owned;
    let mapped;
    let data: &[u8] = if len >= MMAP_MIN {
        // SAFETY: read-only mapping; a concurrent truncation can fault, as with any mmap reader.
        match unsafe { memmap2::Mmap::map(&file) } {
            Ok(m) => {
                mapped = m;
                &mapped
            }
            Err(e) => {
                err(&mut res, format!("cannot map: {e}"));
                return res;
            }
        }
    } else {
        let mut v = Vec::with_capacity(len as usize);
        if let Err(e) = (&file).read_to_end(&mut v) {
            err(&mut res, format!("unreadable: {e}"));
            return res;
        }
        owned = v;
        &owned
    };
    let mut fs = FileScan::new(profile, limits, context, len);
    guarded(&mut fs, &display, |fs| fs.scan(data, &display));
    res.findings = fs.findings;
    res.issues = fs.issues;
    res.scanned = true;
    res
}

/// Scan an in-memory blob (used for platform certificate stores).
pub fn scan_bytes(
    data: &[u8],
    name: &str,
    context: Context,
    profile: &Profile,
    limits: &Limits,
) -> (Vec<Finding>, Vec<Issue>) {
    let mut fs = FileScan::new(profile, limits, context, data.len() as u64);
    fs.scan(data, name);
    (fs.findings, fs.issues)
}

struct Walk {
    files: Vec<(PathBuf, Context)>,
    issues: Vec<Issue>,
    existed: bool,
}

fn is_home_cert_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    if matches!(
        n.as_str(),
        "cacerts" | "cacert.pem" | "ca-bundle.crt" | "ca-certificates.crt" | "cert.pem"
    ) {
        return true;
    }
    if n.starts_with("cert9.db") || n.starts_with("cert8.db") {
        return true;
    }
    matches!(
        n.rsplit_once('.').map(|(_, e)| e),
        Some(
            "pem"
                | "crt"
                | "cer"
                | "der"
                | "p7b"
                | "p7c"
                | "jks"
                | "p12"
                | "pfx"
                | "keystore"
                | "p11-kit"
        )
    )
}

/// Expand a location into the regular files to scan (symlinks followed).
fn expand(loc: &Location, home_filter: bool) -> Walk {
    let mut w = Walk {
        files: Vec::new(),
        issues: Vec::new(),
        existed: false,
    };
    let depth = match loc.kind {
        LocKind::Path { depth } | LocKind::Glob { depth } => depth,
    };
    let sev = if loc.required {
        Severity::Error
    } else {
        Severity::Warning
    };
    for root in locations::resolve(loc) {
        let meta = match std::fs::metadata(&root) {
            Ok(m) => m,
            Err(e) => {
                if loc.required {
                    w.issues.push(Issue {
                        path: root.display().to_string(),
                        severity: Severity::Error,
                        message: format!("not scanned: {e}"),
                    });
                }
                continue;
            }
        };
        w.existed = true;
        if meta.is_file() {
            w.files
                .push((root.clone(), locations::context_for(&root, loc.context)));
            continue;
        }
        if !meta.is_dir() {
            continue;
        }
        let walker = WalkDir::new(&root)
            .follow_links(true)
            .max_depth(depth.max(1))
            .into_iter()
            .filter_entry(|e| {
                !(home_filter
                    && e.file_type().is_dir()
                    && HOME_SKIP.iter().any(|s| e.path().ends_with(s)))
            });
        for entry in walker {
            match entry {
                Ok(e) => {
                    if !e.file_type().is_file() {
                        continue;
                    }
                    let name = e.file_name().to_string_lossy();
                    if home_filter && !is_home_cert_name(&name) {
                        continue;
                    }
                    let p = e.into_path();
                    let ctx = locations::context_for(&p, loc.context);
                    w.files.push((p, ctx));
                }
                Err(e) => {
                    let path = e
                        .path()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| root.display().to_string());
                    // Symlink loops are harmless; anything else limits coverage.
                    let loop_ = e.loop_ancestor().is_some();
                    w.issues.push(Issue {
                        path,
                        severity: if loop_ { Severity::Warning } else { sev },
                        message: format!("directory walk: {e}"),
                    });
                }
            }
        }
    }
    w
}

fn scan_files(
    files: &[(PathBuf, Context)],
    profile: &Profile,
    limits: &Limits,
    jobs: usize,
) -> Vec<FileResult> {
    if jobs <= 1 || files.len() <= 1 {
        return files
            .iter()
            .map(|(p, c)| scan_file(p, *c, profile, limits))
            .collect();
    }
    let next = AtomicUsize::new(0);
    let slots: Vec<Mutex<Option<FileResult>>> = files.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|s| {
        for _ in 0..jobs.min(files.len()) {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some((p, c)) = files.get(i) else { break };
                let r = scan_file(p, *c, profile, limits);
                *slots[i].lock().unwrap() = Some(r);
            });
        }
    });
    slots
        .into_iter()
        .map(|m| m.into_inner().unwrap().unwrap_or_default())
        .collect()
}

/// Run the whole scan. `progress` is called once per location that exists.
pub fn run(cfg: &Config, progress: &mut dyn FnMut(&LocationResult)) -> Report {
    let mut locs: Vec<(Location, bool)> = Vec::new();
    if cfg.system {
        for l in locations::system(&cfg.env, &cfg.os, cfg.root.as_deref()) {
            locs.push((l, false));
        }
    }
    for p in &cfg.paths {
        locs.push((locations::explicit("user path", p, EXPLICIT_DEPTH), false));
    }
    for b in &cfg.binaries {
        locs.push((locations::explicit("user binary", b, EXPLICIT_DEPTH), false));
    }
    if cfg.home_scan {
        match cfg.env.get("HOME").or(cfg.env.get("USERPROFILE")) {
            Some(h) => {
                let mut l = locations::explicit("home scan", Path::new(h), HOME_SCAN_MAX_DEPTH);
                l.required = false;
                locs.push((l, true));
            }
            None => {
                let mut r = Report::default();
                r.issues.push(Issue {
                    path: "--scan-home".into(),
                    severity: Severity::Error,
                    message: "HOME is not set; home directory not scanned".into(),
                });
                return finish(r);
            }
        }
    }

    let mut report = Report::default();
    let mut seen: HashSet<FileKey> = HashSet::new();
    for (loc, home_filter) in &locs {
        let walk = expand(loc, *home_filter);
        let walk_errors = walk
            .issues
            .iter()
            .filter(|i| i.severity == Severity::Error)
            .count();
        report.issues.extend(walk.issues);
        let mut files = Vec::new();
        let mut duplicates = 0;
        for (p, ctx) in walk.files {
            match std::fs::metadata(&p) {
                Ok(m) => {
                    if m.len() == 0 {
                        continue;
                    }
                    if seen.insert(file_key(&p, &m)) {
                        files.push((p, ctx));
                    } else {
                        duplicates += 1;
                    }
                }
                Err(e) => report.issues.push(Issue {
                    path: p.display().to_string(),
                    severity: Severity::Error,
                    message: format!("unreadable: {e}"),
                }),
            }
        }
        let results = scan_files(&files, &cfg.profile, &cfg.limits, cfg.jobs);
        let mut lr = LocationResult {
            label: loc.label.clone(),
            path: loc.pattern.clone(),
            status: if walk.existed {
                LocationStatus::Scanned
            } else {
                LocationStatus::Missing
            },
            files: 0,
            findings: 0,
            action_findings: 0,
            errors: walk_errors,
            duplicates,
        };
        for r in results {
            lr.files += r.scanned as usize;
            lr.findings += r.findings.len();
            lr.action_findings += r.findings.iter().filter(|f| f.action_required).count();
            lr.errors += r
                .issues
                .iter()
                .filter(|i| i.severity == Severity::Error)
                .count();
            report.files_scanned += r.scanned as usize;
            report.findings.extend(r.findings);
            report.issues.extend(r.issues);
        }
        if lr.errors > 0 && lr.files == 0 && walk.existed {
            lr.status = LocationStatus::Error;
        }
        if walk.existed || loc.required {
            if !walk.existed {
                lr.status = LocationStatus::Error;
            }
            progress(&lr);
        }
        report.locations.push(lr);
    }

    #[cfg(windows)]
    if cfg.system && cfg.root.is_none() {
        winstore::scan(&cfg.profile, &cfg.limits, &mut report, progress);
    }

    finish(report)
}

fn finish(mut report: Report) -> Report {
    if report.files_scanned == 0 && report.findings.is_empty() {
        report.issues.push(Issue {
            path: "-".into(),
            severity: Severity::Error,
            message: "no files were scanned; nothing to base a verdict on".into(),
        });
    }
    report.dedup();
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    const TARGET: &[u8] = include_bytes!("../certs/emudhra/EM_DV_TLS_CA_G3B_emSign.der");

    #[test]
    fn c17_panic_keeps_partial_findings_and_reports_error() {
        let p = Profile::emudhra().unwrap();
        let l = Limits::default();
        let mut fs = FileScan::new(&p, &l, Context::Trust, 0);
        guarded(&mut fs, "x", |fs| {
            fs.scan(TARGET, "x");
            panic!("decoder exploded");
        });
        assert_eq!(fs.findings.len(), 1);
        assert!(fs
            .issues
            .iter()
            .any(|i| i.severity == Severity::Error && i.message.contains("decoder exploded")));
    }

    #[test]
    fn c17_no_panic_no_error() {
        let p = Profile::emudhra().unwrap();
        let l = Limits::default();
        let mut fs = FileScan::new(&p, &l, Context::Trust, 0);
        guarded(&mut fs, "x", |fs| fs.scan(TARGET, "x"));
        assert_eq!(fs.findings.len(), 1);
        assert!(fs.issues.is_empty());
    }

    #[test]
    fn home_cert_names() {
        assert!(is_home_cert_name("CA.PEM"));
        assert!(is_home_cert_name("cert9.db-wal"));
        assert!(is_home_cert_name("bundle.p11-kit"));
        assert!(!is_home_cert_name("main.rs"));
        assert!(!is_home_cert_name("certificate.txt"));
    }
}
