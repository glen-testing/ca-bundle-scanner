use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;

use ca_certs_in_code::{OutputFormat, RunConfig};

/// Exit codes: 0 clean, 1 reachable bundled CA store found (with --deep-scan: one containing
/// affected roots), 2 incomplete result (a lockfile, resolver, or deep scan failed).
#[derive(Parser)]
#[command(name = "ca-certs-in-code", version, about, verbatim_doc_comment)]
struct Cli {
    /// Directory to analyze (searched recursively)
    #[arg(default_value = ".")]
    target_dir: PathBuf,
    /// Output format: human, json
    #[arg(short, long, default_value = "human")]
    format: OutputFormat,
    /// Analyze one lockfile instead of searching
    #[arg(short, long)]
    lockfile: Option<PathBuf>,
    /// Only this ecosystem: rust, python, node, go
    #[arg(short, long)]
    ecosystem: Option<ca_certs_in_code::Ecosystem>,
    /// Directory name to skip while searching (repeatable)
    #[arg(long = "exclude")]
    excludes: Vec<String>,
    /// Treat dev/test dependencies as runtime
    #[arg(long)]
    include_dev: bool,
    /// Also report bundlers present without a runtime path from the root
    #[arg(long)]
    include_unreachable: bool,
    /// Use lockfile contents only (no cargo metadata, no uv resolution)
    #[arg(long)]
    no_resolve: bool,
    /// Python version uv resolves requirements files for
    #[arg(long, default_value = "3.12")]
    python_version: String,
    /// Fetch each reachable bundle and inspect it with ca-bundle-scanner
    #[arg(long)]
    deep_scan: bool,
    /// Path to ca-bundle-scanner (default: $CA_BUNDLE_SCANNER, then PATH)
    #[arg(long)]
    scanner_path: Option<PathBuf>,
    /// Download cache for deep scan (default: $XDG_CACHE_HOME/ca-certs-in-code)
    #[arg(long)]
    cache_dir: Option<PathBuf>,
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let config = RunConfig {
        target_dir: cli.target_dir,
        lockfile_path: cli.lockfile,
        ecosystem_filter: cli.ecosystem,
        excludes: cli.excludes,
        include_dev: cli.include_dev,
        include_unreachable: cli.include_unreachable,
        no_resolve: cli.no_resolve,
        python_version: cli.python_version,
        deep_scan: cli.deep_scan,
        scanner_path: cli.scanner_path,
        cache_dir: cli.cache_dir,
        verbose: cli.verbose,
    };
    let out = ca_certs_in_code::run(&config);
    println!("{}", ca_certs_in_code::report::format_output(&out, cli.format));
    if cli.format == OutputFormat::Json {
        for e in &out.errors {
            eprintln!("error: {e}");
        }
    }
    ExitCode::from(out.exit_code(config.deep_scan))
}
