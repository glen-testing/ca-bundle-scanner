//! Dependency analysis of scanned project folders, built in from `deps/`
//! (formerly ca-certs-in-code): which dependencies bundle a CA store, whether they
//! are reachable at runtime, and (online) whether the bundled store is affected.
//! The deep scan inspects downloaded bundles in-process with dependency analysis
//! switched off, so there is no recursion.

use std::path::{Path, PathBuf};

use ca_certs_in_code::deep_scan::ScannerFinding;
use ca_certs_in_code::report::Finding as DepFinding;
use ca_certs_in_code::RunConfig;

use crate::profile::Profile;
use crate::report::{Context, Finding, Issue, Kind, Match, Severity};
use crate::scan::Limits;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Off,
    /// Lockfile contents only, no network; results are informational.
    Offline,
    /// Resolve and deep-scan dependencies (network); affected ones need action.
    Online,
}

#[derive(Clone, Debug)]
pub struct Options {
    pub mode: Mode,
    pub include_dev: bool,
    pub cache_dir: Option<PathBuf>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            mode: Mode::Offline,
            include_dev: false,
            cache_dir: None,
        }
    }
}

/// Result of inspecting one bundle: (verdict, findings), or why it could not be inspected.
pub type Inspection = Result<(String, Vec<ScannerFinding>), String>;
/// Scans one downloaded bundle with the scanner's own file scanning.
pub type Inspect = dyn Fn(&Path, &Profile, &Limits) -> Inspection;

pub struct Outcome {
    pub deps: Vec<DepFinding>,
    pub findings: Vec<Finding>,
    pub issues: Vec<Issue>,
}

/// Whether `dir` holds any lockfile the analysis understands.
pub fn has_lockfiles(dir: &Path) -> bool {
    dir.is_dir()
        && ca_certs_in_code::detect::detect_lockfiles(dir, &[]).is_ok_and(|l| !l.is_empty())
}

/// Analyse the project at `dir`; `inspect` scans one downloaded bundle.
pub fn analyse(
    dir: &Path,
    opts: &Options,
    profile: &Profile,
    limits: &Limits,
    inspect: &Inspect,
) -> Outcome {
    let online = opts.mode == Mode::Online;
    let inspector = move |p: &Path| {
        inspect(p, profile, limits).map_err(|e| ca_certs_in_code::anyhow::anyhow!(e))
    };
    let mut cfg = RunConfig::new(dir);
    cfg.no_resolve = !online;
    cfg.deep_scan = online;
    cfg.include_dev = opts.include_dev;
    cfg.cache_dir = opts.cache_dir.clone();
    cfg.inspector = Some(Box::new(inspector));
    let out = ca_certs_in_code::run(&cfg);

    let mut findings = Vec::new();
    for d in &out.findings {
        let affected = d.bundle.as_ref().is_some_and(|b| b.affected);
        if !(d.reachable && d.mitigated_by.is_none() && affected) {
            continue;
        }
        let certs = d
            .bundle
            .as_ref()
            .map(|b| b.affected_certs.join(", "))
            .unwrap_or_default();
        let chain = d
            .dep_chain
            .as_ref()
            .map(|c| c.join(" -> "))
            .unwrap_or_default();
        findings.push(Finding {
            path: d.lockfile.clone(),
            source: format!("{} dependency", d.ecosystem),
            cert: format!("{} {} bundles {certs} (via {chain})", d.package, d.version),
            sha256: None,
            kind: Kind::DependencyBundle,
            matched: Match::Dependency,
            context: Context::Trust,
            action_required: true,
        });
    }
    let severity = if online {
        Severity::Error
    } else {
        Severity::Warning
    };
    let issues = out
        .errors
        .iter()
        .map(|e| Issue {
            path: dir.display().to_string(),
            severity,
            message: format!("dependency analysis: {e}"),
        })
        .collect();
    Outcome {
        deps: out.findings,
        findings,
        issues,
    }
}
