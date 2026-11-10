pub mod database;
pub mod deep_scan;
pub mod detect;
pub mod graph;
pub mod lockfile;
pub mod report;

use anyhow::Result;
use std::path::PathBuf;

use crate::report::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Rust,
    Python,
    Node,
    Go,
}

impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Ecosystem::Rust => "rust",
            Ecosystem::Python => "python",
            Ecosystem::Node => "node",
            Ecosystem::Go => "go",
        })
    }
}

impl std::str::FromStr for Ecosystem {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "rust" | "cargo" => Ok(Ecosystem::Rust),
            "python" | "pip" | "pypi" => Ok(Ecosystem::Python),
            "node" | "npm" | "js" | "javascript" => Ok(Ecosystem::Node),
            "go" | "golang" => Ok(Ecosystem::Go),
            _ => anyhow::bail!("unknown ecosystem: {s}"),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ResolvedDep {
    pub name: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    /// Local directory holding this package's source, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<PathBuf>,
}

impl ResolvedDep {
    pub fn new(name: &str, version: &str, ecosystem: Ecosystem) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem,
            location: None,
        }
    }
}

/// How much the dependency path can be trusted to mean "ships at runtime".
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// Path from the project root through runtime (non-dev, non-build) dependencies only.
    RuntimeDependencyPath,
    /// Path exists, but the source format does not separate dev/test dependencies.
    LockfileGraph,
    /// Format lists packages without edges; presence is all that is known.
    LockfileEntryOnly,
}

pub struct ParsedLock {
    pub graph: graph::DepGraph,
    pub evidence: Evidence,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Human,
    Json,
}

impl std::str::FromStr for OutputFormat {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "human" => Ok(OutputFormat::Human),
            "json" => Ok(OutputFormat::Json),
            _ => anyhow::bail!("unknown format: {s} (expected: human, json)"),
        }
    }
}

pub struct RunConfig {
    pub target_dir: PathBuf,
    pub lockfile_path: Option<PathBuf>,
    pub ecosystem_filter: Option<Ecosystem>,
    pub excludes: Vec<String>,
    pub include_dev: bool,
    pub include_unreachable: bool,
    pub no_resolve: bool,
    pub python_version: String,
    pub deep_scan: bool,
    pub scanner_path: Option<PathBuf>,
    pub cache_dir: Option<PathBuf>,
    pub verbose: bool,
}

impl RunConfig {
    pub fn new(target_dir: impl Into<PathBuf>) -> Self {
        Self {
            target_dir: target_dir.into(),
            lockfile_path: None,
            ecosystem_filter: None,
            excludes: Vec::new(),
            include_dev: false,
            include_unreachable: false,
            no_resolve: false,
            python_version: "3.12".into(),
            deep_scan: false,
            scanner_path: None,
            cache_dir: None,
            verbose: false,
        }
    }
}

#[derive(Default)]
pub struct RunOutput {
    pub findings: Vec<Finding>,
    pub errors: Vec<String>,
    pub notes: Vec<String>,
}

impl RunOutput {
    /// 2 = incomplete answer (any error), 1 = reachable bundle found (affected, under deep scan), 0 = clean.
    pub fn exit_code(&self, deep_scan: bool) -> u8 {
        if !self.errors.is_empty() {
            return 2;
        }
        let hit = self.findings.iter().filter(|f| f.reachable && f.mitigated_by.is_none()).any(|f| {
            !deep_scan || f.bundle.as_ref().is_some_and(|b| b.affected)
        });
        u8::from(hit)
    }
}

pub fn run(config: &RunConfig) -> RunOutput {
    let mut out = RunOutput::default();
    let lockfiles = match &config.lockfile_path {
        Some(path) => match detect::ecosystem_for_lockfile(path) {
            Ok(eco) => vec![(absolute(path), eco)],
            Err(e) => {
                out.errors.push(e.to_string());
                return out;
            }
        },
        None => match detect::detect_lockfiles(&config.target_dir, &config.excludes) {
            Ok(l) => l,
            Err(e) => {
                out.errors.push(e.to_string());
                return out;
            }
        },
    };

    if lockfiles.is_empty() {
        out.notes.push(format!("no lockfiles found under {}", absolute(&config.target_dir).display()));
        return out;
    }

    let bundlers = database::known_bundlers();
    for (path, eco) in &lockfiles {
        if config.ecosystem_filter.is_some_and(|f| f != *eco) {
            continue;
        }
        if config.verbose {
            eprintln!("parsing {}", path.display());
        }
        let parsed = match lockfile::parse(path, *eco, config) {
            Ok(p) => p,
            Err(e) => {
                out.errors.push(format!("{}: {e:#}", path.display()));
                continue;
            }
        };
        out.notes.extend(parsed.notes.iter().map(|n| format!("{}: {n}", path.display())));

        for bundler in bundlers.iter().filter(|b| b.ecosystem == *eco) {
            for &idx in parsed.graph.find_all(bundler.package) {
                let chain = parsed.graph.path_to(idx);
                let reachable = chain.is_some();
                if !reachable && !config.include_unreachable {
                    continue;
                }
                let dep = parsed.graph.graph[idx].clone();
                let mut finding = Finding::new(bundler, &dep, path, chain, parsed.evidence, &parsed.graph);
                finding.mitigated_by = mitigation(bundler, &parsed.graph);
                if config.deep_scan && reachable {
                    match deep_scan::scan(bundler, &dep, config) {
                        Ok(b) => finding.bundle = Some(b),
                        Err(e) => {
                            let msg = format!("deep scan of {} {}: {e:#}", dep.name, dep.version);
                            finding.deep_scan_error = Some(msg.clone());
                            out.errors.push(msg);
                        }
                    }
                }
                out.findings.push(finding);
            }
        }
    }
    out
}

/// Rust root stores are only consulted through rustls-webpki; if every reachable copy
/// carries the compromised-key distrust list, chains through those keys fail anyway.
fn mitigation(bundler: &database::CertBundlerEntry, graph: &graph::DepGraph) -> Option<String> {
    if !matches!(bundler.package, "webpki-roots" | "webpki-root-certs") {
        return None;
    }
    let verifiers: Vec<&ResolvedDep> = graph
        .find_all("rustls-webpki")
        .iter()
        .filter(|&&i| graph.path_to(i).is_some())
        .map(|&i| &graph.graph[i])
        .collect();
    let all_fixed = !verifiers.is_empty()
        && verifiers.iter().all(|d| database::rustls_webpki_rejects_compromised_keys(&d.version));
    all_fixed.then(|| {
        let v: Vec<&str> = verifiers.iter().map(|d| d.version.as_str()).collect();
        format!("rustls-webpki {} rejects chains through the compromised keys (DISTRUSTED_SPKIS)", v.join(", "))
    })
}

pub fn absolute(p: &std::path::Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| {
        std::env::current_dir().map(|d| d.join(p)).unwrap_or_else(|_| p.to_path_buf())
    })
}
