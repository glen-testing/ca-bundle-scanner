use crate::database::CertBundlerEntry;
use crate::deep_scan::BundleScan;
use crate::graph::DepGraph;
use crate::{Ecosystem, Evidence, OutputFormat, ResolvedDep, RunOutput};
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Finding {
    pub package: String,
    pub version: String,
    pub ecosystem: Ecosystem,
    pub description: String,
    pub cert_loading_symbol: String,
    pub lockfile: String,
    pub reachable: bool,
    pub dep_chain: Option<Vec<String>>,
    pub evidence: Evidence,
    pub notes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bundle: Option<BundleScan>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deep_scan_error: Option<String>,
}

impl Finding {
    pub fn new(
        bundler: &CertBundlerEntry,
        dep: &ResolvedDep,
        lockfile: &Path,
        dep_chain: Option<Vec<String>>,
        evidence: Evidence,
        graph: &DepGraph,
    ) -> Self {
        Self {
            package: dep.name.clone(),
            version: dep.version.clone(),
            ecosystem: dep.ecosystem,
            description: bundler.description.into(),
            cert_loading_symbol: bundler.cert_loading_symbol.into(),
            lockfile: lockfile.display().to_string(),
            reachable: dep_chain.is_some(),
            dep_chain,
            evidence,
            notes: bundler.related.iter().filter(|(p, _)| graph.has_dep(p)).map(|(_, n)| n.to_string()).collect(),
            bundle: None,
            deep_scan_error: None,
        }
    }
}

pub fn format_output(out: &RunOutput, format: OutputFormat) -> String {
    match format {
        OutputFormat::Json => serde_json::to_string_pretty(&serde_json::json!({
            "findings": out.findings,
            "errors": out.errors,
            "notes": out.notes,
        }))
        .unwrap_or_default(),
        OutputFormat::Human => format_human(out),
    }
}

fn format_human(out: &RunOutput) -> String {
    let mut s = String::new();
    if out.findings.is_empty() {
        s.push_str("No bundled CA certificate stores found in runtime dependencies.\n");
    } else {
        s.push_str(&format!("Found {} bundled CA certificate store(s):\n\n", out.findings.len()));
    }
    for (i, f) in out.findings.iter().enumerate() {
        s.push_str(&format!("{}. {} {} ({})\n", i + 1, f.package, f.version, f.ecosystem));
        s.push_str(&format!("   {}\n", f.description));
        s.push_str(&format!("   Lockfile: {}\n", f.lockfile));
        match &f.dep_chain {
            Some(c) => s.push_str(&format!("   Reachable: YES ({:?})\n   Chain: {}\n", f.evidence, c.join(" -> "))),
            None => s.push_str("   Reachable: NO (no runtime dependency path from the project root)\n"),
        }
        for n in &f.notes {
            s.push_str(&format!("   Note: {n}\n"));
        }
        if let Some(b) = &f.bundle {
            if b.affected {
                s.push_str(&format!("   Bundle: AFFECTED — {}\n", b.affected_certs.join(", ")));
            } else {
                s.push_str("   Bundle: clean\n");
            }
            s.push_str(&format!("   Artifact: {}\n", b.artifact));
        }
        if let Some(e) = &f.deep_scan_error {
            s.push_str(&format!("   Deep scan FAILED: {e}\n"));
        }
        s.push('\n');
    }
    for n in &out.notes {
        s.push_str(&format!("note: {n}\n"));
    }
    for e in &out.errors {
        s.push_str(&format!("error: {e}\n"));
    }
    s
}
