use crate::database::CertBundlerEntry;
use crate::deep_scan::BundleScan;
use crate::graph::DepGraph;
use crate::{Ecosystem, Evidence, ResolvedDep};
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
    /// Why this bundle cannot complete a chain through the compromised keys, if it can't.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mitigated_by: Option<String>,
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
            notes: bundler
                .related
                .iter()
                .filter(|(p, _)| graph.has_dep(p))
                .map(|(_, n)| n.to_string())
                .collect(),
            mitigated_by: None,
            bundle: None,
            deep_scan_error: None,
        }
    }
}
