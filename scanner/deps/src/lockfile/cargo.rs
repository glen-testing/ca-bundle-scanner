use crate::graph::DepGraph;
use crate::{Ecosystem, Evidence, ParsedLock, ResolvedDep, RunConfig};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

pub fn parse(path: &Path, config: &RunConfig) -> Result<ParsedLock> {
    let manifest = path.with_file_name("Cargo.toml");
    if !config.no_resolve && manifest.is_file() {
        match from_cargo_metadata(&manifest, config.include_dev) {
            Ok(p) => return Ok(p),
            Err(e) => {
                let mut p = from_lockfile(path)?;
                p.notes.push(format!(
                    "cargo metadata failed ({e:#}); used Cargo.lock, which does not separate dev/build dependencies"
                ));
                return Ok(p);
            }
        }
    }
    from_lockfile(path)
}

#[derive(Deserialize)]
struct Metadata {
    packages: Vec<MetaPackage>,
    workspace_members: Vec<String>,
    resolve: Option<MetaResolve>,
}

#[derive(Deserialize)]
struct MetaPackage {
    id: String,
    name: String,
    version: String,
    manifest_path: PathBuf,
}

#[derive(Deserialize)]
struct MetaResolve {
    nodes: Vec<MetaNode>,
}

#[derive(Deserialize)]
struct MetaNode {
    id: String,
    deps: Vec<MetaDep>,
}

#[derive(Deserialize)]
struct MetaDep {
    pkg: String,
    dep_kinds: Vec<MetaDepKind>,
}

#[derive(Deserialize)]
struct MetaDepKind {
    kind: Option<String>,
}

fn from_cargo_metadata(manifest: &Path, include_dev: bool) -> Result<ParsedLock> {
    let out = Command::new("cargo")
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--manifest-path",
        ])
        .arg(manifest)
        .output()
        .context("running cargo metadata")?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!(
            "{}",
            err.lines()
                .find(|l| l.contains("error"))
                .unwrap_or(err.trim())
        );
    }
    let meta: Metadata = serde_json::from_slice(&out.stdout).context("parsing cargo metadata")?;
    build_from_metadata(meta, include_dev)
}

fn build_from_metadata(meta: Metadata, include_dev: bool) -> Result<ParsedLock> {
    let mut graph = DepGraph::new(ResolvedDep::new("(workspace)", "", Ecosystem::Rust));
    let mut ids = HashMap::new();
    for p in &meta.packages {
        let mut dep = ResolvedDep::new(&p.name, &p.version, Ecosystem::Rust);
        dep.location = p.manifest_path.parent().map(Path::to_path_buf);
        ids.insert(p.id.clone(), graph.add_dep(dep));
    }
    for m in &meta.workspace_members {
        if let Some(&idx) = ids.get(m) {
            graph.add_edge(graph.root, idx);
        }
    }
    let resolve = meta
        .resolve
        .context("cargo metadata returned no resolve graph")?;
    for node in &resolve.nodes {
        let Some(&from) = ids.get(&node.id) else {
            continue;
        };
        for d in &node.deps {
            let runtime = d.dep_kinds.iter().any(|k| match k.kind.as_deref() {
                None => true,
                Some("dev") => include_dev,
                _ => false,
            });
            if let (true, Some(&to)) = (runtime, ids.get(&d.pkg)) {
                graph.add_edge(from, to);
            }
        }
    }
    Ok(ParsedLock {
        graph,
        evidence: Evidence::RuntimeDependencyPath,
        notes: vec![],
    })
}

fn from_lockfile(path: &Path) -> Result<ParsedLock> {
    let lockfile = cargo_lock::Lockfile::load(path)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    let mut graph = DepGraph::new(ResolvedDep::new("(workspace)", "", Ecosystem::Rust));
    for pkg in &lockfile.packages {
        let idx = graph.add_dep(ResolvedDep::new(
            pkg.name.as_str(),
            &pkg.version.to_string(),
            Ecosystem::Rust,
        ));
        // Workspace members are the only packages without a source.
        if pkg.source.is_none() {
            graph.add_edge(graph.root, idx);
        }
    }
    for pkg in &lockfile.packages {
        let from = graph
            .find_version(pkg.name.as_str(), &pkg.version.to_string())
            .expect("added above");
        for dep in &pkg.dependencies {
            if let Some(to) = graph.find_version(dep.name.as_str(), &dep.version.to_string()) {
                graph.add_edge(from, to);
            }
        }
    }
    Ok(ParsedLock {
        graph,
        evidence: Evidence::LockfileGraph,
        notes: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(p: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(p)
    }

    fn chain(p: &ParsedLock, name: &str) -> Vec<Option<Vec<String>>> {
        p.graph
            .find_all(name)
            .iter()
            .map(|&i| p.graph.path_to(i))
            .collect()
    }

    #[test]
    fn tp_lockfile_chain_from_workspace_member() {
        let p = from_lockfile(&fixture("cargo_with_webpki/Cargo.lock")).unwrap();
        let c = chain(&p, "webpki-roots");
        let c = c[0].as_ref().unwrap();
        assert_eq!(c[0], "(workspace)");
        assert!(c[1].starts_with("test-webpki"));
        assert!(c.last().unwrap().starts_with("webpki-roots"));
    }

    #[test]
    fn fp_lockfile_without_bundler() {
        let p = from_lockfile(&fixture("cargo_no_bundler/Cargo.lock")).unwrap();
        assert!(!p.graph.has_dep("webpki-roots"));
        assert!(p.graph.has_dep("serde"));
    }

    #[test]
    fn tp_lockfile_two_versions_both_reachable() {
        let p = from_lockfile(&fixture("cargo_two_webpki/Cargo.lock")).unwrap();
        let c = chain(&p, "webpki-roots");
        assert_eq!(c.len(), 2);
        assert!(c.iter().all(Option::is_some));
    }

    #[test]
    fn tp_lockfile_multi_member_workspace() {
        let p = from_lockfile(&fixture("cargo_two_webpki/Cargo.lock")).unwrap();
        let members: Vec<_> = p
            .graph
            .graph
            .neighbors(p.graph.root)
            .map(|i| p.graph.label(i))
            .collect();
        assert_eq!(members.len(), 2, "{members:?}");
    }

    fn meta(dep_kind: Option<&str>) -> Metadata {
        let pkg = |id: &str, name: &str| MetaPackage {
            id: id.into(),
            name: name.into(),
            version: "1.0.0".into(),
            manifest_path: PathBuf::from(format!("/src/{name}/Cargo.toml")),
        };
        Metadata {
            packages: vec![
                pkg("app", "app"),
                pkg("reqwest", "reqwest"),
                pkg("wp", "webpki-roots"),
            ],
            workspace_members: vec!["app".into()],
            resolve: Some(MetaResolve {
                nodes: vec![
                    MetaNode {
                        id: "app".into(),
                        deps: vec![MetaDep {
                            pkg: "reqwest".into(),
                            dep_kinds: vec![MetaDepKind {
                                kind: dep_kind.map(String::from),
                            }],
                        }],
                    },
                    MetaNode {
                        id: "reqwest".into(),
                        deps: vec![MetaDep {
                            pkg: "wp".into(),
                            dep_kinds: vec![MetaDepKind { kind: None }],
                        }],
                    },
                ],
            }),
        }
    }

    #[test]
    fn tp_metadata_normal_dependency_reachable() {
        let p = build_from_metadata(meta(None), false).unwrap();
        assert!(chain(&p, "webpki-roots")[0].is_some());
        let wp = p.graph.find_unique("webpki-roots").unwrap();
        assert_eq!(
            p.graph.graph[wp].location.as_deref(),
            Some(Path::new("/src/webpki-roots"))
        );
    }

    #[test]
    fn fp_metadata_dev_dependency_not_reachable() {
        let p = build_from_metadata(meta(Some("dev")), false).unwrap();
        assert!(chain(&p, "webpki-roots")[0].is_none());
    }

    #[test]
    fn fp_metadata_build_dependency_not_reachable() {
        let p = build_from_metadata(meta(Some("build")), true).unwrap();
        assert!(chain(&p, "webpki-roots")[0].is_none());
    }

    #[test]
    fn tp_metadata_dev_dependency_with_include_dev() {
        let p = build_from_metadata(meta(Some("dev")), true).unwrap();
        assert!(chain(&p, "webpki-roots")[0].is_some());
    }
}
