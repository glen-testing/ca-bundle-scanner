use crate::graph::DepGraph;
use crate::{Ecosystem, Evidence, ParsedLock, ResolvedDep};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

/// Composer `composer.lock`; direct requirements come from a sibling `composer.json`.
pub fn parse(path: &Path, include_dev: bool) -> Result<ParsedLock> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let manifest = std::fs::read_to_string(path.with_file_name("composer.json")).ok();
    parse_str(&content, manifest.as_deref(), include_dev)
}

fn requires(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default()
}

fn parse_str(content: &str, manifest: Option<&str>, include_dev: bool) -> Result<ParsedLock> {
    let doc: Value = serde_json::from_str(content).context("parsing composer.lock")?;
    let mut graph = DepGraph::new(ResolvedDep::new("(composer project)", "", Ecosystem::Php));
    let mut sections = vec!["packages"];
    if include_dev {
        sections.push("packages-dev");
    }
    let pkgs: Vec<&Value> = sections
        .iter()
        .filter_map(|s| doc.get(*s).and_then(Value::as_array))
        .flatten()
        .collect();
    for p in &pkgs {
        let name = p.get("name").and_then(Value::as_str).unwrap_or("");
        let version = p
            .get("version")
            .and_then(Value::as_str)
            .unwrap_or("")
            .trim_start_matches('v');
        graph.add_dep(ResolvedDep::new(name, version, Ecosystem::Php));
    }
    for p in &pkgs {
        let name = p.get("name").and_then(Value::as_str).unwrap_or("");
        let Some(&from) = graph.find_all(name).first() else {
            continue;
        };
        for dep in requires(p, "require") {
            if let Some(&to) = graph.find_all(&dep).first() {
                graph.add_edge(from, to);
            }
        }
    }
    let evidence = match manifest.and_then(|m| serde_json::from_str::<Value>(m).ok()) {
        Some(m) => {
            let mut direct = requires(&m, "require");
            if include_dev {
                direct.extend(requires(&m, "require-dev"));
            }
            for d in direct {
                if let Some(&to) = graph.find_all(&d).first() {
                    graph.add_edge(graph.root, to);
                }
            }
            Evidence::RuntimeDependencyPath
        }
        None => {
            graph.link_orphans_to_root();
            Evidence::LockfileGraph
        }
    };
    Ok(ParsedLock {
        graph,
        evidence,
        notes: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"{"packages":[
      {"name":"guzzlehttp/guzzle","version":"7.9.2","require":{"php":"^8.1","composer/ca-bundle":"^1.4"}},
      {"name":"composer/ca-bundle","version":"1.4.15","require":{"php":"^7.2"}}],
      "packages-dev":[{"name":"phpunit/phpunit","version":"11.0.0","require":{"composer/ca-bundle":"*"}}]}"#;

    #[test]
    fn tp_ca_bundle_through_guzzle() {
        let p = parse_str(
            LOCK,
            Some(r#"{"require":{"guzzlehttp/guzzle":"^7"}}"#),
            false,
        )
        .unwrap();
        let i = p.graph.find_unique("composer/ca-bundle").unwrap();
        assert_eq!(
            p.graph.path_to(i).unwrap(),
            vec![
                "(composer project)",
                "guzzlehttp/guzzle 7.9.2",
                "composer/ca-bundle 1.4.15"
            ]
        );
        assert_eq!(p.evidence, Evidence::RuntimeDependencyPath);
    }

    #[test]
    fn fp_dev_only_package_excluded_and_unrequired_unreachable() {
        let p = parse_str(LOCK, Some(r#"{"require":{"php":"^8.1"}}"#), false).unwrap();
        assert!(!p.graph.has_dep("phpunit/phpunit"));
        assert!(p
            .graph
            .path_to(p.graph.find_unique("composer/ca-bundle").unwrap())
            .is_none());
    }
}
