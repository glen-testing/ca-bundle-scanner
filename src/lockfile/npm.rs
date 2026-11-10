use crate::graph::DepGraph;
use crate::{Ecosystem, Evidence, ParsedLock, ResolvedDep};
use anyhow::{Context, Result};
use petgraph::graph::NodeIndex;
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::path::Path;

pub fn parse(path: &Path, include_dev: bool) -> Result<ParsedLock> {
    let content = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_str(&content, include_dev)
}

fn is_dev(info: &Value) -> bool {
    info.get("dev").and_then(Value::as_bool).unwrap_or(false)
        || info.get("devOptional").and_then(Value::as_bool).unwrap_or(false)
}

fn dep_keys<'a>(info: &'a Value, fields: &[&str]) -> Vec<&'a str> {
    fields
        .iter()
        .filter_map(|f| info.get(*f).and_then(Value::as_object))
        .flat_map(|m| m.keys().map(String::as_str))
        .collect()
}

/// Package name for an install path like `node_modules/a/node_modules/@s/b`.
fn name_from_path(key: &str) -> &str {
    key.rsplit_once("node_modules/").map_or(key, |(_, n)| n)
}

/// Node's resolution: nearest `node_modules/<dep>` walking up from `from`.
fn resolve<'a>(packages: &'a Map<String, Value>, from: &str, dep: &str) -> Option<&'a str> {
    let mut base = from.to_string();
    loop {
        let candidate = if base.is_empty() { format!("node_modules/{dep}") } else { format!("{base}/node_modules/{dep}") };
        if let Some((k, _)) = packages.get_key_value(&candidate) {
            return Some(k.as_str());
        }
        if base.is_empty() {
            return None;
        }
        base = base.rfind("/node_modules/").map_or(String::new(), |i| base[..i].to_string());
    }
}

fn parse_str(content: &str, include_dev: bool) -> Result<ParsedLock> {
    let doc: Value = serde_json::from_str(content).context("parsing package-lock.json")?;
    let name = doc.get("name").and_then(Value::as_str).unwrap_or("(npm-project)");
    let version = doc.get("version").and_then(Value::as_str).unwrap_or("");
    let mut graph = DepGraph::new(ResolvedDep::new(name, version, Ecosystem::Node));

    let Some(packages) = doc.get("packages").and_then(Value::as_object) else {
        return parse_v1(&doc, graph, include_dev);
    };

    let mut fields = vec!["dependencies", "optionalDependencies", "peerDependencies"];
    if include_dev {
        fields.push("devDependencies");
    }
    let mut nodes: HashMap<&str, NodeIndex> = HashMap::from([("", graph.root)]);
    for (key, info) in packages {
        if key.is_empty() || (is_dev(info) && !include_dev) {
            continue;
        }
        let v = info.get("version").and_then(Value::as_str).unwrap_or("");
        let n = info.get("name").and_then(Value::as_str).unwrap_or_else(|| name_from_path(key));
        nodes.insert(key.as_str(), graph.add_dep(ResolvedDep::new(n, v, Ecosystem::Node)));
    }
    for (key, info) in packages {
        let Some(&from) = nodes.get(key.as_str()) else { continue };
        // Workspace link: edge to the linked package directory, whose own deps are walked separately.
        if info.get("link").and_then(Value::as_bool).unwrap_or(false) {
            let target = info.get("resolved").and_then(Value::as_str).and_then(|r| nodes.get(r));
            if let Some(&to) = target {
                graph.add_edge(from, to);
            }
            continue;
        }
        let fields: &[&str] = if key.is_empty() { &fields } else { &fields[..3] };
        for dep in dep_keys(info, fields) {
            if let Some(&to) = resolve(packages, key, dep).and_then(|k| nodes.get(k)) {
                graph.add_edge(from, to);
            }
        }
    }
    Ok(ParsedLock { graph, evidence: Evidence::RuntimeDependencyPath, notes: vec![] })
}

fn parse_v1(doc: &Value, mut graph: DepGraph, include_dev: bool) -> Result<ParsedLock> {
    fn walk(graph: &mut DepGraph, parent: NodeIndex, deps: &Map<String, Value>, include_dev: bool) {
        for (name, info) in deps {
            if is_dev(info) && !include_dev {
                continue;
            }
            let v = info.get("version").and_then(Value::as_str).unwrap_or("");
            let idx = graph.add_dep(ResolvedDep::new(name, v, Ecosystem::Node));
            graph.add_edge(parent, idx);
            if let Some(sub) = info.get("dependencies").and_then(Value::as_object) {
                walk(graph, idx, sub, include_dev);
            }
        }
    }
    if let Some(deps) = doc.get("dependencies").and_then(Value::as_object) {
        let root = graph.root;
        walk(&mut graph, root, deps, include_dev);
    }
    Ok(ParsedLock {
        graph,
        evidence: Evidence::LockfileGraph,
        notes: vec!["lockfileVersion 1: nesting reflects install layout, not exact dependency edges".into()],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = r#"{
      "name": "app", "version": "1.0.0", "lockfileVersion": 3,
      "packages": {
        "": { "dependencies": { "client": "^1" }, "devDependencies": { "test-helper": "^1" } },
        "node_modules/client": { "version": "1.0.0", "dependencies": { "ssl-root-cas": "^1.3" } },
        "node_modules/client/node_modules/ssl-root-cas": { "version": "1.3.1" },
        "node_modules/ssl-root-cas": { "version": "1.2.0", "dev": true },
        "node_modules/test-helper": { "version": "1.0.0", "dev": true, "dependencies": { "ssl-root-cas": "^1.2" } }
      }
    }"#;

    fn reachable_versions(p: &ParsedLock, name: &str) -> Vec<String> {
        p.graph
            .find_all(name)
            .iter()
            .filter(|&&i| p.graph.path_to(i).is_some())
            .map(|&i| p.graph.graph[i].version.clone())
            .collect()
    }

    #[test]
    fn tp_nested_resolution_picks_nearest_copy() {
        let p = parse_str(LOCK, false).unwrap();
        assert_eq!(reachable_versions(&p, "ssl-root-cas"), vec!["1.3.1"]);
        let c = p.graph.path_to(p.graph.find_version("ssl-root-cas", "1.3.1").unwrap()).unwrap();
        assert_eq!(c, vec!["app 1.0.0", "client 1.0.0", "ssl-root-cas 1.3.1"]);
    }

    #[test]
    fn fp_dev_only_copy_excluded() {
        let p = parse_str(LOCK, false).unwrap();
        assert!(p.graph.find_version("ssl-root-cas", "1.2.0").is_none());
        let p = parse_str(LOCK, true).unwrap();
        assert_eq!(reachable_versions(&p, "ssl-root-cas").len(), 2);
    }

    #[test]
    fn fp_unreferenced_package_not_reachable() {
        let lock = r#"{"name":"app","lockfileVersion":3,"packages":{"":{},
          "node_modules/ssl-root-cas":{"version":"1.3.1"}}}"#;
        let p = parse_str(lock, false).unwrap();
        assert!(reachable_versions(&p, "ssl-root-cas").is_empty());
    }

    #[test]
    fn tp_workspace_link_followed() {
        let lock = r#"{"name":"mono","lockfileVersion":3,"packages":{
          "":{"workspaces":["packages/api"],"dependencies":{"api":"*"}},
          "node_modules/api":{"resolved":"packages/api","link":true},
          "packages/api":{"name":"api","version":"0.1.0","dependencies":{"ssl-root-cas":"^1"}},
          "node_modules/ssl-root-cas":{"version":"1.3.1"}}}"#;
        let p = parse_str(lock, false).unwrap();
        let c = p.graph.path_to(p.graph.find_unique("ssl-root-cas").unwrap()).unwrap();
        assert_eq!(c.last().unwrap(), "ssl-root-cas 1.3.1");
    }

    #[test]
    fn tp_scoped_names() {
        assert_eq!(name_from_path("node_modules/a/node_modules/@s/b"), "@s/b");
    }

    #[test]
    fn tp_lockfile_v1() {
        let lock = r#"{"name":"app","lockfileVersion":1,"dependencies":{
          "client":{"version":"1.0.0","dependencies":{"ssl-root-cas":{"version":"1.3.1"}}},
          "jest":{"version":"29.0.0","dev":true}}}"#;
        let p = parse_str(lock, false).unwrap();
        assert_eq!(reachable_versions(&p, "ssl-root-cas"), vec!["1.3.1"]);
        assert!(!p.graph.has_dep("jest"));
    }
}
