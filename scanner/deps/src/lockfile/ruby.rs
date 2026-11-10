use crate::graph::DepGraph;
use crate::{Ecosystem, Evidence, ParsedLock, ResolvedDep};
use anyhow::{Context, Result};
use std::path::Path;

/// Bundler `Gemfile.lock`: `specs:` entries (4-space indent) with their dependencies
/// (6-space indent); `DEPENDENCIES` lists the Gemfile's direct gems.
pub fn parse(path: &Path) -> Result<ParsedLock> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(parse_str(&content))
}

fn name_version(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    let (name, rest) = line.split_once(' ').unwrap_or((line, ""));
    let name = name.trim_end_matches('!');
    let version = rest.trim().trim_start_matches('(').trim_end_matches(')');
    // Platform builds look like "1.16.0-x86_64-linux"; keep the version part.
    let version = version.split('-').next().unwrap_or(version);
    (!name.is_empty()).then(|| (name.to_string(), version.to_string()))
}

fn parse_str(content: &str) -> ParsedLock {
    let mut graph = DepGraph::new(ResolvedDep::new("(Gemfile)", "", Ecosystem::Ruby));
    let mut edges: Vec<(String, String)> = Vec::new();
    let mut direct: Vec<String> = Vec::new();
    let (mut section, mut in_specs, mut current) = (String::new(), false, None::<String>);
    for raw in content.lines() {
        if !raw.starts_with(' ') {
            section = raw.trim().to_string();
            in_specs = false;
            continue;
        }
        if raw.trim() == "specs:" {
            in_specs = true;
            continue;
        }
        let indent = raw.len() - raw.trim_start().len();
        if section == "DEPENDENCIES" && indent == 2 {
            if let Some((n, _)) = name_version(raw) {
                direct.push(n);
            }
        } else if in_specs && indent == 4 {
            if let Some((n, v)) = name_version(raw) {
                graph.add_dep(ResolvedDep::new(&n, &v, Ecosystem::Ruby));
                current = Some(n);
            }
        } else if in_specs && indent == 6 {
            if let (Some(c), Some((n, _))) = (&current, name_version(raw)) {
                edges.push((c.clone(), n));
            }
        }
    }
    for (from, to) in edges {
        let (Some(&f), Some(&t)) = (graph.find_all(&from).first(), graph.find_all(&to).first())
        else {
            continue;
        };
        graph.add_edge(f, t);
    }
    if direct.is_empty() {
        graph.link_orphans_to_root();
    }
    for d in direct {
        for &i in graph.find_all(&d).to_vec().iter() {
            graph.add_edge(graph.root, i);
        }
    }
    // Gemfile groups (development/test) are not recorded in the lockfile.
    ParsedLock {
        graph,
        evidence: Evidence::LockfileGraph,
        notes: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LOCK: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    excon (1.7.3)\n      logger\n    fog-core (2.6.0)\n      excon (~> 1.0)\n    logger (1.6.1)\n    nokogiri (1.16.0-x86_64-linux)\n\nPLATFORMS\n  x86_64-linux\n\nDEPENDENCIES\n  fog-core\n  nokogiri\n\nBUNDLED WITH\n   2.5.6\n";

    #[test]
    fn tp_transitive_excon_chain() {
        let p = parse_str(LOCK);
        let c = p
            .graph
            .path_to(p.graph.find_unique("excon").unwrap())
            .unwrap();
        assert_eq!(c, vec!["(Gemfile)", "fog-core 2.6.0", "excon 1.7.3"]);
        assert_eq!(
            p.graph.graph[p.graph.find_unique("nokogiri").unwrap()].version,
            "1.16.0"
        );
    }

    #[test]
    fn fp_gem_not_in_dependency_tree() {
        let p = parse_str(&LOCK.replace("      excon (~> 1.0)\n", ""));
        assert!(p
            .graph
            .path_to(p.graph.find_unique("excon").unwrap())
            .is_none());
    }
}
