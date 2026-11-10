use crate::graph::DepGraph;
use crate::{Ecosystem, Evidence, ParsedLock, ResolvedDep};
use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

/// Carton `cpanfile.snapshot`: distributions, the modules each provides, and the
/// modules each requires (mapped back to the providing distribution).
pub fn parse(path: &Path) -> Result<ParsedLock> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(parse_str(&content))
}

/// "Mozilla-CA-20260813" -> ("Mozilla-CA", "20260813").
fn split_dist(d: &str) -> (String, String) {
    match d.rfind('-') {
        Some(i) if d[i + 1..].starts_with(|c: char| c.is_ascii_digit() || c == 'v') => (
            d[..i].to_string(),
            d[i + 1..].trim_start_matches('v').to_string(),
        ),
        _ => (d.to_string(), String::new()),
    }
}

fn parse_str(content: &str) -> ParsedLock {
    let mut graph = DepGraph::new(ResolvedDep::new("(cpanfile)", "", Ecosystem::Perl));
    let mut provides: HashMap<String, String> = HashMap::new();
    let mut requires: Vec<(String, String)> = Vec::new();
    let (mut dist, mut mode) = (None::<String>, "");
    for raw in content.lines() {
        let indent = raw.len() - raw.trim_start().len();
        let line = raw.trim();
        match indent {
            2 => {
                let (n, v) = split_dist(line);
                graph.add_dep(ResolvedDep::new(&n, &v, Ecosystem::Perl));
                dist = Some(n);
            }
            4 => mode = line.trim_end_matches(':'),
            6 => {
                let (Some(d), Some(module)) = (&dist, line.split_whitespace().next()) else {
                    continue;
                };
                match mode {
                    "provides" => {
                        provides.insert(module.to_string(), d.clone());
                    }
                    "requirements" => requires.push((d.clone(), module.to_string())),
                    _ => {}
                }
            }
            _ => {}
        }
    }
    for (from, module) in requires {
        let Some(to) = provides.get(&module) else {
            continue;
        };
        let (Some(&f), Some(&t)) = (graph.find_all(&from).first(), graph.find_all(to).first())
        else {
            continue;
        };
        graph.add_edge(f, t);
    }
    graph.link_orphans_to_root();
    ParsedLock {
        graph,
        evidence: Evidence::LockfileGraph,
        notes: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SNAP: &str = "# carton snapshot format: version 1.0\nDISTRIBUTIONS\n  Mozilla-CA-20260813\n    pathname: L/LW/LWP/Mozilla-CA-20260813.tar.gz\n    provides:\n      Mozilla::CA 20260813\n    requirements:\n      ExtUtils::MakeMaker 0\n  LWP-Protocol-https-6.14\n    pathname: O/OA/OALDERS/LWP-Protocol-https-6.14.tar.gz\n    provides:\n      LWP::Protocol::https 6.14\n    requirements:\n      Mozilla::CA 20180117\n";

    #[test]
    fn tp_mozilla_ca_through_lwp() {
        let p = parse_str(SNAP);
        let i = p.graph.find_unique("Mozilla-CA").unwrap();
        assert_eq!(p.graph.graph[i].version, "20260813");
        assert_eq!(
            p.graph.path_to(i).unwrap(),
            vec![
                "(cpanfile)",
                "LWP-Protocol-https 6.14",
                "Mozilla-CA 20260813"
            ]
        );
    }

    #[test]
    fn fp_requirement_without_provider_adds_no_edge() {
        let p =
            parse_str(&SNAP.replace("      Mozilla::CA 20180117\n", "      Unknown::Module 1\n"));
        let i = p.graph.find_unique("Mozilla-CA").unwrap();
        // Becomes a top-level orphan, linked straight to the root.
        assert_eq!(p.graph.path_to(i).unwrap().len(), 2);
    }
}
