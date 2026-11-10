use crate::graph::DepGraph;
use crate::{Ecosystem, Evidence, ParsedLock, ResolvedDep};
use anyhow::{Context, Result};
use std::path::Path;

/// Elixir `mix.lock` and Erlang `rebar.lock` (Hex packages).
pub fn parse(path: &Path) -> Result<ParsedLock> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    let rebar = path.file_name().is_some_and(|n| n == "rebar.lock");
    Ok(if rebar {
        parse_rebar(&content)
    } else {
        parse_mix(&content)
    })
}

fn root() -> DepGraph {
    DepGraph::new(ResolvedDep::new("(hex project)", "", Ecosystem::Hex))
}

/// `"name": {:hex, :name, "1.2.3", "hash", [:mix], [{:dep, "~> 1.0", [...]}, ...], "hexpm", "hash"},`
fn parse_mix(content: &str) -> ParsedLock {
    let mut graph = root();
    let mut edges = Vec::new();
    for line in content.lines() {
        let Some(rest) = line.trim().strip_prefix('"') else {
            continue;
        };
        let Some((name, rest)) = rest.split_once("\": {:hex, :") else {
            continue;
        };
        let Some(after) = rest.split_once(", \"").map(|x| x.1) else {
            continue;
        };
        let Some((version, tail)) = after.split_once('"') else {
            continue;
        };
        graph.add_dep(ResolvedDep::new(name, version, Ecosystem::Hex));
        // Dependency tuples start with "{:name, " inside the deps list.
        for part in tail.split("{:").skip(1) {
            if let Some((dep, _)) = part.split_once(',') {
                edges.push((name.to_string(), dep.trim().to_string()));
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
    graph.link_orphans_to_root();
    ParsedLock {
        graph,
        evidence: Evidence::LockfileGraph,
        notes: vec![],
    }
}

/// `{<<"name">>,{pkg,<<"name">>,<<"1.2.3">>},Level}`; level 0 entries are direct.
fn parse_rebar(content: &str) -> ParsedLock {
    let mut graph = root();
    for chunk in content.split("{<<\"").skip(1) {
        let Some((name, rest)) = chunk.split_once("\">>,{pkg,<<\"") else {
            continue;
        };
        let Some((_, rest)) = rest.split_once("\">>,<<\"") else {
            continue;
        };
        let Some((version, rest)) = rest.split_once("\">>}") else {
            continue;
        };
        let i = graph.add_dep(ResolvedDep::new(name, version, Ecosystem::Hex));
        if rest.trim_start_matches(',').starts_with('0') {
            graph.add_edge(graph.root, i);
        }
    }
    graph.link_orphans_to_root();
    ParsedLock {
        graph,
        evidence: Evidence::LockfileEntryOnly,
        notes: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIX: &str = "%{\n  \"castore\": {:hex, :castore, \"1.0.21\", \"abc\", [:mix], [], \"hexpm\", \"def\"},\n  \"mint\": {:hex, :mint, \"1.6.2\", \"abc\", [:mix], [{:castore, \"~> 0.1.0 or ~> 1.0\", [hex: :castore, repo: \"hexpm\", optional: true]}, {:hpax, \"~> 1.0\", [hex: :hpax, repo: \"hexpm\", optional: false]}], \"hexpm\", \"def\"},\n  \"hpax\": {:hex, :hpax, \"1.0.0\", \"abc\", [:mix], [], \"hexpm\", \"def\"},\n}\n";

    #[test]
    fn tp_mix_castore_through_mint() {
        let p = parse_mix(MIX);
        let c = p
            .graph
            .path_to(p.graph.find_unique("castore").unwrap())
            .unwrap();
        assert_eq!(c, vec!["(hex project)", "mint 1.6.2", "castore 1.0.21"]);
    }

    #[test]
    fn tp_rebar_certifi_direct() {
        let p = parse_rebar("{\"1.2.0\",\n[{<<\"certifi\">>,{pkg,<<\"certifi\">>,<<\"2.17.0\">>},0},\n {<<\"hackney\">>,{pkg,<<\"hackney\">>,<<\"1.20.1\">>},0}]}.\n");
        assert!(p
            .graph
            .path_to(p.graph.find_unique("certifi").unwrap())
            .is_some());
        assert_eq!(
            p.graph.graph[p.graph.find_unique("certifi").unwrap()].version,
            "2.17.0"
        );
    }

    #[test]
    fn fp_unrelated_hex_lines_ignored() {
        let p =
            parse_mix("%{\n  \"phoenix\": {:git, \"https://github.com/x/y\", \"abc\", []},\n}\n");
        assert_eq!(p.graph.dep_count(), 1);
    }
}
