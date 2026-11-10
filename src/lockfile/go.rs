use crate::graph::DepGraph;
use crate::{Ecosystem, Evidence, ParsedLock, ResolvedDep};
use anyhow::{Context, Result};
use std::path::Path;

/// Parses `require` directives. Since Go 1.17 go.mod lists every module in the build, indirect included.
pub fn parse(path: &Path) -> Result<ParsedLock> {
    let content = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(parse_str(&content))
}

fn parse_str(content: &str) -> ParsedLock {
    let module = content
        .lines()
        .find_map(|l| l.trim().strip_prefix("module "))
        .map(|m| m.trim().trim_matches('"'))
        .unwrap_or("(go-module)");
    let mut graph = DepGraph::new(ResolvedDep::new(module, "", Ecosystem::Go));
    let mut in_block = false;
    for raw in content.lines() {
        let line = raw.split("//").next().unwrap_or("").trim();
        let spec = if in_block {
            if line == ")" {
                in_block = false;
                continue;
            }
            line
        } else if let Some(rest) = line.strip_prefix("require") {
            let rest = rest.trim();
            if rest == "(" {
                in_block = true;
                continue;
            }
            rest
        } else {
            continue;
        };
        let mut parts = spec.split_whitespace();
        if let (Some(m), Some(v)) = (parts.next(), parts.next()) {
            let idx = graph.add_dep(ResolvedDep::new(m.trim_matches('"'), v, Ecosystem::Go));
            graph.add_edge(graph.root, idx);
        }
    }
    ParsedLock { graph, evidence: Evidence::LockfileEntryOnly, notes: vec![] }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tp_fallback_module_in_require_block() {
        let p = parse_str(
            "module example.com/app\n\ngo 1.22\n\nrequire (\n\tgolang.org/x/crypto v0.28.0\n\tgolang.org/x/crypto/x509roots/fallback v0.0.0-20240916204253-42ee18b96377 // indirect\n)\n",
        );
        let i = p.graph.find_unique("golang.org/x/crypto/x509roots/fallback").unwrap();
        assert_eq!(p.graph.graph[i].version, "v0.0.0-20240916204253-42ee18b96377");
        assert!(p.graph.path_to(i).is_some());
    }

    #[test]
    fn tp_single_line_require() {
        let p = parse_str("module m\nrequire golang.org/x/crypto/x509roots/fallback v0.1.0\n");
        assert!(p.graph.has_dep("golang.org/x/crypto/x509roots/fallback"));
    }

    #[test]
    fn fp_x_crypto_alone_is_not_the_fallback_module() {
        let p = parse_str("module m\nrequire golang.org/x/crypto v0.28.0\n// golang.org/x/crypto/x509roots/fallback v0.1.0\n");
        assert!(!p.graph.has_dep("golang.org/x/crypto/x509roots/fallback"));
    }
}
