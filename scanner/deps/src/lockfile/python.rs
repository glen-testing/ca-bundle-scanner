use crate::graph::DepGraph;
use crate::{Ecosystem, Evidence, ParsedLock, ResolvedDep, RunConfig};
use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

/// PEP 503 normalization: lowercase, runs of `-_.` collapse to `-`.
pub fn normalize(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut sep = false;
    for c in name.trim().chars() {
        if matches!(c, '-' | '_' | '.') {
            sep = true;
        } else {
            if sep && !out.is_empty() {
                out.push('-');
            }
            sep = false;
            out.extend(c.to_lowercase());
        }
    }
    out
}

/// Leading distribution name of a PEP 508 requirement string.
fn requirement_name(req: &str) -> String {
    let end = req
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .unwrap_or(req.len());
    normalize(&req[..end])
}

fn root() -> DepGraph {
    DepGraph::new(ResolvedDep::new("(project)", "", Ecosystem::Python))
}

pub fn parse(path: &Path, config: &RunConfig) -> Result<ParsedLock> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let content =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    match name {
        "poetry.lock" => parse_poetry(&content, path.parent(), config.include_dev),
        "uv.lock" => parse_uv_lock(&content, config.include_dev),
        "Pipfile.lock" => parse_pipfile(&content, config.include_dev),
        _ if config.no_resolve => Ok(parse_requirements_flat(&content)),
        _ => resolve_requirements(path, &config.python_version),
    }
}

fn parse_requirements_flat(content: &str) -> ParsedLock {
    let mut graph = root();
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') {
            continue;
        }
        let name = requirement_name(line);
        if name.is_empty() {
            continue;
        }
        let version = line
            .split_once("==")
            .map(|(_, v)| v.split([';', ',', ' ']).next().unwrap_or("").trim())
            .unwrap_or("");
        let idx = graph.add_dep(ResolvedDep::new(&name, version, Ecosystem::Python));
        graph.add_edge(graph.root, idx);
    }
    ParsedLock {
        graph,
        evidence: Evidence::LockfileEntryOnly,
        notes: vec!["--no-resolve: only packages listed in the file are checked; bundlers pulled in transitively are missed".into()],
    }
}

/// Resolves the full dependency tree with `uv pip compile`, wheels only (no build scripts run).
fn resolve_requirements(path: &Path, python_version: &str) -> Result<ParsedLock> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let file = path
        .file_name()
        .context("requirements path has no file name")?;
    let out = Command::new("uv")
        .current_dir(dir)
        .args([
            "pip",
            "compile",
            "--no-header",
            "--annotation-style",
            "line",
            "--only-binary",
            ":all:",
            "--quiet",
            "--python-version",
            python_version,
        ])
        .arg(file)
        .output()
        .context("running uv (install uv, or pass --no-resolve to check only listed packages)")?;
    if !out.status.success() {
        bail!(
            "uv pip compile failed: {} (pass --no-resolve to check only listed packages)",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(parse_uv_compile_output(&String::from_utf8_lossy(
        &out.stdout,
    )))
}

fn parse_uv_compile_output(text: &str) -> ParsedLock {
    let mut graph = root();
    let mut via: Vec<(String, Vec<String>)> = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('-') {
            continue;
        }
        let (spec, ann) = line.split_once('#').unwrap_or((line, ""));
        let Some((name, version)) = spec.trim().split_once("==") else {
            continue;
        };
        let name = requirement_name(name);
        graph.add_dep(ResolvedDep::new(&name, version.trim(), Ecosystem::Python));
        let parents = ann
            .trim()
            .strip_prefix("via")
            .unwrap_or("")
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        via.push((name, parents));
    }
    for (child, parents) in via {
        let Some(c) = graph.find_unique(&child) else {
            continue;
        };
        for p in parents {
            if p.starts_with("-r") || p.starts_with("-c") {
                graph.add_edge(graph.root, c);
            } else if let Some(pi) = graph.find_unique(&requirement_name(&p)) {
                graph.add_edge(pi, c);
            }
        }
    }
    ParsedLock {
        graph,
        evidence: Evidence::RuntimeDependencyPath,
        notes: vec![],
    }
}

fn toml_table_keys(v: Option<&toml::Value>) -> Vec<String> {
    v.and_then(|t| t.as_table())
        .map(|t| t.keys().cloned().collect())
        .unwrap_or_default()
}

/// Direct dependency names declared in pyproject.toml (PEP 621 and Poetry styles).
fn pyproject_roots(dir: Option<&Path>, include_dev: bool) -> Option<Vec<String>> {
    let text = std::fs::read_to_string(dir?.join("pyproject.toml")).ok()?;
    let doc: toml::Value = text.parse().ok()?;
    let mut names = Vec::new();
    let project = doc.get("project");
    for r in project
        .and_then(|p| p.get("dependencies"))
        .and_then(|d| d.as_array())
        .into_iter()
        .flatten()
    {
        names.extend(r.as_str().map(requirement_name));
    }
    for extra in project
        .and_then(|p| p.get("optional-dependencies"))
        .and_then(|d| d.as_table())
        .into_iter()
        .flat_map(|t| t.values())
    {
        names.extend(
            extra
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|r| r.as_str())
                .map(requirement_name),
        );
    }
    let poetry = doc.get("tool").and_then(|t| t.get("poetry"));
    names.extend(
        toml_table_keys(poetry.and_then(|p| p.get("dependencies")))
            .iter()
            .filter(|k| k.as_str() != "python")
            .map(|k| normalize(k)),
    );
    if include_dev {
        names.extend(
            toml_table_keys(poetry.and_then(|p| p.get("dev-dependencies")))
                .iter()
                .map(|k| normalize(k)),
        );
        for g in poetry
            .and_then(|p| p.get("group"))
            .and_then(|g| g.as_table())
            .into_iter()
            .flat_map(|t| t.values())
        {
            names.extend(
                toml_table_keys(g.get("dependencies"))
                    .iter()
                    .map(|k| normalize(k)),
            );
        }
        for g in doc
            .get("dependency-groups")
            .and_then(|g| g.as_table())
            .into_iter()
            .flat_map(|t| t.values())
        {
            names.extend(
                g.as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|r| r.as_str())
                    .map(requirement_name),
            );
        }
    }
    (!names.is_empty()).then_some(names)
}

fn parse_poetry(content: &str, dir: Option<&Path>, include_dev: bool) -> Result<ParsedLock> {
    let doc: toml::Value = content.parse().context("parsing poetry.lock")?;
    let packages = doc
        .get("package")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();
    let mut graph = root();
    for pkg in &packages {
        let name = normalize(pkg.get("name").and_then(|n| n.as_str()).unwrap_or(""));
        let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("");
        graph.add_dep(ResolvedDep::new(&name, version, Ecosystem::Python));
    }
    for pkg in &packages {
        let name = normalize(pkg.get("name").and_then(|n| n.as_str()).unwrap_or(""));
        let Some(from) = graph.find_unique(&name) else {
            continue;
        };
        for dep in toml_table_keys(pkg.get("dependencies")) {
            for &to in graph.find_all(&normalize(&dep)).to_vec().iter() {
                graph.add_edge(from, to);
            }
        }
    }
    let evidence = match pyproject_roots(dir, include_dev) {
        Some(roots) => {
            for r in roots {
                for &to in graph.find_all(&r).to_vec().iter() {
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

fn dep_names(v: Option<&toml::Value>) -> Vec<(String, Option<String>)> {
    v.and_then(|d| d.as_array())
        .into_iter()
        .flatten()
        .filter_map(|d| {
            let name = normalize(d.get("name")?.as_str()?);
            Some((
                name,
                d.get("version").and_then(|v| v.as_str()).map(String::from),
            ))
        })
        .collect()
}

fn parse_uv_lock(content: &str, include_dev: bool) -> Result<ParsedLock> {
    let doc: toml::Value = content.parse().context("parsing uv.lock")?;
    let packages = doc
        .get("package")
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default();
    let mut graph = root();
    let mut idx = Vec::new();
    for pkg in &packages {
        let name = normalize(pkg.get("name").and_then(|n| n.as_str()).unwrap_or(""));
        let version = pkg.get("version").and_then(|v| v.as_str()).unwrap_or("");
        idx.push(graph.add_dep(ResolvedDep::new(&name, version, Ecosystem::Python)));
    }
    let mut members = 0;
    for (pkg, &from) in packages.iter().zip(&idx) {
        let source = pkg.get("source").and_then(|s| s.as_table());
        let is_member =
            source.is_some_and(|s| s.contains_key("editable") || s.contains_key("virtual"));
        if is_member {
            members += 1;
            graph.add_edge(graph.root, from);
        }
        let mut deps = dep_names(pkg.get("dependencies"));
        for extra in pkg
            .get("optional-dependencies")
            .and_then(|o| o.as_table())
            .into_iter()
            .flat_map(|t| t.values())
        {
            deps.extend(dep_names(Some(extra)));
        }
        if include_dev {
            for group in pkg
                .get("dev-dependencies")
                .and_then(|o| o.as_table())
                .into_iter()
                .flat_map(|t| t.values())
            {
                deps.extend(dep_names(Some(group)));
            }
        }
        for (name, version) in deps {
            let targets = match version {
                Some(v) => graph.find_version(&name, &v).into_iter().collect(),
                None => graph.find_all(&name).to_vec(),
            };
            for to in targets {
                graph.add_edge(from, to);
            }
        }
    }
    let evidence = if members > 0 {
        Evidence::RuntimeDependencyPath
    } else {
        graph.link_orphans_to_root();
        Evidence::LockfileGraph
    };
    Ok(ParsedLock {
        graph,
        evidence,
        notes: vec![],
    })
}

fn parse_pipfile(content: &str, include_dev: bool) -> Result<ParsedLock> {
    let doc: serde_json::Value = serde_json::from_str(content).context("parsing Pipfile.lock")?;
    let mut graph = root();
    let sections: &[&str] = if include_dev {
        &["default", "develop"]
    } else {
        &["default"]
    };
    for section in sections {
        for (name, info) in doc
            .get(*section)
            .and_then(|s| s.as_object())
            .into_iter()
            .flatten()
        {
            let version = info
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim_start_matches("==");
            let idx = graph.add_dep(ResolvedDep::new(
                &normalize(name),
                version,
                Ecosystem::Python,
            ));
            graph.add_edge(graph.root, idx);
        }
    }
    Ok(ParsedLock {
        graph,
        evidence: Evidence::LockfileEntryOnly,
        notes: vec![],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reachable(p: &ParsedLock, name: &str) -> bool {
        p.graph
            .find_all(name)
            .iter()
            .any(|&i| p.graph.path_to(i).is_some())
    }

    #[test]
    fn normalization_pep503() {
        assert_eq!(normalize("Charset_Normalizer"), "charset-normalizer");
        assert_eq!(normalize("zope.interface"), "zope-interface");
        assert_eq!(normalize("a--_b"), "a-b");
        assert_eq!(requirement_name("urllib3[socks]>=1.26,<3"), "urllib3");
        assert_eq!(requirement_name("bar ; python_version >= '3.8'"), "bar");
    }

    #[test]
    fn tp_uv_output_builds_transitive_chain() {
        let out = "certifi==2024.8.30       # via requests\nrequests==2.32.3          # via -r requirements.txt\n";
        let p = parse_uv_compile_output(out);
        let c = p
            .graph
            .path_to(p.graph.find_unique("certifi").unwrap())
            .unwrap();
        assert_eq!(c, vec!["(project)", "requests 2.32.3", "certifi 2024.8.30"]);
    }

    #[test]
    fn fp_uv_output_without_certifi() {
        let p = parse_uv_compile_output("six==1.16.0   # via -r requirements.txt\n");
        assert!(!p.graph.has_dep("certifi"));
    }

    #[test]
    fn tp_flat_requirements_lists_explicit_certifi() {
        let p =
            parse_requirements_flat("certifi==2024.8.30\n# comment\n-r other.txt\nrequests>=2\n");
        assert!(reachable(&p, "certifi"));
        assert_eq!(p.evidence, Evidence::LockfileEntryOnly);
    }

    const POETRY: &str = r#"
[[package]]
name = "requests"
version = "2.32.3"
[package.dependencies]
certifi = ">=2017.4.17"

[[package]]
name = "certifi"
version = "2024.8.30"

[[package]]
name = "pytest-httpbin"
version = "2.0.0"
[package.dependencies]
httplib2 = "*"

[[package]]
name = "httplib2"
version = "0.22.0"
"#;

    fn tmpdir(tag: &str, pyproject: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("ccic-py-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("pyproject.toml"), pyproject).unwrap();
        d
    }

    const PYPROJECT: &str = "[tool.poetry.dependencies]\npython = \"^3.11\"\nrequests = \"*\"\n[tool.poetry.group.dev.dependencies]\npytest-httpbin = \"*\"\n";

    #[test]
    fn tp_poetry_runtime_chain() {
        let d = tmpdir("tp", PYPROJECT);
        let p = parse_poetry(POETRY, Some(&d), false).unwrap();
        assert!(reachable(&p, "certifi"));
        assert_eq!(p.evidence, Evidence::RuntimeDependencyPath);
    }

    #[test]
    fn fp_poetry_dev_group_not_reachable() {
        let d = tmpdir("fp", PYPROJECT);
        let p = parse_poetry(POETRY, Some(&d), false).unwrap();
        assert!(!reachable(&p, "httplib2"));
        let p = parse_poetry(POETRY, Some(&d), true).unwrap();
        assert!(reachable(&p, "httplib2"));
    }

    const UV_LOCK: &str = r#"
version = 1
[[package]]
name = "app"
version = "0.1.0"
source = { editable = "." }
dependencies = [{ name = "requests" }]
[package.dev-dependencies]
dev = [{ name = "grpcio" }]

[[package]]
name = "requests"
version = "2.32.3"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "certifi" }]

[[package]]
name = "certifi"
version = "2024.8.30"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "grpcio"
version = "1.66.0"
source = { registry = "https://pypi.org/simple" }
"#;

    #[test]
    fn tp_uv_lock_runtime_chain() {
        let p = parse_uv_lock(UV_LOCK, false).unwrap();
        let c = p
            .graph
            .path_to(p.graph.find_unique("certifi").unwrap())
            .unwrap();
        assert_eq!(
            c,
            vec![
                "(project)",
                "app 0.1.0",
                "requests 2.32.3",
                "certifi 2024.8.30"
            ]
        );
    }

    #[test]
    fn fp_uv_lock_dev_group_not_reachable() {
        assert!(!reachable(
            &parse_uv_lock(UV_LOCK, false).unwrap(),
            "grpcio"
        ));
        assert!(reachable(&parse_uv_lock(UV_LOCK, true).unwrap(), "grpcio"));
    }

    const PIPFILE: &str = r#"{"default": {"certifi": {"version": "==2024.8.30"}},
                             "develop": {"grpcio": {"version": "==1.66.0"}}}"#;

    #[test]
    fn tp_pipfile_default_section() {
        let p = parse_pipfile(PIPFILE, false).unwrap();
        assert!(reachable(&p, "certifi"));
        assert_eq!(
            p.graph.graph[p.graph.find_unique("certifi").unwrap()].version,
            "2024.8.30"
        );
    }

    #[test]
    fn fp_pipfile_develop_section_excluded() {
        assert!(!parse_pipfile(PIPFILE, false)
            .unwrap()
            .graph
            .has_dep("grpcio"));
    }
}
