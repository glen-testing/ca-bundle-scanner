use crate::Ecosystem;
use anyhow::{bail, Result};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

const SKIP_DIRS: &[&str] = &[
    ".git", "node_modules", "target", ".venv", "venv", "__pycache__", "site-packages", ".tox",
];

pub fn ecosystem_for_lockfile(path: &Path) -> Result<Ecosystem> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    match name {
        "Cargo.lock" => Ok(Ecosystem::Rust),
        "package-lock.json" => Ok(Ecosystem::Node),
        "poetry.lock" | "uv.lock" | "Pipfile.lock" => Ok(Ecosystem::Python),
        "go.mod" => Ok(Ecosystem::Go),
        n if n.starts_with("requirements") && n.ends_with(".txt") => Ok(Ecosystem::Python),
        _ => bail!("unrecognized lockfile: {}", path.display()),
    }
}

/// Recursively finds lockfiles, skipping dependency/build directories and `excludes` (dir names).
pub fn detect_lockfiles(dir: &Path, excludes: &[String]) -> Result<Vec<(PathBuf, Ecosystem)>> {
    if !dir.is_dir() {
        bail!("not a directory: {}", dir.display());
    }
    let mut found = Vec::new();
    let walker = WalkDir::new(dir).sort_by_file_name().into_iter().filter_entry(|e| {
        e.depth() == 0
            || !e.file_type().is_dir()
            || e.file_name().to_str().is_some_and(|n| {
                !SKIP_DIRS.contains(&n) && !excludes.iter().any(|x| x == n)
            })
    });
    for entry in walker {
        let entry = entry?;
        if entry.file_type().is_file() {
            if let Ok(eco) = ecosystem_for_lockfile(entry.path()) {
                found.push((crate::absolute(entry.path()), eco));
            }
        }
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("ccic-detect-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn ecosystem_lookup() {
        assert_eq!(ecosystem_for_lockfile(Path::new("/x/Cargo.lock")).unwrap(), Ecosystem::Rust);
        assert_eq!(ecosystem_for_lockfile(Path::new("requirements-prod.txt")).unwrap(), Ecosystem::Python);
        assert!(ecosystem_for_lockfile(Path::new("notes.txt")).is_err());
        assert!(ecosystem_for_lockfile(Path::new("unknown.lock")).is_err());
    }

    #[test]
    fn tp_finds_nested_lockfiles() {
        let d = tmp("nested");
        std::fs::create_dir_all(d.join("services/api")).unwrap();
        std::fs::write(d.join("services/api/requirements.txt"), "certifi\n").unwrap();
        std::fs::write(d.join("Cargo.lock"), "").unwrap();
        let found = detect_lockfiles(&d, &[]).unwrap();
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|(p, _)| p.is_absolute()));
    }

    #[test]
    fn fp_skips_dependency_and_excluded_dirs() {
        let d = tmp("skip");
        for sub in ["node_modules/x", "target/debug", ".venv/lib", "fixtures"] {
            std::fs::create_dir_all(d.join(sub)).unwrap();
            std::fs::write(d.join(sub).join("package-lock.json"), "{}").unwrap();
        }
        let found = detect_lockfiles(&d, &["fixtures".to_string()]).unwrap();
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn missing_dir_is_error() {
        assert!(detect_lockfiles(Path::new("/nonexistent-ccic"), &[]).is_err());
    }
}
