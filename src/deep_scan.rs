use crate::database::{Artifact, CertBundlerEntry};
use crate::{ResolvedDep, RunConfig};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// One finding from `ca-bundle-scanner --json` (report schema 2).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScannerFinding {
    pub path: String,
    pub source: String,
    pub cert: String,
    #[serde(default)]
    pub sha256: Option<String>,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(rename = "match", default)]
    pub matched: String,
    #[serde(default)]
    pub context: String,
    pub action_required: bool,
}

#[derive(Debug, serde::Deserialize)]
struct ScannerIssue {
    severity: String,
    message: String,
}

#[derive(Debug, serde::Deserialize)]
struct ScannerReport {
    schema: u32,
    verdict: String,
    findings: Vec<ScannerFinding>,
    #[serde(default)]
    issues: Vec<ScannerIssue>,
}

const SCANNER_SCHEMA: u32 = 2;

#[derive(Debug, Clone, serde::Serialize)]
pub struct BundleScan {
    pub artifact: String,
    /// The scanner's verdict for the artifact: clean or found.
    pub verdict: String,
    pub certs: Vec<ScannerFinding>,
    pub affected_certs: Vec<String>,
    pub affected: bool,
}

pub fn scan(bundler: &CertBundlerEntry, dep: &ResolvedDep, config: &RunConfig) -> Result<BundleScan> {
    if bundler.artifact == Artifact::VersionRule {
        return Ok(version_rule(bundler, dep));
    }
    let scanner = find_scanner(config.scanner_path.as_deref())?;
    let artifact = locate_or_fetch(bundler.artifact, dep, &cache_dir(config)?)?;
    let (verdict, certs) = run_scanner(&scanner, &artifact)?;
    Ok(classify(artifact.display().to_string(), verdict, certs))
}

/// Affected means the scanner marked at least one finding as needing action; which
/// roots count (distrusted, cross-sign, compromised) is the scanner's policy, not ours.
/// Packages whose payload is fetched at install time are judged by version.
fn version_rule(bundler: &CertBundlerEntry, dep: &ResolvedDep) -> BundleScan {
    let fixed = match bundler.package {
        "electron" => crate::database::electron_blocks_compromised_keys(&dep.version),
        _ => false,
    };
    BundleScan {
        artifact: format!("version rule for {} {}", dep.name, dep.version),
        verdict: if fixed { "clean" } else { "found" }.into(),
        certs: vec![],
        affected_certs: if fixed { vec![] } else { vec!["emSign ECC Root CA - G3 (compiled in, not blocked)".into()] },
        affected: !fixed,
    }
}

pub fn classify(artifact: String, verdict: String, certs: Vec<ScannerFinding>) -> BundleScan {
    let mut affected_certs: Vec<String> = certs.iter().filter(|c| c.action_required).map(|c| c.cert.clone()).collect();
    affected_certs.sort();
    affected_certs.dedup();
    BundleScan { artifact, verdict, affected: !affected_certs.is_empty(), affected_certs, certs }
}

pub fn find_scanner(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return if p.is_file() { Ok(p.to_path_buf()) } else { bail!("scanner not found at {}", p.display()) };
    }
    if let Some(p) = std::env::var_os("CA_BUNDLE_SCANNER").map(PathBuf::from) {
        if p.is_file() {
            return Ok(p);
        }
    }
    let on_path = std::env::var_os("PATH")
        .into_iter()
        .flat_map(|p| std::env::split_paths(&p).collect::<Vec<_>>())
        .map(|d| d.join("ca-bundle-scanner"));
    let home_build = std::env::var_os("HOME")
        .map(|h| PathBuf::from(h).join("ca-bundle-tracker/scanner/target/release/ca-bundle-scanner"));
    on_path
        .chain(home_build)
        .find(|p| p.is_file())
        .context("ca-bundle-scanner not found (use --scanner-path, $CA_BUNDLE_SCANNER, or PATH)")
}

fn cache_dir(config: &RunConfig) -> Result<PathBuf> {
    let dir = match &config.cache_dir {
        Some(d) => d.clone(),
        None => std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
            .context("no cache directory: set --cache-dir or $HOME")?
            .join("ca-certs-in-code"),
    };
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    Ok(dir)
}

pub fn run_scanner(scanner: &Path, artifact: &Path) -> Result<(String, Vec<ScannerFinding>)> {
    let out = Command::new(scanner)
        .args(["--profile", "emudhra", "--no-system", "-q", "-j", "-p"])
        .arg(artifact)
        .output()
        .with_context(|| format!("running {}", scanner.display()))?;
    let code = out.status.code();
    let report: Option<ScannerReport> = serde_json::from_slice(&out.stdout).ok();
    match (code, report) {
        (Some(0 | 1), Some(r)) if r.schema == SCANNER_SCHEMA => Ok((r.verdict, r.findings)),
        (Some(0 | 1), Some(r)) => bail!("scanner report schema {} (this tool reads schema {SCANNER_SCHEMA})", r.schema),
        (Some(3), Some(r)) => {
            let why: Vec<String> = r.issues.iter().filter(|i| i.severity == "error").map(|i| i.message.clone()).collect();
            bail!("scanner could not inspect the whole artifact: {}", why.join("; "))
        }
        (code, _) => bail!("scanner exited {code:?}: {}", String::from_utf8_lossy(&out.stderr).trim()),
    }
}

fn curl_text(url: &str) -> Result<String> {
    let out = Command::new("curl").args(["-fsSL", "--retry", "2", "--max-time", "60", url]).output().context("running curl")?;
    if !out.status.success() {
        bail!("GET {url} failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn curl_file(url: &str, dest: &Path) -> Result<PathBuf> {
    if dest.is_file() {
        return Ok(dest.to_path_buf());
    }
    std::fs::create_dir_all(dest.parent().context("dest has no parent")?)?;
    let tmp = dest.with_extension("part");
    let st = Command::new("curl").args(["-fsSL", "--retry", "2", "--max-time", "300", "-o"]).arg(&tmp).arg(url).status()?;
    if !st.success() {
        let _ = std::fs::remove_file(&tmp);
        bail!("download {url} failed");
    }
    std::fs::rename(&tmp, dest)?;
    Ok(dest.to_path_buf())
}

/// Go module proxy path escaping: uppercase letters become `!` + lowercase.
fn go_escape(s: &str) -> String {
    s.chars().flat_map(|c| if c.is_ascii_uppercase() { vec!['!', c.to_ascii_lowercase()] } else { vec![c] }).collect()
}

fn local_crate_dir(dep: &ResolvedDep) -> Option<PathBuf> {
    if let Some(dir) = dep.location.as_ref().filter(|d| d.is_dir()) {
        return Some(dir.clone());
    }
    let registry = PathBuf::from(std::env::var_os("CARGO_HOME").or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cargo").into_os_string()))?).join("registry/src");
    std::fs::read_dir(registry).ok()?.flatten().map(|e| e.path().join(format!("{}-{}", dep.name, dep.version))).find(|p| p.is_dir())
}

pub fn locate_or_fetch(kind: Artifact, dep: &ResolvedDep, cache: &Path) -> Result<PathBuf> {
    if kind == Artifact::Crate {
        if let Some(dir) = local_crate_dir(dep) {
            return Ok(dir);
        }
    }
    if dep.version.is_empty() {
        bail!("version of {} is unknown (pin it, or drop --no-resolve)", dep.name);
    }
    let (n, v) = (dep.name.as_str(), dep.version.as_str());
    match kind {
        Artifact::Crate => curl_file(
            &format!("https://static.crates.io/crates/{n}/{n}-{v}.crate"),
            &cache.join("crates").join(format!("{n}-{v}.crate")),
        ),
        Artifact::PypiWheel => {
            let meta: serde_json::Value = serde_json::from_str(&curl_text(&format!("https://pypi.org/pypi/{n}/{v}/json"))?)?;
            let urls = meta.get("urls").and_then(|u| u.as_array()).cloned().unwrap_or_default();
            let pick = |pred: &dyn Fn(&str) -> bool| {
                urls.iter().find(|u| u.get("filename").and_then(|f| f.as_str()).is_some_and(pred)).cloned()
            };
            // Any wheel/sdist is only read, never installed or built.
            let chosen = pick(&|f| f.ends_with("-none-any.whl"))
                .or_else(|| pick(&|f| f.ends_with(".whl")))
                .or_else(|| pick(&|f| f.ends_with(".tar.gz")))
                .with_context(|| format!("no downloadable file for {n} {v} on PyPI"))?;
            let url = chosen["url"].as_str().context("PyPI entry has no url")?;
            let file = chosen["filename"].as_str().context("PyPI entry has no filename")?;
            curl_file(url, &cache.join("pypi").join(file))
        }
        Artifact::NpmTarball => {
            let meta: serde_json::Value =
                serde_json::from_str(&curl_text(&format!("https://registry.npmjs.org/{}/{v}", n.replace('/', "%2F")))?)?;
            let url = meta["dist"]["tarball"].as_str().context("npm metadata has no dist.tarball")?;
            curl_file(url, &cache.join("npm").join(format!("{}-{v}.tgz", n.replace('/', "_"))))
        }
        Artifact::RubyGem => curl_file(
            &format!("https://rubygems.org/downloads/{n}-{v}.gem"),
            &cache.join("gems").join(format!("{n}-{v}.gem")),
        ),
        Artifact::HexTarball => curl_file(
            &format!("https://repo.hex.pm/tarballs/{n}-{v}.tar"),
            &cache.join("hex").join(format!("{n}-{v}.tar")),
        ),
        Artifact::Packagist => {
            let meta: serde_json::Value = serde_json::from_str(&curl_text(&format!("https://repo.packagist.org/p2/{n}.json"))?)?;
            let url = meta["packages"][n]
                .as_array()
                .and_then(|vs| vs.iter().find(|x| x["version"].as_str().map(|s| s.trim_start_matches('v')) == Some(v)))
                .and_then(|x| x["dist"]["url"].as_str())
                .with_context(|| format!("no Packagist dist for {n} {v}"))?
                .to_string();
            curl_file(&url, &cache.join("packagist").join(format!("{}-{v}.zip", n.replace('/', "_"))))
        }
        Artifact::CpanDist => {
            let module = n.replace('-', "::");
            let meta: serde_json::Value = serde_json::from_str(&curl_text(&format!(
                "https://fastapi.metacpan.org/v1/download_url/{module}?version=%3D%3D{v}"
            ))?)?;
            let url = meta["download_url"].as_str().with_context(|| format!("no CPAN release for {n} {v}"))?.to_string();
            curl_file(&url, &cache.join("cpan").join(format!("{n}-{v}.tar.gz")))
        }
        Artifact::VersionRule => bail!("{n} is judged by version, not downloaded"),
        Artifact::GoModule => curl_file(
            &format!("https://proxy.golang.org/{}/@v/{}.zip", go_escape(n), go_escape(v)),
            &cache.join("go").join(format!("{}@{v}.zip", n.replace('/', "_"))),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Ecosystem;

    fn cert(name: &str, kind: &str, action: bool) -> ScannerFinding {
        ScannerFinding {
            path: "x".into(),
            source: "PEM CERTIFICATE".into(),
            cert: name.into(),
            sha256: Some("ab".repeat(32)),
            kind: kind.into(),
            matched: "certificate".into(),
            context: "trust".into(),
            action_required: action,
        }
    }

    #[test]
    fn tp_action_required_finding_is_affected() {
        let b = classify(
            "a".into(),
            "found".into(),
            vec![cert("emSign ECC Root CA - G3", "distrusted-root", true), cert("emSign Root CA - G1", "info-root", false)],
        );
        assert!(b.affected);
        assert_eq!(b.affected_certs, vec!["emSign ECC Root CA - G3"]);
    }

    #[test]
    fn tp_cross_sign_root_in_bundle_is_affected() {
        assert!(classify("a".into(), "found".into(), vec![cert("AAA Certificate Services", "cross-sign-root", true)]).affected);
    }

    #[test]
    fn fp_informational_roots_only() {
        let certs = vec![
            cert("emSign Root CA - G1", "info-root", false),
            cert("emSign Root CA - C1", "info-root", false),
            cert("fingerprint of emSign ECC Root CA - G3", "reference", false),
        ];
        let b = classify("a".into(), "clean".into(), certs);
        assert!(!b.affected && b.affected_certs.is_empty());
        assert_eq!(b.certs.len(), 3);
    }

    #[test]
    fn fp_empty_bundle() {
        assert!(!classify("a".into(), "clean".into(), vec![]).affected);
    }

    #[test]
    fn tp_crate_located_from_metadata_without_network() {
        let mut dep = ResolvedDep::new("webpki-roots", "9.9.9", Ecosystem::Rust);
        dep.location = Some(std::env::temp_dir());
        let p = locate_or_fetch(Artifact::Crate, &dep, Path::new("/nonexistent")).unwrap();
        assert_eq!(p, std::env::temp_dir());
    }

    #[test]
    fn fp_unknown_version_is_error() {
        let dep = ResolvedDep::new("certifi", "", Ecosystem::Python);
        assert!(locate_or_fetch(Artifact::PypiWheel, &dep, Path::new("/tmp")).is_err());
    }

    fn fake_scanner(tag: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = std::env::temp_dir().join(format!("ccic-fake-scanner-{tag}-{}", std::process::id()));
        std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    const REPORT: &str = r#"{"schema":2,"profile":"emudhra","verdict":"found","exit_code":1,"files_scanned":1,"findings":[{"path":"p","source":"PEM CERTIFICATE","cert":"emSign ECC Root CA - G3","sha256":"ab","type":"distrusted-root","match":"certificate","context":"trust","action_required":true},{"path":"p","source":"text","cert":"CA name","type":"reference","match":"keyword","context":"source","action_required":false}],"issues":[],"locations":[]}"#;

    #[test]
    fn tp_schema2_report_parsed_on_exit_1() {
        let s = fake_scanner("ok", &format!("echo '{REPORT}'; exit 1"));
        let (verdict, f) = run_scanner(&s, Path::new("/x")).unwrap();
        assert_eq!((verdict.as_str(), f.len()), ("found", 2));
        assert!(f[0].action_required && f[1].sha256.is_none());
    }

    #[test]
    fn fp_incomplete_scan_not_treated_as_clean() {
        let body = r#"{"schema":2,"verdict":"incomplete","findings":[],"issues":[{"path":"p","severity":"error","message":"ZIP entry not inspected"}]}"#;
        let s = fake_scanner("inc", &format!("echo '{body}'; exit 3"));
        let e = run_scanner(&s, Path::new("/x")).unwrap_err().to_string();
        assert!(e.contains("ZIP entry not inspected"), "{e}");
    }

    #[test]
    fn fp_other_schema_or_old_array_rejected() {
        let s = fake_scanner("v3", &format!("echo '{}'; exit 0", REPORT.replace("\"schema\":2", "\"schema\":3")));
        assert!(run_scanner(&s, Path::new("/x")).is_err());
        let s = fake_scanner("arr", r#"echo '[]'; exit 0"#);
        assert!(run_scanner(&s, Path::new("/x")).is_err());
    }

    #[test]
    fn fp_scanner_usage_error() {
        let s = fake_scanner("err", "echo boom >&2; exit 2");
        assert!(run_scanner(&s, Path::new("/x")).is_err());
    }

    #[test]
    fn go_path_escaping() {
        assert_eq!(go_escape("github.com/Azure/x"), "github.com/!azure/x");
    }
}
