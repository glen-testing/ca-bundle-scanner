//! End-to-end tests against the built binary. Tests marked `#[ignore]` need network
//! (crates.io, PyPI, uv) and ca-bundle-scanner; run with `cargo test -- --include-ignored`.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(p: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(p)
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ccic-cli-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn run(args: &[&str]) -> (i32, Value) {
    let out = Command::new(env!("CARGO_BIN_EXE_ca-certs-in-code"))
        .args(["-f", "json"])
        .args(args)
        .output()
        .unwrap();
    let json = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!("bad JSON ({e}): {}", String::from_utf8_lossy(&out.stdout))
    });
    (out.status.code().unwrap(), json)
}

fn packages(v: &Value) -> Vec<String> {
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["reachable"] == true)
        .map(|f| format!("{} {}", f["package"].as_str().unwrap(), f["version"].as_str().unwrap()))
        .collect()
}

// ── exit codes ──

#[test]
fn tp_error_exit_2_for_missing_lockfile() {
    let (code, v) = run(&["-l", "/nonexistent/Cargo.lock"]);
    assert_eq!(code, 2);
    assert!(!v["errors"].as_array().unwrap().is_empty());
}

#[test]
fn tp_error_exit_2_for_unparseable_lockfile() {
    let d = tmpdir("garbage");
    std::fs::write(d.join("package-lock.json"), "{ not json").unwrap();
    assert_eq!(run(&[d.to_str().unwrap()]).0, 2);
}

#[test]
fn fp_clean_project_exit_0() {
    let (code, v) = run(&["--no-resolve", fixture("cargo_no_bundler").to_str().unwrap()]);
    assert_eq!(code, 0, "{v}");
    assert!(packages(&v).is_empty());
}

#[test]
fn fp_empty_dir_exit_0() {
    assert_eq!(run(&[tmpdir("empty").to_str().unwrap()]).0, 0);
}

// ── detection / parsing ──

#[test]
fn tp_nested_requirements_found() {
    let d = tmpdir("nested");
    std::fs::create_dir_all(d.join("svc/api")).unwrap();
    std::fs::write(d.join("svc/api/requirements.txt"), "certifi==2024.8.30\n").unwrap();
    let (code, v) = run(&["--no-resolve", d.to_str().unwrap()]);
    assert_eq!(code, 1);
    assert_eq!(packages(&v), vec!["certifi 2024.8.30"]);
    assert!(v["findings"][0]["lockfile"].as_str().unwrap().starts_with('/'));
}

#[test]
fn tp_two_webpki_versions_reported() {
    let (code, v) = run(&["--no-resolve", fixture("cargo_two_webpki").to_str().unwrap()]);
    assert_eq!(code, 1);
    let mut p = packages(&v);
    p.sort();
    assert_eq!(p, vec!["webpki-roots 0.25.4", "webpki-roots 0.26.3"]);
}

#[test]
fn tp_npm_fixture() {
    let (code, v) = run(&[fixture("npm_with_ca_certs").to_str().unwrap()]);
    assert_eq!(code, 1);
    assert_eq!(packages(&v), vec!["ssl-root-cas 1.3.1"]);
}

// ── network: resolvers ──

#[test]
#[ignore = "network: uv resolves against PyPI"]
fn tp_requests_only_resolves_to_certifi() {
    let d = tmpdir("req-only");
    std::fs::write(d.join("requirements.txt"), "requests==2.32.3\n").unwrap();
    let (code, v) = run(&[d.to_str().unwrap()]);
    assert_eq!(code, 1, "{v}");
    let f = &v["findings"][0];
    assert_eq!(f["package"], "certifi");
    assert_eq!(f["evidence"], "runtime_dependency_path");
    assert!(f["dep_chain"][1].as_str().unwrap().starts_with("requests"));
}

#[test]
#[ignore = "network: uv resolves against PyPI"]
fn fp_requirements_without_bundler() {
    let d = tmpdir("six");
    std::fs::write(d.join("requirements.txt"), "six==1.16.0\n").unwrap();
    let (code, v) = run(&[d.to_str().unwrap()]);
    assert_eq!(code, 0, "{v}");
}

#[test]
#[ignore = "network: cargo metadata downloads crate manifests"]
fn tp_cargo_metadata_runtime_path() {
    // Fixture resolves rustls-webpki 0.103.16, so the reachable webpki-roots is mitigated (exit 0).
    let (code, v) = run(&[fixture("cargo_with_webpki").to_str().unwrap()]);
    let f = &v["findings"][0];
    assert_eq!(f["reachable"], true, "{v}");
    assert_eq!(f["evidence"], "runtime_dependency_path");
    assert!(f["mitigated_by"].as_str().is_some_and(|m| m.contains("0.103.16")), "{v}");
    assert_eq!(code, 0, "{v}");
}

#[test]
#[ignore = "network: cargo metadata downloads crate manifests"]
fn fp_cargo_dev_dependency_not_reported() {
    let dir = fixture("cargo_dev_only");
    let (code, v) = run(&[dir.to_str().unwrap()]);
    assert_eq!(code, 0, "{v}");
    assert!(packages(&v).is_empty(), "{v}");
    let (_, v) = run(&["--include-dev", dir.to_str().unwrap()]);
    assert_eq!(packages(&v), vec!["webpki-roots 1.0.11"], "{v}");
}

// ── network: deep scan ──

fn deep_scan_pinned(tag: &str, req: &str) -> (i32, Value) {
    let d = tmpdir(tag);
    std::fs::write(d.join("requirements.txt"), req).unwrap();
    run(&["--no-resolve", "--deep-scan", d.to_str().unwrap()])
}

#[test]
#[ignore = "network: downloads from PyPI; needs ca-bundle-scanner"]
fn tp_deep_scan_affected_certifi() {
    let (code, v) = deep_scan_pinned("certifi-old", "certifi==2024.8.30\n");
    assert_eq!(code, 1, "{v}");
    let b = &v["findings"][0]["bundle"];
    assert_eq!(b["affected"], true);
    assert_eq!(b["verdict"], "found");
    let affected: Vec<&str> = b["affected_certs"].as_array().unwrap().iter().map(|c| c.as_str().unwrap()).collect();
    assert!(affected.contains(&"emSign ECC Root CA - G3"), "{affected:?}");
    assert!(affected.contains(&"AAA Certificate Services"), "{affected:?}");
    assert!(affected.iter().all(|c| !c.contains("- G1") && !c.contains("- C1") && !c.contains("- C3")), "{affected:?}");
}

#[test]
#[ignore = "network: downloads from PyPI; needs ca-bundle-scanner"]
fn fp_deep_scan_patched_certifi_is_clean() {
    let (code, v) = deep_scan_pinned("certifi-new", "certifi==2026.10.23\n");
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["findings"][0]["bundle"]["affected"], false);
}

#[test]
#[ignore = "network: crates.io; needs ca-bundle-scanner"]
fn tp_deep_scan_webpki_roots_crate_download() {
    let (code, v) = run(&["--no-resolve", "--deep-scan", "--cache-dir", tmpdir("cache").to_str().unwrap(), fixture("cargo_two_webpki").to_str().unwrap()]);
    assert_eq!(code, 1, "{v}");
    for f in v["findings"].as_array().unwrap() {
        assert_eq!(f["bundle"]["affected"], true, "{f}");
    }
}

#[test]
fn tp_deep_scan_failure_exit_2() {
    let d = tmpdir("noscanner");
    std::fs::write(d.join("requirements.txt"), "certifi==2024.8.30\n").unwrap();
    let (code, v) = run(&["--no-resolve", "--deep-scan", "--scanner-path", "/nonexistent/scanner", d.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(v["findings"][0]["deep_scan_error"].is_string());
}

#[test]
#[ignore = "network: crates.io; needs ca-bundle-scanner"]
fn fp_deep_scan_fixed_webpki_roots_is_clean() {
    let d = tmpdir("webpki-fixed");
    std::fs::write(
        d.join("Cargo.lock"),
        "version = 3\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [\"webpki-roots\"]\n\n[[package]]\nname = \"webpki-roots\"\nversion = \"1.0.11\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n",
    )
    .unwrap();
    let cache = tmpdir("cache-fixed");
    let (code, v) = run(&["--no-resolve", "--deep-scan", "--cache-dir", cache.to_str().unwrap(), d.to_str().unwrap()]);
    assert_eq!(code, 0, "{v}");
    assert_eq!(v["findings"][0]["bundle"]["affected"], false);
    assert_eq!(v["findings"][0]["bundle"]["verdict"], "clean");
}

// ── rustls-webpki distrust list as a mitigation ──

fn rust_lock(tag: &str, webpki_versions: &[&str]) -> PathBuf {
    let d = tmpdir(tag);
    let mut deps = vec!["\"webpki-roots\"".to_string()];
    let mut pkgs = String::from("[[package]]\nname = \"webpki-roots\"\nversion = \"1.0.7\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n");
    for v in webpki_versions {
        deps.push(format!("\"rustls-webpki {v}\""));
        pkgs.push_str(&format!("[[package]]\nname = \"rustls-webpki\"\nversion = \"{v}\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n"));
    }
    let lock = format!("version = 3\n[[package]]\nname = \"app\"\nversion = \"0.1.0\"\ndependencies = [{}]\n\n{pkgs}", deps.join(", "));
    std::fs::write(d.join("Cargo.lock"), lock).unwrap();
    d
}

#[test]
fn tp_fixed_rustls_webpki_mitigates_webpki_roots() {
    let (code, v) = run(&["--no-resolve", rust_lock("wp-fixed", &["0.103.16"]).to_str().unwrap()]);
    assert_eq!(code, 0, "{v}");
    let f = &v["findings"][0];
    assert_eq!(f["reachable"], true);
    assert!(f["mitigated_by"].as_str().unwrap().contains("0.103.16"), "{f}");
}

#[test]
fn fp_unfixed_or_mixed_rustls_webpki_still_flagged() {
    for (tag, vs) in [("wp-old", vec!["0.103.13"]), ("wp-mixed", vec!["0.101.7", "0.103.16"]), ("wp-none", vec![])] {
        let (code, v) = run(&["--no-resolve", rust_lock(tag, &vs).to_str().unwrap()]);
        assert_eq!(code, 1, "{tag}: {v}");
        assert!(v["findings"][0].get("mitigated_by").is_none(), "{tag}: {v}");
    }
}
