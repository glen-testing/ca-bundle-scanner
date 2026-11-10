//! End-to-end tests of the analysis library. Tests marked `#[ignore]` need network
//! (crates.io, PyPI, uv); run with `cargo test -- --include-ignored`. Deep scans that
//! inspect downloaded bundles are tested through ca-bundle-scanner (`tests/cli.rs`).

use ca_certs_in_code::{run as analyse, RunConfig};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn fixture(p: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(p)
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ccic-cli-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Map the old command-line flags onto a RunConfig and run the analysis in-process.
fn run(args: &[&str]) -> (i32, Value) {
    let mut cfg = RunConfig::new(".");
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match *a {
            "-l" => cfg.lockfile_path = Some(PathBuf::from(it.next().unwrap())),
            "--no-resolve" => cfg.no_resolve = true,
            "--deep-scan" => cfg.deep_scan = true,
            "--include-dev" => cfg.include_dev = true,
            "--cache-dir" => cfg.cache_dir = Some(PathBuf::from(it.next().unwrap())),
            dir => cfg.target_dir = PathBuf::from(dir),
        }
    }
    let out = analyse(&cfg);
    let json =
        serde_json::json!({ "findings": out.findings, "errors": out.errors, "notes": out.notes });
    (
        out.exit_code(cfg.deep_scan) as i32,
        serde_json::from_value(json).unwrap(),
    )
}

fn packages(v: &Value) -> Vec<String> {
    v["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["reachable"] == true)
        .map(|f| {
            format!(
                "{} {}",
                f["package"].as_str().unwrap(),
                f["version"].as_str().unwrap()
            )
        })
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
    let (code, v) = run(&[
        "--no-resolve",
        fixture("cargo_no_bundler").to_str().unwrap(),
    ]);
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
    assert!(Path::new(v["findings"][0]["lockfile"].as_str().unwrap()).is_absolute());
}

#[test]
fn tp_two_webpki_versions_reported() {
    let (code, v) = run(&[
        "--no-resolve",
        fixture("cargo_two_webpki").to_str().unwrap(),
    ]);
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
    assert!(
        f["mitigated_by"]
            .as_str()
            .is_some_and(|m| m.contains("0.103.16")),
        "{v}"
    );
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

#[test]
fn tp_deep_scan_failure_exit_2() {
    let d = tmpdir("noscanner");
    std::fs::write(d.join("requirements.txt"), "certifi==2024.8.30\n").unwrap();
    // No bundle inspector is configured, so the deep scan cannot complete.
    let (code, v) = run(&["--no-resolve", "--deep-scan", d.to_str().unwrap()]);
    assert_eq!(code, 2);
    assert!(v["findings"][0]["deep_scan_error"].is_string());
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
    let (code, v) = run(&[
        "--no-resolve",
        rust_lock("wp-fixed", &["0.103.16"]).to_str().unwrap(),
    ]);
    assert_eq!(code, 0, "{v}");
    let f = &v["findings"][0];
    assert_eq!(f["reachable"], true);
    assert!(
        f["mitigated_by"].as_str().unwrap().contains("0.103.16"),
        "{f}"
    );
}

#[test]
fn fp_unfixed_or_mixed_rustls_webpki_still_flagged() {
    for (tag, vs) in [
        ("wp-old", vec!["0.103.13"]),
        ("wp-mixed", vec!["0.101.7", "0.103.16"]),
        ("wp-none", vec![]),
    ] {
        let (code, v) = run(&["--no-resolve", rust_lock(tag, &vs).to_str().unwrap()]);
        assert_eq!(code, 1, "{tag}: {v}");
        assert!(v["findings"][0].get("mitigated_by").is_none(), "{tag}: {v}");
    }
}

// ── more ecosystems, Electron, Go toolchain ──

fn write_files(tag: &str, files: &[(&str, &str)]) -> PathBuf {
    let d = tmpdir(tag);
    for (n, c) in files {
        std::fs::write(d.join(n), c).unwrap();
    }
    d
}

fn electron_lock(v: &str) -> String {
    format!(
        r#"{{"name":"app","version":"1.0.0","lockfileVersion":3,"packages":{{"":{{"devDependencies":{{"electron":"^{v}"}}}},"node_modules/electron":{{"version":"{v}","dev":true}}}}}}"#
    )
}

#[test]
fn tp_electron_devdependency_unpatched_is_found() {
    let d = write_files(
        "electron-old",
        &[("package-lock.json", &electron_lock("44.4.5"))],
    );
    let (code, v) = run(&["--deep-scan", d.to_str().unwrap()]);
    assert_eq!(code, 1, "{v}");
    assert_eq!(packages(&v), vec!["electron 44.4.5"]);
    assert_eq!(v["findings"][0]["bundle"]["affected"], true);
}

#[test]
fn fp_electron_patched_is_mitigated() {
    let d = write_files(
        "electron-new",
        &[("package-lock.json", &electron_lock("44.9.1"))],
    );
    let (code, v) = run(&["--deep-scan", d.to_str().unwrap()]);
    assert_eq!(code, 0, "{v}");
    assert!(v["findings"][0]["mitigated_by"]
        .as_str()
        .unwrap()
        .contains("44.9.1"));
}

fn go_mod(toolchain: &str) -> String {
    format!("module example.com/app\n\ngo 1.26\n\ntoolchain go{toolchain}\n\nrequire golang.org/x/crypto/x509roots/fallback v0.0.0-20240916204253-42ee18b96377\n")
}

#[test]
fn tp_go_fallback_with_old_toolchain_flagged() {
    let d = write_files("go-old", &[("go.mod", &go_mod("1.26.9"))]);
    assert_eq!(run(&[d.to_str().unwrap()]).0, 1);
}

#[test]
fn fp_go_fallback_with_fixed_toolchain_mitigated() {
    let d = write_files("go-new", &[("go.mod", &go_mod("1.26.10"))]);
    let (code, v) = run(&[d.to_str().unwrap()]);
    assert_eq!(code, 0, "{v}");
    assert!(v["findings"][0]["mitigated_by"]
        .as_str()
        .unwrap()
        .contains("1.26.10"));
}

const GEMFILE_LOCK: &str = "GEM\n  remote: https://rubygems.org/\n  specs:\n    excon (EXCON)\n    fog-core (2.6.0)\n      excon (~> 1.0)\n\nDEPENDENCIES\n  fog-core\n";
const COMPOSER_LOCK: &str = r#"{"packages":[{"name":"guzzlehttp/guzzle","version":"7.9.2","require":{"composer/ca-bundle":"^1.4"}},{"name":"composer/ca-bundle","version":"BUNDLE"}]}"#;
const MIX_LOCK: &str = "%{\n  \"castore\": {:hex, :castore, \"CASTORE\", \"a\", [:mix], [], \"hexpm\", \"b\"},\n  \"mint\": {:hex, :mint, \"1.6.2\", \"a\", [:mix], [{:castore, \"~> 1.0\", [hex: :castore, repo: \"hexpm\", optional: true]}], \"hexpm\", \"b\"},\n}\n";
const SNAPSHOT: &str = "# carton snapshot format: version 1.0\nDISTRIBUTIONS\n  Mozilla-CA-MOZCA\n    pathname: L/LW/LWP/Mozilla-CA-MOZCA.tar.gz\n    provides:\n      Mozilla::CA MOZCA\n";

fn eco_project(tag: &str, excon: &str, bundle: &str, castore: &str, mozca: &str) -> PathBuf {
    write_files(
        tag,
        &[
            ("Gemfile.lock", &GEMFILE_LOCK.replace("EXCON", excon)),
            ("composer.lock", &COMPOSER_LOCK.replace("BUNDLE", bundle)),
            ("mix.lock", &MIX_LOCK.replace("CASTORE", castore)),
            ("cpanfile.snapshot", &SNAPSHOT.replace("MOZCA", mozca)),
        ],
    )
}

#[test]
fn tp_ruby_php_hex_perl_bundlers_detected() {
    let d = eco_project("eco", "1.7.3", "1.4.15", "1.0.21", "20260813");
    let (code, v) = run(&["--no-resolve", d.to_str().unwrap()]);
    assert_eq!(code, 1, "{v}");
    let mut p = packages(&v);
    p.sort();
    assert_eq!(
        p,
        vec![
            "Mozilla-CA 20260813",
            "castore 1.0.21",
            "composer/ca-bundle 1.4.15",
            "excon 1.7.3"
        ]
    );
}

#[test]
fn fp_ruby_php_hex_perl_without_bundlers_clean() {
    let d = write_files("eco-clean", &[
        ("Gemfile.lock", "GEM\n  remote: https://rubygems.org/\n  specs:\n    rack (3.1.0)\n\nDEPENDENCIES\n  rack\n"),
        ("composer.lock", r#"{"packages":[{"name":"monolog/monolog","version":"3.7.0"}]}"#),
        ("mix.lock", "%{\n  \"jason\": {:hex, :jason, \"1.4.4\", \"a\", [:mix], [], \"hexpm\", \"b\"},\n}\n"),
        ("cpanfile.snapshot", "DISTRIBUTIONS\n  JSON-PP-4.16\n    pathname: I/IS/ISHIGAKI/JSON-PP-4.16.tar.gz\n"),
    ]);
    let (code, v) = run(&["--no-resolve", d.to_str().unwrap()]);
    assert_eq!(code, 0, "{v}");
}
