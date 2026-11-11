//! End-to-end tests of the ca-bundle-scanner binary. Every issue ID from
//! ISSUES.md has a true-positive (tp) and a false-positive (fp) test.
//! All runs use --no-system so the host trust store cannot affect results.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use assert_cmd::Command;
use serde_json::Value;

fn certs_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("certs/emudhra")
}
fn data_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data")
}
fn der(name: &str) -> Vec<u8> {
    fs::read(certs_dir().join(format!("{name}.der"))).unwrap()
}
fn data(name: &str) -> Vec<u8> {
    fs::read(data_dir().join(name)).unwrap()
}
fn pem(der: &[u8], label: &str) -> String {
    const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for chunk in der.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                s.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    let body: Vec<String> = s
        .as_bytes()
        .chunks(64)
        .map(|c| String::from_utf8(c.to_vec()).unwrap())
        .collect();
    format!(
        "-----BEGIN {label}-----\n{}\n-----END {label}-----\n",
        body.join("\n")
    )
}
fn b64(der: &[u8]) -> String {
    pem(der, "X")
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .collect()
}

const TARGET: &str = "EM_DV_TLS_CA_G3B_emSign";
fn target_pem() -> String {
    pem(&der(TARGET), "CERTIFICATE")
}
fn clean_pem() -> String {
    String::from_utf8(data("clean_leaf.pem")).unwrap()
}
fn clean_der() -> Vec<u8> {
    let p = clean_pem();
    let body: String = p.lines().filter(|l| !l.starts_with("-----")).collect();
    decode_b64(&body)
}
fn decode_b64(s: &str) -> Vec<u8> {
    let val = |c: u8| match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' => 62,
        _ => 63,
    };
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u32, 0);
    for c in s.bytes().filter(|c| *c != b'=') {
        acc = (acc << 6) | val(c) as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

struct Out {
    code: i32,
    json: Value,
    stdout: String,
    stderr: String,
}

fn run_args(args: &[&str], env: &[(&str, &str)]) -> Out {
    let mut cmd = Command::cargo_bin("ca-bundle-scanner").unwrap();
    cmd.args(args);
    for (k, v) in env {
        cmd.env(k, v);
    }
    let o = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout).into_owned();
    Out {
        code: o.status.code().unwrap_or(-1),
        json: serde_json::from_str(&stdout).unwrap_or(Value::Null),
        stdout,
        stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
    }
}

/// Scan paths with the eMudhra profile, JSON output, single job, no system paths.
fn scan(paths: &[&Path]) -> Out {
    let mut args = vec![
        "--profile",
        "emudhra",
        "--no-system",
        "--json",
        "--jobs",
        "1",
    ];
    let strs: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    for s in &strs {
        args.push("-p");
        args.push(s);
    }
    run_args(&args, &[])
}

fn write(dir: &Path, name: &str, bytes: impl AsRef<[u8]>) -> PathBuf {
    let p = dir.join(name);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(&p, bytes).unwrap();
    p
}

fn findings(o: &Out) -> Vec<Value> {
    o.json["findings"].as_array().cloned().unwrap_or_default()
}
fn action(o: &Out) -> Vec<Value> {
    findings(o)
        .into_iter()
        .filter(|f| f["action_required"] == true)
        .collect()
}
fn errors(o: &Out) -> Vec<Value> {
    o.json["issues"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| i["severity"] == "error")
        .collect()
}
fn has_sha(o: &Out, sha: &str) -> bool {
    findings(o).iter().any(|f| f["sha256"] == sha)
}
const TARGET_SHA: &str = "42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493";

fn assert_found(o: &Out) {
    assert_eq!(
        o.code, 1,
        "expected exit 1\nstdout: {}\nstderr: {}",
        o.stdout, o.stderr
    );
    assert!(!action(o).is_empty());
}
fn assert_clean(o: &Out) {
    assert_eq!(
        o.code, 0,
        "expected exit 0\nstdout: {}\nstderr: {}",
        o.stdout, o.stderr
    );
    assert!(action(o).is_empty());
    assert!(errors(o).is_empty(), "unexpected errors: {:?}", errors(o));
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    e.write_all(bytes).unwrap();
    e.finish().unwrap()
}
fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (n, b) in entries {
        w.start_file(*n, opts).unwrap();
        w.write_all(b).unwrap();
    }
    w.finish().unwrap().into_inner()
}
fn tar_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = tar::Builder::new(Vec::new());
    for (n, d) in entries {
        let mut h = tar::Header::new_gnu();
        h.set_size(d.len() as u64);
        h.set_mode(0o644);
        h.set_cksum();
        b.append_data(&mut h, n, *d).unwrap();
    }
    b.into_inner().unwrap()
}
fn ar_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut v = b"!<arch>\n".to_vec();
    for (n, d) in entries {
        v.extend_from_slice(
            format!(
                "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                n,
                0,
                0,
                0,
                644,
                d.len()
            )
            .as_bytes(),
        );
        v.extend_from_slice(d);
        if d.len() % 2 == 1 {
            v.push(b'\n');
        }
    }
    v
}
fn cpio_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut v = Vec::new();
    let mut push = |name: &str, d: &[u8], mode: u32| {
        let hdr =
            format!(
            "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
            1, mode, 0, 0, 1, 0, d.len(), 0, 0, 0, 0, name.len() + 1, 0
        );
        v.extend_from_slice(hdr.as_bytes());
        v.extend_from_slice(name.as_bytes());
        v.push(0);
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v.extend_from_slice(d);
        while v.len() % 4 != 0 {
            v.push(0);
        }
    };
    for (n, d) in entries {
        push(n, d, 0o100644);
    }
    push("TRAILER!!!", b"", 0);
    v
}
fn rpm_of(payload: &[u8]) -> Vec<u8> {
    let mut v = vec![0xed, 0xab, 0xee, 0xdb];
    v.resize(96, 0);
    let header = [0x8e, 0xad, 0xe8, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    v.extend_from_slice(&header); // signature header, 16 bytes (already 8-aligned)
    v.extend_from_slice(&header); // main header
    v.extend_from_slice(payload);
    v
}

// ── C01: nested certificates after a non-matching DER span ──────────────

#[test]
fn c01_tp_p7b_p12_and_stray_header() {
    let t = tempfile::tempdir().unwrap();
    let p7 = write(t.path(), "a.p7b", data("target.p7b"));
    let p12 = write(t.path(), "b.p12", data("target_nopass.p12"));
    let mut stray = vec![0x30, 0x82, 0x0f, 0x00];
    stray.extend_from_slice(&der(TARGET));
    stray.extend(std::iter::repeat_n(0u8, 0x1000));
    let bin = write(t.path(), "c.bin", stray);
    for p in [&p7, &p12, &bin] {
        let o = scan(&[p]);
        assert_found(&o);
        assert!(has_sha(&o, TARGET_SHA), "{}", p.display());
    }
}

#[test]
fn c01_fp_clean_containers() {
    let t = tempfile::tempdir().unwrap();
    let p7 = write(t.path(), "a.p7b", data("clean.p7b"));
    let p12 = write(t.path(), "b.p12", data("clean_nopass.p12"));
    let mut stray = vec![0x30, 0x82, 0x0f, 0x00];
    stray.extend_from_slice(&clean_der());
    stray.extend(std::iter::repeat_n(0u8, 0x1000));
    let bin = write(t.path(), "c.bin", stray);
    assert_clean(&scan(&[&p7, &p12, &bin]));
}

// ── C02: malformed PEM blocks must not hide the rest ────────────────────

#[test]
fn c02_tp_bad_block_and_unterminated_begin() {
    let t = tempfile::tempdir().unwrap();
    let bad = "-----BEGIN CERTIFICATE-----\n!!not base64!!\n-----END CERTIFICATE-----\n";
    let mismatched = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END X509 CRL-----\n";
    let unterminated = "-----BEGIN CERTIFICATE-----\nMIIBAAAA\n";
    let a = write(t.path(), "a.pem", format!("{bad}{}", target_pem()));
    let b = write(t.path(), "b.pem", format!("{mismatched}{}", target_pem()));
    let c = write(t.path(), "c.pem", format!("{unterminated}{}", target_pem()));
    let mut bin = vec![0xffu8, 0xfe, 0x00];
    bin.extend_from_slice(unterminated.as_bytes());
    bin.extend_from_slice(target_pem().as_bytes());
    let d = write(t.path(), "d.bin", bin);
    for p in [&a, &b, &c, &d] {
        let o = scan(&[p]);
        assert_found(&o);
        assert!(has_sha(&o, TARGET_SHA), "{}", p.display());
    }
}

#[test]
fn c02_fp_bad_block_with_clean_cert() {
    let t = tempfile::tempdir().unwrap();
    let bad = "-----BEGIN CERTIFICATE-----\n!!not base64!!\n-----END CERTIFICATE-----\n";
    let a = write(t.path(), "a.pem", format!("{bad}{}", clean_pem()));
    assert_clean(&scan(&[&a]));
}

// ── C03: only the distrusted root drives the verdict ─────────────────────

#[test]
fn c03_tp_ecc_g3_is_distrusted() {
    let t = tempfile::tempdir().unwrap();
    let p = write(
        t.path(),
        "g3.pem",
        pem(&der("emSign_ECC_Root_G3"), "CERTIFICATE"),
    );
    let o = scan(&[&p]);
    assert_found(&o);
    assert_eq!(action(&o)[0]["type"], "distrusted-root");
}

#[test]
fn c03_fp_g1_c1_c3_are_informational() {
    let t = tempfile::tempdir().unwrap();
    let text: String = ["emSign_Root_G1", "emSign_Root_C1", "emSign_ECC_Root_C3"]
        .iter()
        .map(|n| pem(&der(n), "CERTIFICATE"))
        .collect();
    let p = write(t.path(), "patched-certifi.pem", text);
    let o = scan(&[&p]);
    assert_clean(&o);
    let f = findings(&o);
    assert_eq!(f.len(), 3);
    assert!(f
        .iter()
        .all(|x| x["type"] == "info-root" && x["action_required"] == false));
    assert!(!o.stdout.contains("make the system trust"));
}

// ── C04: exit codes ──────────────────────────────────────────────────────

#[test]
fn c04_tp_failures_are_not_clean() {
    let t = tempfile::tempdir().unwrap();
    let missing = t.path().join("nope.pem");
    let o = scan(&[&missing]);
    assert_eq!(o.code, 3, "{}", o.stdout);
    assert!(!errors(&o).is_empty());

    if cfg!(unix) && !is_root_user() {
        let p = write(t.path(), "locked.pem", target_pem());
        set_mode(&p, 0o000);
        let o = scan(&[&p]);
        set_mode(&p, 0o644);
        assert_eq!(o.code, 3);
    }
    // Nothing scanned at all.
    let o = run_args(&["--profile", "emudhra", "--no-system", "--json"], &[]);
    assert_eq!(o.code, 3);
    // Usage errors exit 2, never 1.
    assert_eq!(
        run_args(&["--profile", "emudhra", "--scan-paht", "x"], &[]).code,
        2
    );
    assert_eq!(run_args(&["--profile", "emudhra", "-p"], &[]).code, 2);
    assert_eq!(run_args(&["--no-system"], &[]).code, 2);
    assert_eq!(run_args(&["-f", "abcd"], &[]).code, 2);
    let h = run_args(&["--help"], &[]);
    assert_eq!(h.code, 0);
    assert!(h.stdout.contains("Usage"));
    let v = run_args(&["--version"], &[]);
    assert_eq!(v.code, 0);
    assert!(v.stdout.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn c04_fp_readable_clean_file_exits_zero() {
    let t = tempfile::tempdir().unwrap();
    let p = write(t.path(), "ok.pem", clean_pem());
    let o = scan(&[&p]);
    assert_clean(&o);
    assert_eq!(o.json["files_scanned"], 1);
}

#[cfg(unix)]
fn set_mode(p: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
}
#[cfg(not(unix))]
fn set_mode(_: &Path, _: u32) {}
fn is_root_user() -> bool {
    std::env::var("USER").map(|u| u == "root").unwrap_or(false)
}

// ── C05: code-signing intermediates ─────────────────────────────────────

#[test]
fn c05_tp_code_signing_cas() {
    let t = tempfile::tempdir().unwrap();
    let names = [
        "EM_OV_CS_CA_G3B_emSign",
        "EM_OV_CS_CA_G3C_emSign",
        "EM_OV_CS_CA_G3B_AAA",
        "EM_OV_CS_CA_G3C_AAA",
    ];
    let text: String = names.iter().map(|n| pem(&der(n), "CERTIFICATE")).collect();
    let p = write(t.path(), "cs.pem", text);
    let o = scan(&[&p]);
    assert_found(&o);
    assert_eq!(action(&o).len(), 4);
    assert!(action(&o).iter().all(|f| f["type"] == "compromised"));
}

#[test]
fn c05_fp_other_code_signing_cert() {
    let t = tempfile::tempdir().unwrap();
    let p = write(t.path(), "other.pem", clean_pem());
    assert_clean(&scan(&[&p]));
}

// ── C06: same compromised key in a different certificate ────────────────

#[test]
fn c06_tp_reissued_cert_and_bare_key() {
    let t = tempfile::tempdir().unwrap();
    let p = write(t.path(), "reissued.pem", data("reissued_same_key.pem"));
    let o = scan(&[&p]);
    assert_found(&o);
    let f = &action(&o)[0];
    assert_eq!(f["match"], "public-key");
    assert_eq!(f["type"], "compromised");

    // The 97-byte EC point alone, as a trust-anchor list would store it.
    let target = der(TARGET);
    let point_at = target
        .windows(3)
        .position(|w| w == [0x03, 0x62, 0x00])
        .unwrap()
        + 3;
    let mut bin = vec![0u8; 512];
    bin.extend_from_slice(&target[point_at..point_at + 97]);
    bin.extend(vec![0u8; 512]);
    let q = write(t.path(), "anchors.bin", bin);
    let o = scan(&[&q]);
    assert_found(&o);
    assert_eq!(action(&o)[0]["match"], "public-key");
}

#[test]
fn c06_fp_unrelated_key() {
    let t = tempfile::tempdir().unwrap();
    let p = write(t.path(), "leaf.pem", data("leaf_issued_by_testca.pem"));
    assert_clean(&scan(&[&p]));
}

// ── C07: AAA Certificate Services cross-sign root ───────────────────────

#[test]
fn c07_tp_aaa_in_a_bundle() {
    let t = tempfile::tempdir().unwrap();
    let p = write(
        t.path(),
        "botocore/cacert.pem",
        pem(&der("Sectigo_AAA_Certificate_Services"), "CERTIFICATE"),
    );
    let o = scan(&[&p]);
    assert_found(&o);
    assert_eq!(action(&o)[0]["type"], "cross-sign-root");
}

// --root resolves the Unix location table.
#[cfg(not(windows))]
#[test]
fn c07_fp_aaa_in_platform_store_is_informational() {
    let t = tempfile::tempdir().unwrap();
    write(
        t.path(),
        "root/.mozilla/firefox/p.default/cert9.db",
        der("Sectigo_AAA_Certificate_Services"),
    );
    let o = run_args(
        &[
            "--profile",
            "emudhra",
            "--json",
            "--root",
            t.path().to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(o.code, 0, "{}", o.stdout);
    let f = findings(&o);
    assert_eq!(f.len(), 1);
    assert_eq!(f[0]["context"], "platform-store");
    assert_eq!(f[0]["action_required"], false);
}

// ── C08: directory walk coverage ─────────────────────────────────────────

#[cfg(unix)]
#[test]
fn c08_tp_symlink_der_uppercase_hashname() {
    let t = tempfile::tempdir().unwrap();
    let store = t.path().join("store");
    let real = write(t.path(), "real/target.crt", target_pem());
    fs::create_dir_all(&store).unwrap();
    std::os::unix::fs::symlink(&real, store.join("link.pem")).unwrap();
    let cases = [
        ("store2/ca.der", der(TARGET)),
        ("store3/CA.PEM", target_pem().into_bytes()),
        ("store4/b74d2bd5.0", target_pem().into_bytes()),
        ("store5/ca-bundle.trust.p11-kit", target_pem().into_bytes()),
    ];
    let mut dirs = vec![store.clone()];
    for (n, b) in &cases {
        let p = write(t.path(), n, b);
        dirs.push(p.parent().unwrap().to_path_buf());
    }
    for d in &dirs {
        let o = scan(&[d]);
        assert_found(&o);
        assert!(has_sha(&o, TARGET_SHA), "{}", d.display());
    }
}

#[test]
fn c08_fp_same_layout_clean() {
    let t = tempfile::tempdir().unwrap();
    write(t.path(), "ca.der", clean_der());
    write(t.path(), "CA.PEM", clean_pem());
    write(t.path(), "b74d2bd5.0", clean_pem());
    write(t.path(), "notes.txt", "hello");
    let o = scan(&[t.path()]);
    assert_clean(&o);
    assert_eq!(o.json["files_scanned"], 4);
}

// ── C09: DMG / MSI detection must not skip scanning ─────────────────────

#[test]
fn c09_tp_koly_and_ole2_still_scanned() {
    let t = tempfile::tempdir().unwrap();
    let mut a = target_pem().into_bytes();
    a.extend_from_slice(&[0u8; 600]);
    a.extend_from_slice(b"koly");
    let p = write(t.path(), "evade.pem", &a);
    assert_found(&scan(&[&p]));

    let mut dmg = der(TARGET);
    let mut trailer = vec![0u8; 512];
    trailer[..4].copy_from_slice(b"koly");
    trailer[4..8].copy_from_slice(&[0, 0, 0, 4]);
    trailer[8..12].copy_from_slice(&[0, 0, 2, 0]);
    dmg.extend_from_slice(&trailer);
    let o = scan(&[&write(t.path(), "x.dmg", &dmg)]);
    assert_found(&o);
    assert!(o.json["issues"].to_string().contains("disk image"));

    let mut msi = vec![0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];
    msi.extend_from_slice(&der(TARGET));
    assert_found(&scan(&[&write(t.path(), "x.msi", &msi)]));
}

#[test]
fn c09_fp_clean_with_koly() {
    let t = tempfile::tempdir().unwrap();
    let mut a = clean_pem().into_bytes();
    a.extend_from_slice(b"koly");
    assert_clean(&scan(&[&write(t.path(), "a.pem", &a)]));
}

// ── C10: TRUSTED CERTIFICATE and X509 CERTIFICATE labels ────────────────

#[test]
fn c10_tp_trusted_and_x509_labels() {
    let t = tempfile::tempdir().unwrap();
    let a = write(t.path(), "trust.crt", data("trusted_g3_tls.pem"));
    let o = scan(&[&a]);
    assert_found(&o);
    assert!(action(&o)[0]["source"]
        .as_str()
        .unwrap()
        .contains("tls-server"));
    let b = write(t.path(), "old.pem", pem(&der(TARGET), "X509 CERTIFICATE"));
    assert_found(&scan(&[&b]));
}

#[test]
fn c10_fp_trusted_clean() {
    let t = tempfile::tempdir().unwrap();
    assert_clean(&scan(&[&write(
        t.path(),
        "trust.crt",
        data("trusted_clean.pem"),
    )]));
}

// ── C11: escaped PEM and base64-wrapped certificates ────────────────────

#[test]
fn c11_tp_json_escaped_and_base64() {
    let t = tempfile::tempdir().unwrap();
    let escaped = target_pem().replace('\n', "\\n");
    let a = write(t.path(), "conf.json", format!("{{\"ca\": \"{escaped}\"}}"));
    assert_found(&scan(&[&a]));
    let kube = format!(
        "clusters:\n- cluster:\n    certificate-authority-data: {}\n    server: https://k\n",
        b64(target_pem().as_bytes())
    );
    assert_found(&scan(&[&write(t.path(), "kubeconfig", kube)]));
    let raw = format!("cert = \"{}\"\n", b64(&der(TARGET)));
    assert_found(&scan(&[&write(t.path(), "settings.toml", raw)]));
}

#[test]
fn c11_fp_base64_of_clean_cert() {
    let t = tempfile::tempdir().unwrap();
    let kube = format!(
        "certificate-authority-data: {}\n",
        b64(clean_pem().as_bytes())
    );
    let escaped = clean_pem().replace('\n', "\\n");
    let a = write(t.path(), "kubeconfig", kube);
    let b = write(t.path(), "conf.json", format!("{{\"ca\": \"{escaped}\"}}"));
    assert_clean(&scan(&[&a, &b]));
}

// ── C12: multi-member gzip ───────────────────────────────────────────────

#[test]
fn c12_tp_second_gzip_member() {
    let t = tempfile::tempdir().unwrap();
    let mut gz = gzip(clean_pem().as_bytes());
    gz.extend(gzip(target_pem().as_bytes()));
    assert_found(&scan(&[&write(t.path(), "b.pem.gz", gz)]));
}

#[test]
fn c12_fp_multi_member_clean() {
    let t = tempfile::tempdir().unwrap();
    let mut gz = gzip(clean_pem().as_bytes());
    gz.extend(gzip(b"just text"));
    assert_clean(&scan(&[&write(t.path(), "b.pem.gz", gz)]));
}

// ── C13: encrypted containers are reported as not inspected ─────────────

#[test]
fn c13_tp_encrypted_p12_and_zip_are_incomplete() {
    let t = tempfile::tempdir().unwrap();
    for (n, f) in [
        ("a.p12", "target_encrypted.p12"),
        ("b.zip", "target_encrypted.zip"),
    ] {
        let o = scan(&[&write(t.path(), n, data(f))]);
        assert_eq!(o.code, 3, "{n}: {}", o.stdout);
        assert!(!errors(&o).is_empty());
    }
}

#[test]
fn c13_fp_plain_containers_no_error() {
    let t = tempfile::tempdir().unwrap();
    let a = write(t.path(), "a.p12", data("clean_nopass.p12"));
    let b = write(
        t.path(),
        "b.zip",
        zip_of(&[("x.pem", clean_pem().as_bytes())]),
    );
    assert_clean(&scan(&[&a, &b]));
}

// ── C14: presence in a distrust / source location is not trust ──────────

// --root resolves the Unix location table.
#[cfg(not(windows))]
#[test]
fn c14_fp_blocklist_source_and_trust_flags() {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    write(r, "etc/pki/ca-trust/source/blocklist/em.pem", target_pem());
    write(
        r,
        "usr/share/pki/ca-trust-source/blocklist/em.pem",
        target_pem(),
    );
    write(
        r,
        "usr/share/ca-certificates/mozilla/g3.crt",
        pem(&der("emSign_ECC_Root_G3"), "CERTIFICATE"),
    );
    let p11 = format!(
        "[p11-kit-object-v1]\nclass: certificate\nx-distrusted: true\n{}",
        target_pem()
    );
    write(r, "etc/pki/ca-trust/source/anchors/distrusted.p11-kit", p11);
    write(
        r,
        "etc/pki/tls/certs/ca-bundle.trust.crt",
        data("trusted_g3_rejected.pem"),
    );
    write(
        r,
        "etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt",
        data("trusted_g3_email.pem"),
    );
    let o = run_args(
        &[
            "--profile",
            "emudhra",
            "--json",
            "--root",
            r.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(o.code, 0, "{}", o.stdout);
    let f = findings(&o);
    assert_eq!(f.len(), 6, "{f:#?}");
    assert!(f.iter().all(|x| x["action_required"] == false));
    let ctxs: Vec<&str> = f.iter().map(|x| x["context"].as_str().unwrap()).collect();
    assert!(ctxs.contains(&"distrust") && ctxs.contains(&"source") && ctxs.contains(&"restricted"));
}

// --root resolves the Unix location table.
#[cfg(not(windows))]
#[test]
fn c14_tp_same_certs_in_active_locations() {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    write(r, "etc/pki/ca-trust/source/anchors/em.pem", target_pem());
    write(
        r,
        "etc/ssl/certs/ca-certificates.crt",
        data("trusted_g3_tls.pem"),
    );
    let o = run_args(
        &[
            "--profile",
            "emudhra",
            "--json",
            "--root",
            r.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(o.code, 1, "{}", o.stdout);
    assert_eq!(action(&o).len(), 2);
}

// ── C15: location table under --root ────────────────────────────────────

// --root resolves the Unix location table.
#[cfg(not(windows))]
#[test]
fn c15_tp_aws_cli_and_snap_firefox_paths() {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    let aaa = pem(&der("Sectigo_AAA_Certificate_Services"), "CERTIFICATE");
    write(
        r,
        "usr/lib/python3.9/site-packages/awscli/botocore/cacert.pem",
        &aaa,
    );
    write(
        r,
        "usr/local/aws-cli/v2/2.30.0/dist/awscli/botocore/cacert.pem",
        &aaa,
    );
    write(
        r,
        "home/bob/snap/firefox/common/.mozilla/firefox/x/cert9.db",
        der(TARGET),
    );
    let o = run_args(
        &[
            "--profile",
            "emudhra",
            "--json",
            "--root",
            r.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(o.code, 1);
    assert_eq!(action(&o).len(), 3, "{:#?}", findings(&o));
}

// --root resolves the Unix location table.
#[cfg(not(windows))]
#[test]
fn c15_fp_same_paths_clean() {
    let t = tempfile::tempdir().unwrap();
    let r = t.path();
    write(
        r,
        "usr/lib/python3.9/site-packages/awscli/botocore/cacert.pem",
        clean_pem(),
    );
    write(
        r,
        "home/bob/snap/firefox/common/.mozilla/firefox/x/cert9.db",
        clean_der(),
    );
    let o = run_args(
        &[
            "--profile",
            "emudhra",
            "--json",
            "--root",
            r.to_str().unwrap(),
        ],
        &[],
    );
    assert_clean(&o);
    assert_eq!(o.json["files_scanned"], 2);
}

// ── C16: home scan skips package caches ─────────────────────────────────

#[test]
fn c16_home_scan_skips_cargo_registry_but_finds_others() {
    let t = tempfile::tempdir().unwrap();
    let h = t.path();
    write(h, ".cargo/registry/src/crate/tests/em.pem", target_pem());
    write(h, "projects/ok.pem", clean_pem());
    let home = h.to_str().unwrap();
    let args = [
        "--profile",
        "emudhra",
        "--no-system",
        "--scan-home",
        "--json",
    ];
    // fp: the only target is inside a skipped cache.
    let o = run_args(&args, &[("HOME", home)]);
    assert_eq!(o.code, 0, "{}", o.stdout);
    assert!(findings(&o).is_empty());
    assert_eq!(o.json["files_scanned"], 1);
    // tp: a target elsewhere in HOME is found.
    write(h, "projects/certs/em.pem", target_pem());
    let o = run_args(&args, &[("HOME", home)]);
    assert_eq!(o.code, 1);
    assert_eq!(action(&o).len(), 1);
}

// ── C18: JSON output is valid for any path ───────────────────────────────

#[cfg(unix)]
#[test]
fn c18_tp_hostile_file_names_roundtrip() {
    let t = tempfile::tempdir().unwrap();
    let name = "we\"ird\\na\tme\n.pem";
    let p = write(t.path(), name, target_pem());
    let o = scan(&[&p]);
    assert!(o.json.is_object(), "invalid JSON: {}", o.stdout);
    assert_eq!(action(&o)[0]["path"], p.to_str().unwrap());
    let z = write(
        t.path(),
        "e.zip",
        zip_of(&[("\"],\"x\":[\"", target_pem().as_bytes())]),
    );
    let o = scan(&[&z]);
    assert!(o.json.is_object());
    let mut keys: Vec<&str> = o
        .json
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort();
    let want = [
        "dependencies",
        "exit_code",
        "files_scanned",
        "findings",
        "issues",
        "items",
        "locations",
        "profile",
        "schema",
        "verdict",
    ];
    assert_eq!(keys, want, "a file name must not inject top-level keys");
}

#[test]
fn c18_fp_plain_names_valid_json() {
    let t = tempfile::tempdir().unwrap();
    let o = scan(&[&write(t.path(), "a.pem", clean_pem())]);
    assert!(o.json.is_object());
    assert_eq!(o.json["verdict"], "clean");
}

// ── C19 / P06: counts and duplicate paths ───────────────────────────────

#[cfg(unix)]
#[test]
fn c19_duplicates_scanned_once() {
    let t = tempfile::tempdir().unwrap();
    let p = write(t.path(), "a/x.pem", target_pem());
    std::os::unix::fs::symlink(&p, t.path().join("a/y.pem")).unwrap();
    let o = scan(&[&p, &p, &t.path().join("a")]);
    assert_eq!(o.json["files_scanned"], 1, "{}", o.stdout);
    assert_eq!(action(&o).len(), 1);
    // fp: two distinct files are both counted.
    write(t.path(), "b/x.pem", clean_pem());
    write(t.path(), "b/y.pem", clean_pem());
    let o = scan(&[&t.path().join("b")]);
    assert_eq!(o.json["files_scanned"], 2);
}

// ── C20: large archive members are scanned, not discarded ────────────────

#[test]
fn c20_tp_entry_over_50mb_in_tar_gz() {
    let t = tempfile::tempdir().unwrap();
    let mut big = vec![b'\n'; 60 << 20];
    big.extend_from_slice(target_pem().as_bytes());
    let tgz = gzip(&tar_of(&[("big.pem", &big)]));
    let o = scan(&[&write(t.path(), "a.tar.gz", tgz)]);
    assert_found(&o);
    assert!(errors(&o).is_empty());
}

#[test]
fn c20_fp_large_clean_entry() {
    let t = tempfile::tempdir().unwrap();
    let mut big = vec![b'\n'; 60 << 20];
    big.extend_from_slice(clean_pem().as_bytes());
    let tgz = gzip(&tar_of(&[("big.pem", &big)]));
    assert_clean(&scan(&[&write(t.path(), "a.tar.gz", tgz)]));
}

// ── C21: ZIP with a prefix (executable JAR) ─────────────────────────────

#[test]
fn c21_tp_prefixed_jar() {
    let t = tempfile::tempdir().unwrap();
    let mut v = b"#!/bin/sh\nexec java -jar \"$0\" \"$@\"\n".to_vec();
    v.extend(zip_of(&[(
        "BOOT-INF/classes/ca.pem",
        target_pem().as_bytes(),
    )]));
    assert_found(&scan(&[&write(t.path(), "app.jar", v)]));
}

#[test]
fn c21_fp_prefixed_jar_clean() {
    let t = tempfile::tempdir().unwrap();
    let mut v = b"#!/bin/sh\nexec java -jar \"$0\"\n".to_vec();
    v.extend(zip_of(&[(
        "BOOT-INF/classes/ca.pem",
        clean_pem().as_bytes(),
    )]));
    assert_clean(&scan(&[&write(t.path(), "app.jar", v)]));
}

// ── C22: RPM payload (gzip-compressed cpio) ─────────────────────────────

#[test]
fn c22_tp_rpm_payload() {
    let t = tempfile::tempdir().unwrap();
    let rpm = rpm_of(&gzip(&cpio_of(&[(
        "./etc/pki/x.pem",
        target_pem().as_bytes(),
    )])));
    assert_found(&scan(&[&write(t.path(), "ca.rpm", rpm)]));
}

#[test]
fn c22_fp_rpm_clean() {
    let t = tempfile::tempdir().unwrap();
    let rpm = rpm_of(&gzip(&cpio_of(&[(
        "./etc/pki/x.pem",
        clean_pem().as_bytes(),
    )])));
    assert_clean(&scan(&[&write(t.path(), "ca.rpm", rpm)]));
}

// ── C23: Electron asar archives ─────────────────────────────────────────

fn asar(content: &[u8]) -> Vec<u8> {
    let json = format!(
        "{{\"files\":{{\"ca.pem\":{{\"size\":{},\"offset\":\"0\"}}}}}}",
        content.len()
    );
    let mut v = vec![4, 0, 0, 0];
    v.extend_from_slice(&((json.len() + 8) as u32).to_le_bytes());
    v.extend_from_slice(&((json.len() + 4) as u32).to_le_bytes());
    v.extend_from_slice(&(json.len() as u32).to_le_bytes());
    v.extend_from_slice(json.as_bytes());
    v.extend_from_slice(content);
    v
}

#[test]
fn c23_tp_asar() {
    let t = tempfile::tempdir().unwrap();
    let o = scan(&[&write(t.path(), "app.asar", asar(&der(TARGET)))]);
    assert_found(&o);
    assert_eq!(action(&o)[0]["source"], "Electron .asar");
}

#[test]
fn c23_fp_asar_clean() {
    let t = tempfile::tempdir().unwrap();
    assert_clean(&scan(&[&write(t.path(), "app.asar", asar(&clean_der()))]));
}

// ── C24: --cert / --fingerprint with certificates outside 200..8192 bytes ─

#[test]
fn c24_tp_large_cert_by_file_and_fingerprint() {
    let t = tempfile::tempdir().unwrap();
    let big = data("big_cert.pem");
    let big_der = decode_b64(
        &String::from_utf8(big.clone())
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with("---"))
            .collect::<String>(),
    );
    assert!(big_der.len() > 8192);
    let certfile = write(t.path(), "big.pem", &big);
    let mut bin = vec![7u8; 100];
    bin.extend_from_slice(&big_der);
    let b = write(t.path(), "blob.bin", &bin);
    let o = run_args(
        &[
            "-c",
            certfile.to_str().unwrap(),
            "--no-system",
            "--json",
            "-b",
            b.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(o.code, 1, "{}", o.stdout);
    let sha = action(&o)[0]["sha256"].as_str().unwrap().to_string();
    let o = run_args(
        &[
            "-f",
            &sha,
            "--no-system",
            "--json",
            "-b",
            b.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(o.code, 1);
}

#[test]
fn c24_fp_large_clean_blob() {
    let t = tempfile::tempdir().unwrap();
    let certfile = write(t.path(), "big.pem", data("big_cert.pem"));
    let b = write(t.path(), "blob.bin", clean_der());
    let o = run_args(
        &[
            "-c",
            certfile.to_str().unwrap(),
            "--no-system",
            "--json",
            "-b",
            b.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(o.code, 0, "{}", o.stdout);
}

// ── C25: ar with a zero-size member ──────────────────────────────────────

#[test]
fn c25_tp_member_after_empty_one() {
    let t = tempfile::tempdir().unwrap();
    let deb = ar_of(&[
        ("debian-binary", b"2.0\n"),
        ("empty", b""),
        ("data.tar", &tar_of(&[("ca.pem", target_pem().as_bytes())])),
    ]);
    assert_found(&scan(&[&write(t.path(), "x.deb", deb)]));
}

#[test]
fn c25_fp_member_after_empty_one_clean() {
    let t = tempfile::tempdir().unwrap();
    let deb = ar_of(&[
        ("empty", b""),
        ("data.tar", &tar_of(&[("ca.pem", clean_pem().as_bytes())])),
    ]);
    assert_clean(&scan(&[&write(t.path(), "x.deb", deb)]));
}

// ── C26: labels name the actual issuer; consistent type names ───────────

#[test]
fn c26_labels() {
    let t = tempfile::tempdir().unwrap();
    let text = format!(
        "{}{}",
        target_pem(),
        pem(&der("EM_DV_TLS_CA_G3B_AAA"), "CERTIFICATE")
    );
    let o = scan(&[&write(t.path(), "b.pem", text)]);
    let names: Vec<String> = action(&o)
        .iter()
        .map(|f| f["cert"].as_str().unwrap().to_string())
        .collect();
    assert!(
        names
            .iter()
            .any(|n| n == "EM DV TLS CA - G3B (issued by emSign Root TLS CA - G3)"),
        "{names:?}"
    );
    assert!(names
        .iter()
        .any(|n| n == "EM DV TLS CA - G3B (issued by AAA Certificate Services)"));
    assert!(!o.stdout.contains("(emSign Root)"));
    assert!(action(&o).iter().all(|f| f["type"] == "compromised"));
}

// ── C27: fingerprint text is a reference, not a compromise ──────────────

#[test]
fn c27_fingerprint_in_source_is_informational() {
    let t = tempfile::tempdir().unwrap();
    let colon: String = TARGET_SHA
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap().to_uppercase())
        .collect::<Vec<_>>()
        .join(":");
    let src = format!("const BLOCKED: [&str; 2] = [\"sha256:{TARGET_SHA}\", \"{colon}\"];\n");
    let o = scan(&[&write(t.path(), "blocklist.rs", src)]);
    assert_eq!(o.code, 0, "{}", o.stdout);
    let f = findings(&o);
    assert!(!f.is_empty() && f.iter().all(|x| x["type"] == "reference"));
    // fp: a different 64-hex string is not reported at all.
    let o = scan(&[&write(
        t.path(),
        "other.rs",
        format!("x = \"{}\"", "ab".repeat(32)),
    )]);
    assert!(findings(&o).is_empty());
}

// ── C28: no false reassurance for PKCS#7 ────────────────────────────────

#[test]
fn c28_no_pkcs7_reassurance_warning() {
    let t = tempfile::tempdir().unwrap();
    let o = scan(&[&write(t.path(), "c.p7b", data("clean.p7b"))]);
    assert!(!o.json["issues"]
        .to_string()
        .contains("no matching certificates inside"));
    let o = scan(&[&write(t.path(), "t.p7b", data("target.p7b"))]);
    assert_found(&o);
}

// ── C30: leaf certificates issued by a compromised CA ───────────────────

#[test]
fn c30_tp_leaf_issued_by_compromised() {
    let t = tempfile::tempdir().unwrap();
    let o = scan(&[&write(
        t.path(),
        "server.crt",
        data("leaf_issued_by_compromised.pem"),
    )]);
    assert_found(&o);
    let f = &action(&o)[0];
    assert_eq!(f["type"], "issued-by-compromised");
    assert_eq!(f["match"], "authority-key-id");
}

#[test]
fn c30_fp_leaf_issued_by_other_ca() {
    let t = tempfile::tempdir().unwrap();
    assert_clean(&scan(&[&write(
        t.path(),
        "server.crt",
        data("leaf_issued_by_testca.pem"),
    )]));
}

// ── Archive formats end to end (xz, zstd, nested zip) ───────────────────

#[test]
fn archives_tp_xz_zstd_nested() {
    let t = tempfile::tempdir().unwrap();
    let tar = tar_of(&[("etc/ssl/ca.pem", target_pem().as_bytes())]);
    let mut xz = Vec::new();
    lzma_rs::xz_compress(&mut std::io::BufReader::new(&tar[..]), &mut xz).unwrap();
    let zst =
        ruzstd::encoding::compress_to_vec(&tar[..], ruzstd::encoding::CompressionLevel::Fastest);
    let inner = zip_of(&[("lib/inner.jar", &zip_of(&[("ca.der", &der(TARGET))]))]);
    for (n, b) in [("a.tar.xz", xz), ("a.tar.zst", zst), ("outer.war", inner)] {
        let o = scan(&[&write(t.path(), n, b)]);
        assert_found(&o);
        assert!(has_sha(&o, TARGET_SHA), "{n}");
    }
}

#[test]
fn archives_fp_xz_zstd_nested_clean() {
    let t = tempfile::tempdir().unwrap();
    let tar = tar_of(&[("etc/ssl/ca.pem", clean_pem().as_bytes())]);
    let mut xz = Vec::new();
    lzma_rs::xz_compress(&mut std::io::BufReader::new(&tar[..]), &mut xz).unwrap();
    let zst =
        ruzstd::encoding::compress_to_vec(&tar[..], ruzstd::encoding::CompressionLevel::Fastest);
    let inner = zip_of(&[("lib/inner.jar", &zip_of(&[("ca.der", &clean_der())]))]);
    let a = write(t.path(), "a.tar.xz", xz);
    let b = write(t.path(), "a.tar.zst", zst);
    let c = write(t.path(), "outer.war", inner);
    assert_clean(&scan(&[&a, &b, &c]));
}

// ── N09: bzip2 (.bz2, .bz, .tbz, .tbz2, multi-stream, ZIP method 12) ────

fn bzip2_of(bytes: &[u8]) -> Vec<u8> {
    let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
    e.write_all(bytes).unwrap();
    e.finish().unwrap()
}
fn zip_bzip2_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Bzip2);
    for (n, b) in entries {
        w.start_file(*n, opts).unwrap();
        w.write_all(b).unwrap();
    }
    w.finish().unwrap().into_inner()
}
/// The same tar under every bzip2 spelling, a two-stream file whose second
/// stream holds `pem` (pbzip2 / `cat a.bz2 b.bz2`), and a ZIP with bzip2 entries.
fn bzip2_variants(pem: &str) -> Vec<(&'static str, Vec<u8>)> {
    let tar = tar_of(&[("etc/ssl/ca.pem", pem.as_bytes())]);
    let mut multi = bzip2_of(clean_pem().as_bytes());
    multi.extend(bzip2_of(pem.as_bytes()));
    vec![
        ("a.tar.bz2", bzip2_of(&tar)),
        ("a.tbz2", bzip2_of(&tar)),
        ("a.tbz", bzip2_of(&tar)),
        ("ca.pem.bz", bzip2_of(pem.as_bytes())),
        ("multi.pem.bz2", multi),
        ("a.zip", zip_bzip2_of(&[("ca.pem", pem.as_bytes())])),
    ]
}

#[test]
fn n09_tp_bzip2_every_form() {
    let t = tempfile::tempdir().unwrap();
    for (n, b) in bzip2_variants(&target_pem()) {
        let o = scan(&[&write(t.path(), n, b)]);
        assert_found(&o);
        assert!(has_sha(&o, TARGET_SHA), "{n}");
        assert!(errors(&o).is_empty(), "{n}: {:?}", errors(&o));
    }
}

#[test]
fn n09_fp_bzip2_every_form_clean() {
    let t = tempfile::tempdir().unwrap();
    let paths: Vec<PathBuf> = bzip2_variants(&clean_pem())
        .into_iter()
        .map(|(n, b)| write(t.path(), n, b))
        .collect();
    let refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();
    assert_clean(&scan(&refs));
}

#[test]
fn n09_truncated_bzip2_is_incomplete_not_clean() {
    let t = tempfile::tempdir().unwrap();
    let mut b = bzip2_of(&tar_of(&[("etc/ssl/ca.pem", clean_pem().as_bytes())]));
    b.truncate(b.len() / 2);
    let o = scan(&[&write(t.path(), "cut.tar.bz2", b)]);
    assert_eq!(o.code, 3, "stdout: {}", o.stdout);
    assert!(errors(&o)
        .iter()
        .any(|e| e["message"].as_str().unwrap_or("").contains("bzip2")));
}

// ── P04: memory-mapped large files ───────────────────────────────────────

#[test]
fn p04_large_file_mmap_path() {
    let t = tempfile::tempdir().unwrap();
    let mut v = vec![0u8; 3 << 20];
    v.extend_from_slice(&der(TARGET));
    assert_found(&scan(&[&write(t.path(), "big.bin", &v)]));
    let mut c = vec![0u8; 3 << 20];
    c.extend_from_slice(&clean_der());
    assert_clean(&scan(&[&write(t.path(), "big2.bin", &c)]));
}

// ── P07: parallel scanning gives the same answer ─────────────────────────

#[test]
fn p07_parallel_matches_serial() {
    let t = tempfile::tempdir().unwrap();
    for i in 0..24 {
        let body = if i % 5 == 0 {
            target_pem()
        } else {
            clean_pem()
        };
        write(t.path(), &format!("d/{i:02}.pem"), body);
    }
    let d = t.path().join("d");
    let ds = d.to_str().unwrap();
    let base = ["--profile", "emudhra", "--no-system", "--json", "-p", ds];
    let serial = run_args(&[&base[..], &["--jobs", "1"]].concat(), &[]);
    let par = run_args(&[&base[..], &["--jobs", "4"]].concat(), &[]);
    assert_eq!(serial.json["findings"], par.json["findings"]);
    assert_eq!(action(&serial).len(), 5);
}

// ── P11: nesting warning emitted once, not per entry ────────────────────

#[test]
fn p11_single_nesting_warning() {
    let t = tempfile::tempdir().unwrap();
    let files: Vec<(String, Vec<u8>)> = (0..50)
        .map(|i| (format!("f{i}.txt"), b"x".to_vec()))
        .collect();
    let refs: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(n, b)| (n.as_str(), b.as_slice()))
        .collect();
    let deep = zip_of(&[("l1.zip", &zip_of(&[("l2.zip", &zip_of(&refs))]))]);
    let o = scan(&[&write(t.path(), "deep.zip", deep)]);
    let n = o.json["issues"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|i| i["message"].as_str().unwrap().contains("nested"))
        .count();
    assert_eq!(n, 1);
    let o = scan(&[&write(t.path(), "flat.zip", zip_of(&refs))]);
    assert!(o.json["issues"].as_array().unwrap().is_empty());
}

// ── Text output sanity (human report) ───────────────────────────────────

#[test]
fn text_output_sections() {
    let t = tempfile::tempdir().unwrap();
    let p = write(t.path(), "b.pem", target_pem());
    let o = run_args(
        &[
            "--profile",
            "emudhra",
            "--no-system",
            "-q",
            "-p",
            p.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(o.code, 1);
    assert!(o.stdout.starts_with("Result: FOUND"));
    assert!(o.stdout.contains("COMPROMISED CA CERTIFICATES"));
    let c = write(t.path(), "c.pem", clean_pem());
    let o = run_args(
        &[
            "--profile",
            "emudhra",
            "--no-system",
            "-q",
            "-p",
            c.to_str().unwrap(),
        ],
        &[],
    );
    assert!(o.stdout.starts_with("Result: CLEAN"), "{}", o.stdout);
}

// ── N04: bundle fingerprint comments do not duplicate certificate matches ─

#[test]
fn n04_fingerprint_comment_next_to_cert_not_duplicated() {
    let t = tempfile::tempdir().unwrap();
    let colon: String = TARGET_SHA
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap().to_uppercase())
        .collect::<Vec<_>>()
        .join(":");
    let bundle = format!(
        "# Label: \"EM DV\"\n# SHA256 Fingerprint: {colon}\n{}",
        target_pem()
    );
    let o = scan(&[&write(t.path(), "cacert.pem", bundle)]);
    assert_found(&o);
    assert_eq!(findings(&o).len(), 1, "{:#?}", findings(&o));
    assert_eq!(findings(&o)[0]["match"], "certificate");
}

// ── N05: keys and certificates compiled in as source literals ───────────

fn esc(b: &[u8]) -> String {
    b.iter().map(|x| format!("\\x{x:02x}")).collect()
}
/// SubjectPublicKeyInfo contents without the outer SEQUENCE header, as webpki-roots stores it.
fn spki_contents(der: &[u8]) -> Vec<u8> {
    let (_, c) = x509_parser::parse_x509_certificate(der).unwrap();
    let raw = c.public_key().raw;
    let hdr = if raw[1] < 0x80 {
        2
    } else {
        2 + (raw[1] & 0x7f) as usize
    };
    raw[hdr..].to_vec()
}
fn pem_lines(der: &[u8]) -> Vec<String> {
    pem(der, "CERTIFICATE")
        .lines()
        .filter(|l| !l.starts_with("-----"))
        .map(String::from)
        .collect()
}

#[test]
fn n05_tp_certificate_as_rust_byte_string() {
    let t = tempfile::tempdir().unwrap();
    let src = format!(
        "pub const ROOTS: &[CertificateDer<'static>] = &[\n  // \"emSign ECC Root CA - G3\"\n  CertificateDer::from_slice(b\"{}\"),\n];\n",
        esc(&der("emSign_ECC_Root_G3"))
    );
    let o = scan(&[&write(t.path(), "lib.rs", src)]);
    assert_found(&o);
    assert!(action(&o)
        .iter()
        .any(|f| f["type"] == "distrusted-root" && f["match"] == "certificate"));
}

#[test]
fn n05_tp_trust_anchor_public_key_literal() {
    let t = tempfile::tempdir().unwrap();
    // webpki-roots style: printable bytes appear literally, the rest as escapes.
    let spki: String = spki_contents(&der("emSign_ECC_Root_G3"))
        .iter()
        .map(|&b| match b {
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z' => (b as char).to_string(),
            b'\t' => "\\t".into(),
            b'\r' => "\\r".into(),
            _ => format!("\\x{b:02x}"),
        })
        .collect();
    let src = format!(
        "TrustAnchor {{\n    subject: Der::from_slice(b\"1\\x0b0\\t\"),\n    subject_public_key_info: Der::from_slice(b\"{spki}\"),\n    name_constraints: None\n}},\n"
    );
    let o = scan(&[&write(t.path(), "lib.rs", src)]);
    assert_found(&o);
    assert!(action(&o)
        .iter()
        .any(|f| f["type"] == "distrusted-root" && f["match"] == "public-key"));
}

#[test]
fn n05_tp_numeric_arrays_c_and_java() {
    let t = tempfile::tempdir().unwrap();
    let d = der("emSign_ECC_Root_G3");
    let c = d
        .iter()
        .map(|x| format!("0x{x:02x}"))
        .collect::<Vec<_>>()
        .join(", ");
    let java = d
        .iter()
        .map(|&x| format!("(byte) {}", x as i8))
        .collect::<Vec<_>>()
        .join(", ");
    let a = write(
        t.path(),
        "roots.c",
        format!("static const unsigned char g3[] = {{ {c} }};\n"),
    );
    let b = write(
        t.path(),
        "Roots.java",
        format!("static final byte[] G3 = {{ {java} }};\n"),
    );
    for p in [a, b] {
        assert_found(&scan(&[&p]));
    }
}

#[test]
fn n05_tp_pem_in_comments_and_string_concatenation() {
    let t = tempfile::tempdir().unwrap();
    let lines = pem_lines(&der("emSign_ECC_Root_G3"));
    let comment = format!(
        "/*\n * -----BEGIN CERTIFICATE-----\n{}\n * -----END CERTIFICATE-----\n */\n",
        lines
            .iter()
            .map(|l| format!(" * {l}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
    let js = format!(
        "module.exports = \"-----BEGIN CERTIFICATE-----\\n\" +\n{}\n  \"-----END CERTIFICATE-----\\n\";\n",
        lines.iter().map(|l| format!("  \"{l}\\n\" +")).collect::<Vec<_>>().join("\n")
    );
    for (name, body) in [("lib.rs", comment), ("roots.pem", js)] {
        let o = scan(&[&write(t.path(), name, body)]);
        assert_found(&o);
    }
}

#[test]
fn n05_fp_baseline_root_literal_is_informational() {
    let t = tempfile::tempdir().unwrap();
    let src = format!("const G1: &[u8] = b\"{}\";\n", esc(&der("emSign_Root_G1")));
    let o = scan(&[&write(t.path(), "lib.rs", src)]);
    assert_eq!(o.code, 0, "{}", o.stdout);
    assert!(action(&o).is_empty());
    assert!(findings(&o).iter().any(|f| f["type"] == "info-root"));
}

#[test]
fn n05_fp_unrelated_certificate_and_name_only() {
    let t = tempfile::tempdir().unwrap();
    let d = clean_der();
    let lit = write(
        t.path(),
        "lib.rs",
        format!("const C: &[u8] = b\"{}\";\n", esc(&d)),
    );
    let arr = write(
        t.path(),
        "c.c",
        format!(
            "unsigned char c[] = {{ {} }};\n",
            d.iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(",")
        ),
    );
    for p in [lit, arr] {
        let o = scan(&[&p]);
        assert_eq!(o.code, 0, "{}", o.stdout);
        assert!(findings(&o).is_empty(), "{}", o.stdout);
    }
    let o = scan(&[&write(t.path(), "names.rs", "// emSign ECC Root CA - G3\n")]);
    assert!(action(&o).is_empty());
}

// ── N06: Chromium SPKI-hash blocklist (patched Electron) ─────────────────

const COMPROMISED: [&str; 8] = [
    "EM_EV_TLS_CA_G3B_emSign",
    "EM_OV_TLS_CA_G3B_emSign",
    "EM_DV_TLS_CA_G3B_emSign",
    "EM_EV_TLS_CA_G3C_emSign",
    "EM_OV_TLS_CA_G3C_emSign",
    "EM_DV_TLS_CA_G3C_emSign",
    "EM_OV_CS_CA_G3B_emSign",
    "EM_OV_CS_CA_G3C_emSign",
];

fn spki_sha256(der: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let (_, c) = x509_parser::parse_x509_certificate(der).unwrap();
    sha2::Sha256::digest(c.public_key().raw).to_vec()
}

/// An Electron-like binary: filler, the G3 and AAA roots as DER, and `n` blocklist hashes.
fn electron_like(n: usize) -> Vec<u8> {
    let mut b = vec![0x90u8; 4096];
    b.extend(der("emSign_ECC_Root_G3"));
    b.extend(vec![0u8; 512]);
    b.extend(der("Sectigo_AAA_Certificate_Services"));
    b.extend(vec![0u8; 512]);
    for name in COMPROMISED.iter().take(n) {
        b.extend(spki_sha256(&der(name)));
    }
    b.extend(vec![0x90u8; 4096]);
    b
}

#[test]
fn n06_tp_complete_key_blocklist_mitigates_roots() {
    let t = tempfile::tempdir().unwrap();
    let o = scan(&[&write(t.path(), "electron", electron_like(8))]);
    assert_eq!(o.code, 0, "{}", o.stdout);
    let f = findings(&o);
    let roots: Vec<_> = f
        .iter()
        .filter(|x| x["type"] == "distrusted-root" || x["type"] == "cross-sign-root")
        .collect();
    assert_eq!(roots.len(), 2, "{}", o.stdout);
    assert!(roots
        .iter()
        .all(|x| x["context"] == "key-blocklist" && x["action_required"] == false));
    assert!(f
        .iter()
        .any(|x| x["match"] == "blocklist" && x["cert"].as_str().unwrap().contains("all 8")));
}

#[test]
fn n06_fp_partial_blocklist_or_none_still_needs_action() {
    let t = tempfile::tempdir().unwrap();
    for n in [0, 7] {
        let o = scan(&[&write(t.path(), &format!("electron{n}"), electron_like(n))]);
        assert_found(&o);
        assert!(action(&o)
            .iter()
            .any(|x| x["type"] == "distrusted-root" && x["context"] == "trust"));
        let partial = findings(&o)
            .iter()
            .any(|x| x["match"] == "blocklist" && x["cert"].as_str().unwrap().contains("7 of 8"));
        assert_eq!(partial, n == 7, "{}", o.stdout);
    }
}

#[test]
fn n06_fp_blocklist_in_another_file_does_not_mitigate() {
    let t = tempfile::tempdir().unwrap();
    let roots = write(t.path(), "bundle.bin", electron_like(0));
    let mut hashes = Vec::new();
    for name in COMPROMISED {
        hashes.extend(spki_sha256(&der(name)));
    }
    let list = write(t.path(), "blocklist.bin", hashes);
    let o = scan(&[&roots, &list]);
    assert_found(&o);
}

// ── N07: opaque installers / filesystem images must not scan clean ──────

fn appimage_like() -> Vec<u8> {
    let mut b = b"\x7fELF".to_vec();
    b.resize(8192, 0x11);
    let mut sb = vec![0u8; 96];
    sb[..4].copy_from_slice(b"hsqs");
    sb[12..16].copy_from_slice(&131072u32.to_le_bytes());
    sb[20..22].copy_from_slice(&6u16.to_le_bytes());
    sb[22..24].copy_from_slice(&17u16.to_le_bytes());
    sb[28..30].copy_from_slice(&4u16.to_le_bytes());
    b.extend(sb);
    b.extend((0..65536u32).map(|i| (i.wrapping_mul(2654435761) >> 24) as u8));
    b
}
fn nsis_like() -> Vec<u8> {
    let mut b = b"MZ".to_vec();
    b.resize(1024, 0x22);
    b.extend_from_slice(&[0, 0, 0, 0]);
    b.extend_from_slice(b"\xef\xbe\xad\xdeNullsoftInst");
    b.extend((0..65536u32).map(|i| (i.wrapping_mul(2246822519) >> 24) as u8));
    b
}

#[test]
fn n07_tp_appimage_and_nsis_are_incomplete_not_clean() {
    let t = tempfile::tempdir().unwrap();
    for (name, body, word) in [
        ("App.AppImage", appimage_like(), "SquashFS"),
        ("setup.exe", nsis_like(), "NSIS"),
    ] {
        let o = scan(&[&write(t.path(), name, body)]);
        assert_eq!(o.code, 3, "{name}: {}", o.stdout);
        assert!(
            errors(&o)
                .iter()
                .any(|e| e["message"].as_str().unwrap().contains(word)),
            "{}",
            o.stdout
        );
    }
}

#[test]
fn n07_fp_raw_hit_inside_opaque_file_is_found_with_warning() {
    let t = tempfile::tempdir().unwrap();
    let mut body = appimage_like();
    body.extend(der(TARGET));
    let o = scan(&[&write(t.path(), "App.AppImage", body)]);
    assert_found(&o);
    assert!(errors(&o).is_empty(), "{}", o.stdout);
}

#[test]
fn n07_fp_plain_executables_unaffected() {
    let t = tempfile::tempdir().unwrap();
    let mut elf = b"\x7fELF".to_vec();
    elf.resize(70000, 0x33);
    let mut pe = b"MZ".to_vec();
    pe.resize(70000, 0x44);
    // A tool that only mentions the signatures (like 7-Zip) is not an installer.
    pe.extend_from_slice(b"\xef\xbe\xad\xdeNullsoftInst Inno Setup Setup Data (%s)");
    for (n, b) in [("tool", elf), ("tool.exe", pe)] {
        let o = scan(&[&write(t.path(), n, b)]);
        assert_eq!(o.code, 0, "{n}: {}", o.stdout);
    }
}

/// A Rust-binary-like file: webpki-roots-style G3 trust anchor key plus
/// rustls-webpki-style bare SPKIs of `n` compromised keys.
fn rustls_like(n: usize) -> Vec<u8> {
    let mut b = vec![0x55u8; 4096];
    b.extend(spki_contents(&der("emSign_ECC_Root_G3")));
    b.extend(vec![0u8; 256]);
    for name in COMPROMISED.iter().take(n) {
        let d = der(name);
        let (_, c) = x509_parser::parse_x509_certificate(&d).unwrap();
        b.extend(c.public_key().raw);
        b.extend(vec![0u8; 16]);
    }
    b.extend(vec![0x55u8; 4096]);
    b
}

#[test]
fn n08_tp_bare_spki_distrust_list_mitigates() {
    let t = tempfile::tempdir().unwrap();
    let o = scan(&[&write(t.path(), "libsignal.node", rustls_like(8))]);
    assert_eq!(o.code, 0, "{}", o.stdout);
    let f = findings(&o);
    assert!(
        f.iter().filter(|x| x["type"] == "compromised").count() >= 8,
        "{}",
        o.stdout
    );
    assert!(f
        .iter()
        .filter(|x| x["type"] == "compromised" || x["type"] == "distrusted-root")
        .all(|x| x["context"] == "key-blocklist" && x["action_required"] == false));
    assert!(f
        .iter()
        .any(|x| x["match"] == "blocklist" && x["cert"].as_str().unwrap().contains("bare-SPKI")));
}

#[test]
fn n08_fp_partial_list_or_full_certificates_still_need_action() {
    let t = tempfile::tempdir().unwrap();
    assert_found(&scan(&[&write(t.path(), "partial.node", rustls_like(7))]));
    // The same keys inside the compromised certificates themselves are not a distrust list.
    let mut certs = Vec::new();
    for name in COMPROMISED {
        certs.extend(der(name));
        certs.extend(vec![0u8; 64]);
    }
    let o = scan(&[&write(t.path(), "intermediates.bin", certs)]);
    assert_found(&o);
    assert!(
        !findings(&o).iter().any(|x| x["match"] == "blocklist"),
        "{}",
        o.stdout
    );
}

#[test]
fn n10_tp_inner_spki_distrust_list_mitigates() {
    // Deno and pixi builds keep the keys as SPKI contents without the outer SEQUENCE header.
    let t = tempfile::tempdir().unwrap();
    let mut b = vec![0x66u8; 4096];
    b.extend(der("emSign_ECC_Root_G3"));
    for name in COMPROMISED {
        b.extend(spki_contents(&der(name)));
        b.extend(vec![0u8; 8]);
    }
    let o = scan(&[&write(t.path(), "deno", b)]);
    assert_eq!(o.code, 0, "{}", o.stdout);
    assert!(findings(&o).iter().any(|x| x["match"] == "blocklist"));
}

#[test]
fn n11_tp_hex_text_spki_hashes_mitigate() {
    // Go 1.26.10+ keeps the hashes as hex strings in crypto/x509's distrustedSPKIHashes map.
    let t = tempfile::tempdir().unwrap();
    let mut b = vec![0x77u8; 2048];
    b.extend(der("emSign_ECC_Root_G3"));
    for name in COMPROMISED {
        let h: String = spki_sha256(&der(name))
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect();
        b.extend(h.into_bytes());
    }
    let o = scan(&[&write(t.path(), "gobinary", b)]);
    assert_eq!(o.code, 0, "{}", o.stdout);
    assert!(findings(&o).iter().any(|x| x["match"] == "blocklist"));
}

// ── N12: trust model per item (bundled / OS store / both, pinning, blocklist) ──

fn item(o: &Out) -> Value {
    o.json["items"]
        .as_array()
        .and_then(|a| a.first())
        .cloned()
        .unwrap_or(Value::Null)
}

#[test]
fn n12_tp_bundle_os_store_both_pinning_blocklist() {
    let t = tempfile::tempdir().unwrap();
    let roots: String = ["emSign_Root_G1", "emSign_Root_C1", "emSign_ECC_Root_C3"]
        .iter()
        .map(|n| pem(&der(n), "CERTIFICATE"))
        .collect();
    let o = scan(&[&write(t.path(), "cacert.pem", &roots)]);
    let i = item(&o);
    assert_eq!(i["model"], "bundled", "{}", o.stdout);
    assert_eq!(i["bundled_roots"], 3);

    let mut both = roots.clone().into_bytes();
    both.extend_from_slice(b"\0/etc/ssl/certs/ca-certificates.crt\0SecTrustEvaluateWithError\0");
    assert_eq!(
        item(&scan(&[&write(t.path(), "both.bin", both)]))["model"],
        "both"
    );

    let os = scan(&[&write(
        t.path(),
        "client",
        b"\x7fELF....SSL_CTX_set_default_verify_paths....",
    )]);
    assert_eq!(item(&os)["model"], "os-store");

    let pin = format!("okhttp3.CertificatePinner sha256/{}=", "Q".repeat(43));
    let p = item(&scan(&[&write(t.path(), "pinned.dex", pin)]));
    assert_eq!(p["pinning"].as_array().unwrap().len(), 2, "{p}");

    let b = item(&scan(&[&write(t.path(), "electron", electron_like(8))]));
    assert!(
        b["blocklist"]
            .as_array()
            .unwrap()
            .iter()
            .any(|x| x.as_str().unwrap().contains("all 8")),
        "{b}"
    );
}

#[test]
fn fp_n12_single_cert_or_plain_file_has_no_trust_item() {
    let t = tempfile::tempdir().unwrap();
    // One leaf certificate, and ordinary text, are not trust stores or verifiers.
    let o = scan(&[&write(t.path(), "leaf.pem", clean_pem())]);
    assert!(
        o.json["items"].as_array().unwrap().is_empty(),
        "{}",
        o.stdout
    );
    let o = scan(&[&write(
        t.path(),
        "notes.txt",
        "see /etc/ssl/ for certs; sha256/short=",
    )]);
    assert!(
        o.json["items"].as_array().unwrap().is_empty(),
        "{}",
        o.stdout
    );
}

// ── N13: OneCRL issuer+serial lists (Firefox) mitigate NSS roots of the same app ──

const TLS_COMPROMISED: [&str; 6] = [
    "EM_EV_TLS_CA_G3B_emSign",
    "EM_OV_TLS_CA_G3B_emSign",
    "EM_DV_TLS_CA_G3B_emSign",
    "EM_EV_TLS_CA_G3C_emSign",
    "EM_OV_TLS_CA_G3C_emSign",
    "EM_DV_TLS_CA_G3C_emSign",
];

fn onecrl_json(n: usize) -> String {
    let recs: Vec<String> = TLS_COMPROMISED
        .iter()
        .take(n)
        .map(|name| {
            let d = der(name);
            let (_, c) = x509_parser::parse_x509_certificate(&d).unwrap();
            format!(
                r#"{{"enabled":true,"issuerName":"{}","serialNumber":"{}"}}"#,
                b64(c.issuer().as_raw()),
                b64(c.raw_serial())
            )
        })
        .collect();
    format!(r#"{{"data":[{}]}}"#, recs.join(","))
}

/// libxul.so with the G3 and AAA roots, plus omni.ja carrying a OneCRL dump.
fn firefox_entries(onecrl: &str) -> Vec<(String, Vec<u8>)> {
    let mut xul = vec![0x11u8; 4096];
    xul.extend(der("emSign_ECC_Root_G3"));
    xul.extend(der("Sectigo_AAA_Certificate_Services"));
    let omni = zip_of(&[(
        "defaults/settings/security-state/onecrl.json",
        onecrl.as_bytes(),
    )]);
    vec![
        ("firefox/libxul.so".into(), xul),
        ("firefox/browser/omni.ja".into(), omni),
    ]
}

#[test]
fn n13_tp_onecrl_mitigates_firefox_tarball_and_install_dir() {
    let t = tempfile::tempdir().unwrap();
    let e = firefox_entries(&onecrl_json(6));
    let refs: Vec<(&str, &[u8])> = e.iter().map(|(n, b)| (n.as_str(), b.as_slice())).collect();
    let o = scan(&[&write(t.path(), "firefox.tar", tar_of(&refs))]);
    assert_eq!(o.code, 0, "{}", o.stdout);
    assert!(findings(&o)
        .iter()
        .any(|x| x["match"] == "blocklist" && x["cert"].as_str().unwrap().contains("6 TLS keys")));
    // Same layout installed on disk (separate files).
    for (n, b) in &e {
        write(&t.path().join("install"), n, b);
    }
    let o = scan(&[&t.path().join("install")]);
    assert_eq!(o.code, 0, "{}", o.stdout);
}

#[test]
fn n13_fp_incomplete_onecrl_or_other_app_does_not_mitigate() {
    let t = tempfile::tempdir().unwrap();
    let e = firefox_entries(&onecrl_json(5));
    let refs: Vec<(&str, &[u8])> = e.iter().map(|(n, b)| (n.as_str(), b.as_slice())).collect();
    assert_found(&scan(&[&write(t.path(), "partial.tar", tar_of(&refs))]));
    // A complete list in a neighbouring app's folder does not cover this app's roots.
    let full = firefox_entries(&onecrl_json(6));
    write(&t.path().join("apps"), "a/libxul.so", &full[0].1);
    write(&t.path().join("apps"), "b/browser/omni.ja", &full[1].1);
    assert_found(&scan(&[&t.path().join("apps")]));
}

// ── N14: dependency analysis of project folders (built in from deps/) ───

fn scan_with(paths: &[&Path], extra: &[&str]) -> Out {
    let mut args = vec![
        "--profile",
        "emudhra",
        "--no-system",
        "--json",
        "--jobs",
        "1",
    ];
    args.extend_from_slice(extra);
    let strs: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    for s in &strs {
        args.push("-p");
        args.push(s);
    }
    run_args(&args, &[])
}
fn deps_of(o: &Out) -> Vec<String> {
    let mut v: Vec<String> = o.json["dependencies"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|d| {
            format!(
                "{} {}",
                d["package"].as_str().unwrap(),
                d["version"].as_str().unwrap()
            )
        })
        .collect();
    v.sort();
    v
}
const TWO_WEBPKI_LOCK: &str = "version = 3\n[[package]]\nname = \"api\"\nversion = \"0.1.0\"\ndependencies = [\"webpki-roots 0.25.4\"]\n\n[[package]]\nname = \"worker\"\nversion = \"0.1.0\"\ndependencies = [\"webpki-roots 0.26.3\"]\n\n[[package]]\nname = \"webpki-roots\"\nversion = \"0.25.4\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"webpki-roots\"\nversion = \"0.26.3\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";

#[test]
fn n14_tp_offline_lists_bundling_dependencies_without_changing_verdict() {
    let t = tempfile::tempdir().unwrap();
    write(t.path(), "Cargo.lock", TWO_WEBPKI_LOCK);
    let o = scan_with(&[t.path()], &[]);
    assert_eq!(
        deps_of(&o),
        vec!["webpki-roots 0.25.4", "webpki-roots 0.26.3"],
        "{}",
        o.stdout
    );
    // Offline the bundle contents are unknown, so nothing needs action yet.
    assert_eq!(o.code, 0, "{}", o.stdout);
    assert!(action(&o).is_empty());
}

#[test]
fn n14_fp_no_lockfile_or_no_deps_flag_means_no_analysis() {
    let t = tempfile::tempdir().unwrap();
    write(t.path(), "notes.txt", "nothing here");
    assert!(deps_of(&scan_with(&[t.path()], &[])).is_empty());
    write(t.path(), "Cargo.lock", TWO_WEBPKI_LOCK);
    assert!(deps_of(&scan_with(&[t.path()], &["--no-deps"])).is_empty());
}

fn online(files: &[(&str, &str)], cache: &Path) -> Out {
    let t = tempfile::tempdir().unwrap();
    for (n, c) in files {
        write(t.path(), n, c);
    }
    let c = cache.to_string_lossy().into_owned();
    scan_with(&[t.path()], &["--deps-online", "--deps-cache-dir", &c])
}
fn dep_affected(o: &Out, pkg: &str) -> Option<bool> {
    o.json["dependencies"]
        .as_array()?
        .iter()
        .find(|d| d["package"] == pkg)
        .and_then(|d| d["bundle"]["affected"].as_bool())
}

#[test]
#[ignore = "network: uv and PyPI"]
fn n14_tp_fp_online_certifi_and_botocore() {
    let cache = tempfile::tempdir().unwrap();
    let o = online(
        &[("requirements.txt", "certifi==2024.8.30\n")],
        cache.path(),
    );
    assert_found(&o);
    assert!(action(&o).iter().any(|f| f["type"] == "dependency-bundle"));
    let o = online(
        &[("requirements.txt", "certifi==2026.10.23\n")],
        cache.path(),
    );
    assert_eq!(dep_affected(&o, "certifi"), Some(false), "{}", o.stdout);
    assert!(action(&o).is_empty(), "{}", o.stdout);
    for (v, want) in [("1.43.116", true), ("1.43.117", false)] {
        let o = online(
            &[("requirements.txt", &format!("botocore=={v}\n"))],
            cache.path(),
        );
        assert_eq!(
            dep_affected(&o, "botocore"),
            Some(want),
            "{v}: {}",
            o.stdout
        );
    }
}

#[test]
#[ignore = "network: crates.io"]
fn n14_tp_online_webpki_roots_versions() {
    let cache = tempfile::tempdir().unwrap();
    let o = online(&[("Cargo.lock", TWO_WEBPKI_LOCK)], cache.path());
    assert_eq!(dep_affected(&o, "webpki-roots"), Some(true), "{}", o.stdout);
    let fixed = TWO_WEBPKI_LOCK
        .replace("0.25.4", "1.0.11")
        .replace("0.26.3", "1.0.11");
    let o = online(&[("Cargo.lock", &fixed)], cache.path());
    assert_eq!(
        dep_affected(&o, "webpki-roots"),
        Some(false),
        "{}",
        o.stdout
    );
}

const GEMS: &str =
    "GEM\n  remote: https://rubygems.org/\n  specs:\n    excon (EXCON)\n\nDEPENDENCIES\n  excon\n";
const COMPOSER: &str = r#"{"packages":[{"name":"composer/ca-bundle","version":"BUNDLE"}]}"#;
const MIX: &str =
    "%{\n  \"castore\": {:hex, :castore, \"CASTORE\", \"a\", [:mix], [], \"hexpm\", \"b\"},\n}\n";
const CPAN: &str =
    "DISTRIBUTIONS\n  Mozilla-CA-MOZCA\n    pathname: L/LW/LWP/Mozilla-CA-MOZCA.tar.gz\n";

#[test]
#[ignore = "network: RubyGems, Packagist, Hex, MetaCPAN"]
fn n14_tp_fp_online_ruby_php_hex_perl() {
    let cache = tempfile::tempdir().unwrap();
    for (excon, bundle, castore, mozca, want) in [
        ("1.7.3", "1.4.15", "1.0.21", "20260813", true),
        ("1.8.0", "1.4.16", "1.0.22", "20261020", false),
    ] {
        let o = online(
            &[
                ("Gemfile.lock", &GEMS.replace("EXCON", excon)),
                ("composer.lock", &COMPOSER.replace("BUNDLE", bundle)),
                ("mix.lock", &MIX.replace("CASTORE", castore)),
                ("cpanfile.snapshot", &CPAN.replace("MOZCA", mozca)),
            ],
            cache.path(),
        );
        for pkg in ["excon", "composer/ca-bundle", "castore", "Mozilla-CA"] {
            assert_eq!(
                dep_affected(&o, pkg),
                Some(want),
                "{pkg} ({want}): {}",
                o.stdout
            );
        }
    }
}

// ── N15: LZMA, XZ and PPMd ZIP entries (method 14, 95, 98) ──────────────

fn zip_with(method: zip::CompressionMethod, entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default().compression_method(method);
    for (n, b) in entries {
        w.start_file(*n, opts).unwrap();
        w.write_all(b).unwrap();
    }
    w.finish().unwrap().into_inner()
}

/// The zip crate cannot write LZMA (method 14); those come from `tests/data/gen.sh`.
const N15_WRITABLE: [zip::CompressionMethod; 2] =
    [zip::CompressionMethod::Xz, zip::CompressionMethod::Ppmd];

#[test]
fn n15_tp_lzma_xz_ppmd_zip_entries() {
    let t = tempfile::tempdir().unwrap();
    let mut zips = vec![("lzma.zip".to_string(), data("lzma_target.zip"))];
    for m in N15_WRITABLE {
        let z = zip_with(m, &[("certs/ca.pem", target_pem().as_bytes())]);
        zips.push((format!("{m:?}.zip"), z));
    }
    for (name, z) in zips {
        let o = scan(&[&write(t.path(), &name, z)]);
        assert_found(&o);
        assert!(has_sha(&o, TARGET_SHA), "{name}: {}", o.stdout);
        assert!(errors(&o).is_empty(), "{name}: {:?}", errors(&o));
    }
}

#[test]
fn n15_fp_lzma_xz_ppmd_zip_entries_clean() {
    let t = tempfile::tempdir().unwrap();
    let mut zips = vec![("lzma.zip".to_string(), data("lzma_clean.zip"))];
    for m in N15_WRITABLE {
        let z = zip_with(m, &[("certs/ca.pem", clean_pem().as_bytes())]);
        zips.push((format!("{m:?}.zip"), z));
    }
    for (name, z) in zips {
        assert_clean(&scan(&[&write(t.path(), &name, z)]));
    }
}

// ── N16: gzip followed by non-gzip data; gzip magic without a gzip header ──

#[test]
fn n16_tp_data_after_gzip_and_fake_gzip_magic_are_scanned() {
    let t = tempfile::tempdir().unwrap();
    // Save-game layout: a gzip member, then the application's own records.
    let mut a = gzip(clean_pem().as_bytes());
    a.extend_from_slice(b"\x00\x01RECORDS");
    a.extend_from_slice(target_pem().as_bytes());
    assert_found(&scan(&[&write(t.path(), "save.sav", a)]));
    // Starts with the two gzip magic bytes but CM is not deflate: not gzip.
    let mut b = vec![0x1f, 0x8b, 0x00, 0x00];
    b.extend_from_slice(target_pem().as_bytes());
    assert_found(&scan(&[&write(t.path(), "blob.bin", b)]));
    // Multi-member gzip still reads every member (C12).
    let mut c = gzip(clean_pem().as_bytes());
    c.extend(gzip(target_pem().as_bytes()));
    assert_found(&scan(&[&write(t.path(), "c.pem.gz", c)]));
}

#[test]
fn n16_fp_data_after_gzip_is_not_an_error() {
    let t = tempfile::tempdir().unwrap();
    let mut a = gzip(clean_pem().as_bytes());
    a.extend_from_slice(&[0xab; 4096]);
    assert_clean(&scan(&[&write(t.path(), "save.sav", a)]));
    let mut b = vec![0x1f, 0x8b, 0x00, 0x00];
    b.extend_from_slice(clean_pem().as_bytes());
    assert_clean(&scan(&[&write(t.path(), "blob.bin", b)]));
    // A truncated real gzip member is still an error (exit 3), never clean.
    let mut c = gzip(clean_pem().as_bytes());
    c.truncate(c.len() / 2);
    let o = scan(&[&write(t.path(), "cut.gz", c)]);
    assert_eq!(o.code, 3, "{}", o.stdout);
}

// ── N17: "ustar" at offset 257 without a valid tar header ───────────────

fn ustar_text(body: &str) -> Vec<u8> {
    let mut v = b"var headers = require('./headers'); // ".to_vec();
    v.resize(257, b' ');
    v.extend_from_slice(b"ustar\0 is the magic; see ");
    v.extend_from_slice(body.as_bytes());
    v.resize(v.len().max(1024), b'\n');
    v
}

#[test]
fn n17_tp_text_with_ustar_is_scanned_and_real_tar_still_opened() {
    let t = tempfile::tempdir().unwrap();
    assert_found(&scan(&[&write(
        t.path(),
        "headers.js",
        ustar_text(&target_pem()),
    )]));
    let tar = tar_of(&[("ca.pem", target_pem().as_bytes())]);
    assert_found(&scan(&[&write(t.path(), "ca.tar", tar)]));
}

#[test]
fn n17_fp_text_with_ustar_is_not_a_broken_tar() {
    let t = tempfile::tempdir().unwrap();
    assert_clean(&scan(&[&write(
        t.path(),
        "headers.js",
        ustar_text("nothing"),
    )]));
}

// ── N18: "UPX!" outside an executable is not a packed binary ────────────

#[test]
fn n18_tp_upx_executable_still_reported() {
    let t = tempfile::tempdir().unwrap();
    let mut exe = b"MZ".to_vec();
    exe.resize(512, 0);
    exe.extend_from_slice(b"UPX!");
    exe.resize(8192, 0);
    let o = scan(&[&write(t.path(), "packed.exe", exe)]);
    assert_eq!(o.code, 3, "{}", o.stdout);
}

#[test]
fn n18_fp_source_mentioning_upx_is_clean() {
    let t = tempfile::tempdir().unwrap();
    let src = "pub fn has_upx(d: &[u8]) -> bool { find(d, b\"UPX!\") }\n".repeat(20);
    assert_clean(&scan(&[&write(t.path(), "detect.rs", src)]));
}
