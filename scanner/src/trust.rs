//! Trust-model signals for each scanned item: does it bundle CA certificates,
//! use the operating system's trust store, pin keys, or carry a blocklist?
//! Signals are evidence found in the bytes (certificates, API and path names),
//! so they say what the item can do, not which path a given connection takes.

use std::sync::OnceLock;

use aho_corasick::AhoCorasick;
use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Model {
    /// Ships its own CA certificates or trust anchors.
    Bundled,
    /// Uses the operating system's trust store.
    OsStore,
    /// Both: a bundled store plus OS-store code (merged, or one as fallback).
    Both,
    #[default]
    NoneDetected,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct TrustProfile {
    pub path: String,
    pub model: Model,
    /// Distinct self-signed CA certificates found.
    pub bundled_roots: usize,
    pub bundle: Vec<String>,
    pub os_store: Vec<String>,
    pub pinning: Vec<String>,
    pub blocklist: Vec<String>,
}

/// Evidence entries kept per list.
const CAP: usize = 8;
/// A single self-signed CA can be an app's private CA; a store has several.
const MIN_BUNDLED_ROOTS: usize = 2;

fn add(list: &mut Vec<String>, s: String) {
    if list.len() < CAP && !list.contains(&s) {
        list.push(s);
    }
}

impl TrustProfile {
    pub fn add_bundle(&mut self, s: String) {
        add(&mut self.bundle, s);
    }
    pub fn add_blocklist(&mut self, s: String) {
        add(&mut self.blocklist, s);
    }

    /// Bundled when several roots or a known root's trust anchor were found.
    pub fn finish(mut self, path: &str) -> Self {
        self.path = path.to_string();
        let bundled = self.bundled_roots >= MIN_BUNDLED_ROOTS
            || self.bundle.iter().any(|b| b.starts_with("known root"));
        self.model = match (bundled, !self.os_store.is_empty()) {
            (true, true) => Model::Both,
            (true, false) => Model::Bundled,
            (false, true) => Model::OsStore,
            (false, false) => Model::NoneDetected,
        };
        self
    }

    pub fn has_signal(&self) -> bool {
        self.model != Model::NoneDetected || !self.pinning.is_empty() || !self.blocklist.is_empty()
    }
}

#[derive(Clone, Copy)]
enum Sig {
    Os,
    Pin,
    Block,
}

/// (bytes to look for, signal, description).
const MARKERS: &[(&str, Sig, &str)] = &[
    (
        "/etc/ssl/certs/ca-certificates.crt",
        Sig::Os,
        "Debian/Ubuntu/Alpine OS bundle path",
    ),
    (
        "/etc/pki/tls/certs/ca-bundle.crt",
        Sig::Os,
        "RHEL/Fedora OS bundle path",
    ),
    (
        "/etc/ssl/cert.pem",
        Sig::Os,
        "macOS/BSD/Alpine OS bundle path",
    ),
    (
        "/etc/pki/ca-trust/extracted",
        Sig::Os,
        "RHEL p11-kit extracted store path",
    ),
    ("SSL_CERT_FILE", Sig::Os, "SSL_CERT_FILE override"),
    ("SSL_CERT_DIR", Sig::Os, "SSL_CERT_DIR override"),
    (
        "SSL_CTX_set_default_verify_paths",
        Sig::Os,
        "OpenSSL default verify paths",
    ),
    (
        "X509_get_default_cert_file",
        Sig::Os,
        "OpenSSL default cert file",
    ),
    (
        "CertGetCertificateChain",
        Sig::Os,
        "Windows CryptoAPI chain building",
    ),
    (
        "SecTrustEvaluate",
        Sig::Os,
        "macOS/iOS Security framework trust evaluation",
    ),
    (
        "crypto/x509.loadSystemRoots",
        Sig::Os,
        "Go system root loading",
    ),
    (
        "rustls_native_certs",
        Sig::Os,
        "rustls-native-certs (OS roots for rustls)",
    ),
    (
        "rustls_platform_verifier",
        Sig::Os,
        "rustls-platform-verifier (OS verifier)",
    ),
    (
        "load_default_certs",
        Sig::Os,
        "Python ssl load_default_certs",
    ),
    ("inject_into_ssl", Sig::Os, "Python truststore injection"),
    ("NODE_USE_SYSTEM_CA", Sig::Os, "Node.js system CA option"),
    ("--use-system-ca", Sig::Os, "Node.js --use-system-ca"),
    ("--use-openssl-ca", Sig::Os, "Node.js --use-openssl-ca"),
    ("Windows-ROOT", Sig::Os, "Java Windows-ROOT keystore"),
    ("KeychainStore", Sig::Os, "Java macOS KeychainStore"),
    ("AndroidCAStore", Sig::Os, "Android system CA store"),
    ("pin-sha256", Sig::Pin, "HPKP-style pin-sha256"),
    ("CertificatePinner", Sig::Pin, "OkHttp CertificatePinner"),
    (
        "<pin digest=",
        Sig::Pin,
        "Android network security config pin",
    ),
    ("kTSKPinnedDomains", Sig::Pin, "TrustKit pinned domains"),
    (
        "PinnedCertificatesTrustEvaluator",
        Sig::Pin,
        "Alamofire certificate pinning",
    ),
    (
        "PublicKeysTrustEvaluator",
        Sig::Pin,
        "Alamofire public-key pinning",
    ),
    ("assert_fingerprint", Sig::Pin, "urllib3 assert_fingerprint"),
    (
        "setCertificateVerifyProc",
        Sig::Pin,
        "custom certificate verifier (Electron setCertificateVerifyProc)",
    ),
    (
        "ServerCertificateCustomValidationCallback",
        Sig::Pin,
        "custom certificate verifier (.NET)",
    ),
    ("blocked.certs", Sig::Block, "JDK blocked.certs list"),
    (
        "blacklisted.certs",
        Sig::Block,
        "JDK blacklisted.certs list (older JDK name)",
    ),
    (
        "x-distrusted: true",
        Sig::Block,
        "p11-kit x-distrusted entry",
    ),
];

fn automaton() -> &'static AhoCorasick {
    static AC: OnceLock<AhoCorasick> = OnceLock::new();
    AC.get_or_init(|| AhoCorasick::new(MARKERS.iter().map(|m| m.0)).expect("markers"))
}

fn is_b64(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'+' || c == b'/'
}

/// Record OS-store, pinning and blocklist markers found in `data` (component `path`).
pub fn scan_markers(data: &[u8], path: &str, tp: &mut TrustProfile) {
    let mut seen = vec![false; MARKERS.len()];
    for m in automaton().find_iter(data) {
        let i = m.pattern().as_usize();
        if std::mem::replace(&mut seen[i], true) {
            continue;
        }
        let (_, sig, what) = MARKERS[i];
        let note = format!("{what} ({})", short(path));
        match sig {
            Sig::Os => add(&mut tp.os_store, note),
            Sig::Pin => add(&mut tp.pinning, note),
            Sig::Block => add(&mut tp.blocklist, note),
        }
    }
    // OkHttp / HPKP pins: "sha256/" + 43 base64 characters + "=".
    for o in memchr::memmem::find_iter(data, b"sha256/") {
        let pin = data.get(o + 7..o + 51);
        if pin.is_some_and(|p| p[..43].iter().all(|&c| is_b64(c)) && p[43] == b'=') {
            add(
                &mut tp.pinning,
                format!("sha256/ public-key pin ({})", short(path)),
            );
            break;
        }
    }
}

/// Last two components of an archive entry path, for compact evidence.
fn short(path: &str) -> String {
    let parts: Vec<&str> = path.rsplit(['/', ':']).take(2).collect();
    parts.into_iter().rev().collect::<Vec<_>>().join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(data: &[u8]) -> TrustProfile {
        let mut tp = TrustProfile::default();
        scan_markers(data, "app/bin", &mut tp);
        tp.finish("app")
    }

    #[test]
    fn tp_os_store_markers() {
        let tp = profile(b"...\0/etc/ssl/certs/ca-certificates.crt\0SSL_CERT_FILE\0");
        assert_eq!(tp.model, Model::OsStore);
        assert_eq!(tp.os_store.len(), 2);
    }

    #[test]
    fn tp_pinning_markers() {
        let pin = format!("sha256/{}=", "A".repeat(43));
        let tp = profile(format!("okhttp3.CertificatePinner {pin}").as_bytes());
        assert_eq!(tp.pinning.len(), 2, "{:?}", tp.pinning);
    }

    #[test]
    fn tp_bundled_and_both() {
        let mut tp = TrustProfile {
            bundled_roots: 140,
            ..Default::default()
        };
        scan_markers(b"CertGetCertificateChain", "x", &mut tp);
        assert_eq!(tp.finish("x").model, Model::Both);
        let tp = TrustProfile {
            bundled_roots: 140,
            ..Default::default()
        };
        assert_eq!(tp.finish("x").model, Model::Bundled);
    }

    #[test]
    fn fp_plain_data_and_near_misses() {
        let tp = profile(b"sha256/short= the certificate pinner chapter; /etc/ssl/ alone");
        assert_eq!(tp.model, Model::NoneDetected);
        assert!(tp.pinning.is_empty() && tp.os_store.is_empty() && !tp.has_signal());
        // One self-signed CA (an app's private CA) is not a bundled store.
        let tp = TrustProfile {
            bundled_roots: 1,
            ..Default::default()
        };
        assert_eq!(tp.finish("x").model, Model::NoneDetected);
    }
}
