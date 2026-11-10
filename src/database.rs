use crate::Ecosystem;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Artifact {
    PypiWheel,
    Crate,
    NpmTarball,
    GoModule,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CertBundlerEntry {
    pub package: &'static str,
    pub ecosystem: Ecosystem,
    pub description: &'static str,
    pub cert_loading_symbol: &'static str,
    /// (package, note): context attached when the named package is also in the graph.
    pub related: &'static [(&'static str, &'static str)],
    pub artifact: Artifact,
}

pub fn known_bundlers() -> Vec<CertBundlerEntry> {
    vec![
        CertBundlerEntry {
            package: "certifi",
            ecosystem: Ecosystem::Python,
            description: "Mozilla-derived cacert.pem bundle; default trust store for requests, httpx, aiohttp, urllib3 users",
            cert_loading_symbol: "certifi.where()",
            related: &[(
                "truststore",
                "truststore is installed; if the app calls truststore.inject_into_ssl(), ssl contexts use the OS store instead of certifi",
            )],
            artifact: Artifact::PypiWheel,
        },
        CertBundlerEntry {
            package: "grpcio",
            ecosystem: Ecosystem::Python,
            description: "gRPC C-core with embedded roots.pem, used unless GRPC_DEFAULT_SSL_ROOTS_FILE_PATH or explicit root_certificates are set",
            cert_loading_symbol: "grpc.ssl_channel_credentials()",
            related: &[],
            artifact: Artifact::PypiWheel,
        },
        CertBundlerEntry {
            package: "httplib2",
            ecosystem: Ecosystem::Python,
            description: "Ships cacerts.txt",
            cert_loading_symbol: "httplib2.certs.where()",
            related: &[(
                "certifi",
                "certifi is installed, so httplib2 uses certifi.where() instead of its own cacerts.txt (unless HTTPLIB2_CA_CERTS is set)",
            )],
            artifact: Artifact::PypiWheel,
        },
        CertBundlerEntry {
            package: "webpki-roots",
            ecosystem: Ecosystem::Rust,
            description: "Mozilla root trust anchors compiled into the binary",
            cert_loading_symbol: "webpki_roots::TLS_SERVER_ROOTS",
            related: &[(
                "rustls-native-certs",
                "rustls-native-certs is also present; when both root sets are enabled (e.g. reqwest rustls-tls-native-roots + rustls-tls-webpki-roots) both are trusted, so webpki-roots still applies",
            )],
            artifact: Artifact::Crate,
        },
        CertBundlerEntry {
            package: "webpki-root-certs",
            ecosystem: Ecosystem::Rust,
            description: "Mozilla root certificates (full DER) compiled into the binary",
            cert_loading_symbol: "webpki_root_certs::TLS_SERVER_ROOT_CERTS",
            related: &[],
            artifact: Artifact::Crate,
        },
        CertBundlerEntry {
            package: "ssl-root-cas",
            ecosystem: Ecosystem::Node,
            description: "Mozilla root CAs injected into Node's https global agent",
            cert_loading_symbol: "require('ssl-root-cas').inject()",
            related: &[],
            artifact: Artifact::NpmTarball,
        },
        CertBundlerEntry {
            package: "golang.org/x/crypto/x509roots/fallback",
            ecosystem: Ecosystem::Go,
            description: "Mozilla roots used when the OS has no trust store (blank import)",
            cert_loading_symbol: "import _ \"golang.org/x/crypto/x509roots/fallback\"",
            related: &[],
            artifact: Artifact::GoModule,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn no_duplicate_entries() {
        let mut seen = HashSet::new();
        for b in known_bundlers() {
            assert!(seen.insert((b.package, b.ecosystem)), "duplicate: {}", b.package);
        }
    }

    #[test]
    fn tp_known_bundlers_present() {
        let names: HashSet<_> = known_bundlers().iter().map(|b| b.package).collect();
        for n in ["certifi", "webpki-roots", "webpki-root-certs", "httplib2", "grpcio"] {
            assert!(names.contains(n), "{n} missing");
        }
    }

    #[test]
    fn fp_non_bundlers_absent() {
        // node-forge has no root store, ca-certificates is not an npm package,
        // golang.org/x/crypto as a whole is not the fallback root module.
        let names: HashSet<_> = known_bundlers().iter().map(|b| b.package).collect();
        for n in ["node-forge", "ca-certificates", "golang.org/x/crypto", "pip"] {
            assert!(!names.contains(n), "{n} should not be listed");
        }
    }
}

/// Verifier releases that reject chains through the compromised eMudhra keys even
/// when a bundled root store still contains emSign ECC Root CA - G3.
pub fn rustls_webpki_rejects_compromised_keys(version: &str) -> bool {
    use semver::Version;
    let Ok(v) = Version::parse(version) else { return false };
    // DISTRUSTED_SPKIS: 0.103.16+ on the 0.103 line, 0.104.0-alpha.8+ after it.
    let fixed_103 = v >= Version::new(0, 103, 16) && v < Version::parse("0.104.0-alpha.0").unwrap();
    fixed_103 || v >= Version::parse("0.104.0-alpha.8").unwrap()
}

#[cfg(test)]
mod mitigation_tests {
    use super::rustls_webpki_rejects_compromised_keys as fixed;

    #[test]
    fn tp_fixed_releases() {
        for v in ["0.103.16", "0.103.20", "0.104.0-alpha.8", "0.104.0", "0.105.1"] {
            assert!(fixed(v), "{v}");
        }
    }

    #[test]
    fn fp_unfixed_releases() {
        for v in ["0.103.15", "0.103.13", "0.102.8", "0.101.7", "0.104.0-alpha.7", "garbage", ""] {
            assert!(!fixed(v), "{v}");
        }
    }
}
