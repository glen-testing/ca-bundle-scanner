# ca-bundle-tracker

Reference for which software ships its own Certificate Authority (CA) trust
store and which trusts the host operating system's bundle, plus a scanner that
finds compromised or distrusted CA certificates on a machine.

Built in response to the October 2026 eMudhra compromise: **8 CA private keys**
(6 TLS, 2 code-signing) were trivially recoverable, and each key has **two
certificates**, one issued by emSign and one cross-signed by Sectigo's
"AAA Certificate Services", so **16 CA certificates** in all
([Mozilla Bugzilla 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449),
[Apple support 149555](https://support.apple.com/en-us/149555)). Patching the
OS trust store does not reach software with its own bundle — Java, Python
certifi and botocore, Node.js, Electron apps, Docker images — and two paths
are easy to miss:

- **AAA Certificate Services.** The Sectigo cross-signs chain to it. Mozilla
  removed its websites trust bit on 2025-04-16 (bug 1957685), but older bundle
  snapshots still carry it, e.g. AWS CLI before 2.38.4. OpenSSL-, Python- and
  Java-based clients do not check revocation, so a bundle that contains AAA
  accepts chains through the compromised cross-signs.
- **macOS `/etc/ssl/cert.pem`.** Apple's fix did not cover command-line tools
  that read this file (curl, git, python3, ruby, perl, openssl).

## Contents

- `docs/` — GitHub Pages site generated from the data file (filterable tables
  for browsers, runtimes, CLI tools, servers, containers, desktop apps,
  embedded platforms and operating systems)
- `data/ca-bundle-sources.json` — the reference data, one source of truth, with
  per-entry sources and retrieval dates; schema in
  `data/ca-bundle-sources.schema.json`
- `tools/` — site generator, data validator, and their tests
- `scanner/` — `ca-bundle-scanner`, a Rust command-line scanner
- `ISSUES.md` — the validated issue list from the 2026-11-02 review, with the
  tests that prove each fix

## Scanner

    cargo install --path scanner
    ca-bundle-scanner --profile emudhra

or, without installing: `cd scanner && cargo build --release && ./target/release/ca-bundle-scanner --profile emudhra`.

### What the eMudhra profile looks for

| Role | Certificates | Verdict when present in an active bundle |
|---|---|---|
| Compromised CA | 16: EM {EV,OV,DV} TLS CA - G3{B,C} and EM OV CS CA - G3{B,C}, each emSign-issued and AAA cross-signed | action required |
| Distrusted root / issuing CA | emSign ECC Root CA - G3; emSign Root TLS CA - G3 and Root CS CA - G3 (cross-signed and self-issued forms) | action required |
| Cross-sign root | Sectigo AAA Certificate Services | action required in bundles; informational in platform stores (macOS, Windows, NSS), whose vendors block the cross-signs |
| Same operator, not distrusted | emSign Root CA - G1, Root CA - C1, ECC Root CA - C3 | informational only |

Matching is by exact certificate (SHA-256 of the DER), and also by **public
key**, so a re-issued or newly cross-signed certificate with a compromised key,
or a bare key in a trust-anchor list, is still found. Leaf certificates whose
Authority Key Identifier names a compromised CA are reported as "issued by a
compromised CA".

Where a certificate sits matters. Copies in distrust lists (p11-kit blocklists,
`x-distrusted: true`, OpenSSL `TRUSTED CERTIFICATE` reject flags, Windows
`Disallowed`), in source directories that are not active trust
(`/usr/share/ca-certificates`, `/usr/share/pki/ca-trust-source`), or with
trust flags that exclude TLS and code signing are reported as informational.

### Options

    Certificate selection (at least one):
      --profile emudhra          built-in eMudhra set (above)
      -c, --cert <FILE>          PEM/DER certificate(s) to treat as compromised (repeatable)
      -r, --root-cert <FILE>     root(s) whose presence means distrusted trust (repeatable)
      -f, --fingerprint <HEX>    SHA-256 to search for; colons allowed (repeatable)
    Scan targets:
      (default)                  built-in system and per-user locations for this OS
      -p, --scan-path <PATH>     extra file or directory, recursive (repeatable)
      -b, --scan-binary <PATH>   extra binary/archive (repeatable)
      --scan-home                walk $HOME for certificate files
      --root <DIR>               resolve system locations under DIR (unpacked image, mounted disk)
      --no-system                skip the built-in locations
      --jobs <N>                 files scanned in parallel (default: CPUs, at most 4)
    Output:
      -q, --quiet                result and findings only
      -j, --json                 one JSON document on stdout (schema 2)
      -h, --help / -V, --version

### Exit codes

| Code | Meaning |
|---|---|
| 0 | clean: nothing needing action, and everything in scope was inspected |
| 1 | at least one finding needs action |
| 2 | usage error (unknown flag, missing value, unreadable `--cert` file) |
| 3 | incomplete: nothing found, but something in scope could not be inspected (missing `-p` path, unreadable file, encrypted PKCS#12 or ZIP entry, unsupported compression, a resource limit reached, or nothing scanned at all) |

### Formats

PEM (any label, including `TRUSTED CERTIFICATE` and `X509 CERTIFICATE`, CRLF,
JSON `\n` escapes; one bad block never hides the others), raw DER, PKCS#7,
PKCS#12 (plaintext bags), Java KeyStore, NSS `cert9.db` (and its `-wal`), macOS
keychains, base64 runs (e.g. kubeconfig `certificate-authority-data`), and
binaries (PEM strings and DER bytes regardless of architecture). Archives are
unpacked recursively, up to 5 levels: ZIP/JAR/WAR/APK (including executable
JARs with a script prefix), gzip (multi-member), xz, zstd, tar, ar/`.deb`,
RPM (cpio payload) and Electron `.asar`. bzip2 is reported as not inspected;
DMG, MSI and UPX-packed files get a raw-bytes scan plus a warning.

Limits per top-level file: 512 MiB of decompressed output, 100,000 archive
entries, 4 GiB file size. Reaching a limit is reported as an error (exit 3
when nothing else was found), and the part already decompressed is scanned.

### Platform coverage

- **Linux / BSD:** OS bundles and directories (Debian, RHEL family, SUSE, Arch,
  Alpine, NixOS, FreeBSD), RHEL anchors and blocklists, Java `cacerts`, Python
  certifi / pip / botocore / AWS CLI v2 / gcloud, RubyGems, Node.js and VS Code
  binaries, Firefox/Thunderbird/Chromium NSS databases (including Snap and
  Flatpak), Docker and Kubernetes CA files, and `SSL_CERT_FILE`,
  `SSL_CERT_DIR`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`,
  `CURL_CA_BUNDLE`, `AWS_CA_BUNDLE`.
- **macOS:** `/etc/ssl/cert.pem`, system/admin/login keychains, Homebrew
  bundles, JDKs, python.org certifi, Electron app frameworks, Firefox profiles.
- **Windows:** the CryptoAPI system stores `ROOT`, `AuthRoot`, `CA`,
  `TrustedPublisher` and `Disallowed` for LocalMachine and CurrentUser, Git for
  Windows, JDKs, AWS CLI, Python, Node.js, VS Code, Firefox profiles. The store
  code is type-checked and linted for Windows locally and runs in the
  Windows CI job.

## Development

    cd scanner
    cargo fmt --check && cargo clippy --release --all-targets -- -D warnings
    cargo test --release            # unit + end-to-end tests, no network
    tests/data/gen.sh               # regenerate OpenSSL-built test fixtures
    scripts/refresh-certs.sh        # re-download built-in certs from crt.sh and compare

    python3 tools/validate_data.py && python3 tools/build_site.py --check
    python3 -m unittest discover -s tools

Every fix in `ISSUES.md` has a true-positive and a false-positive test.
Test certificates are signed by a throwaway test CA; compromised CAs
contribute only public data (public keys, key identifiers).

## Sources

- [Mozilla Bugzilla 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449) — incident, 16 certificates, fingerprints
- [Mozilla Bugzilla 2084101](https://bugzilla.mozilla.org/show_bug.cgi?id=2084101) — emSign ECC Root CA - G3 removal
- [Apple — About the compromised eMudhra intermediate CAs](https://support.apple.com/en-us/149555)
- [certifi advisory GHSA-6q48-6c7w-9gw2](https://osv.dev/vulnerability/GHSA-6q48-6c7w-9gw2)
- [Chrome Root Program](https://googlechrome.github.io/chromerootprogram/)
- [CCADB (Common CA Database)](https://www.ccadb.org/)
- Vendor documentation for each listed runtime and tool (cited per entry in the data file)
