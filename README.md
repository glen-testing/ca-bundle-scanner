# ca-bundle-tracker

What software ships its own Certificate Authority (CA) trust
store and what trusts the host operating system's bundle? Additionally, a scanner that
finds compromised or distrusted CA certificates on a machine.

Built in response to the October 2026 eMudhra compromise.

## Contents

- `docs/`: GitHub Pages site covering filterable tables for browsers, runtimes, CLI tools, servers, containers, desktop apps, embedded platforms and operating systems
- `data/ca-bundle-sources.json`: reference data with per-entry sources and retrieval dates; schema in `data/ca-bundle-sources.schema.json`
- `tools/`: site generator, data validator, and their tests
- `scanner/`: `ca-bundle-scanner`, a Rust command-line scanner
- `ISSUES.md`: Issued found during development and future ideas.

## Scanner

    cargo install --path scanner
    ca-bundle-scanner --profile emudhra

Alternatively, without installing: `cd scanner && cargo build --release && ./target/release/ca-bundle-scanner --profile emudhra`.

### What the eMudhra profile looks for

| Role | Certificates | Verdict when present in an active bundle |
|---|---|---|
| Compromised CA | 16: EM {EV,OV,DV} TLS CA - G3{B,C} and EM OV CS CA - G3{B,C}, each emSign-issued and AAA cross-signed | action required |
| Distrusted root / issuing CA | emSign ECC Root CA - G3; emSign Root TLS CA - G3 and Root CS CA - G3 (cross-signed and self-issued forms) | action required |
| Cross-sign root | Sectigo AAA Certificate Services | action required in bundles; informational in platform stores (macOS, Windows, NSS), whose vendors block the cross-signs |
| Same operator, not distrusted | emSign Root CA - G1, Root CA - C1, ECC Root CA - C3 | informational only |

Matching is by exact certificate (SHA-256 of the DER), or by **public
key**, so a re-issued or newly cross-signed certificate with a compromised key,
or a bare key in a trust-anchor list, is still found. Leaf certificates whose
Authority Key Identifier names a compromised CA are reported as "issued by a compromised CA".

This should take into account distrust lists (p11-kit blocklists,
`x-distrusted: true`, OpenSSL `TRUSTED CERTIFICATE` reject flags, Windows
`Disallowed`), source directories that are not active trust
(`/usr/share/ca-certificates`, `/usr/share/pki/ca-trust-source`), additionally
trust flags that exclude TLS and code signing are reported as informational.

The same applies to roots inside a binary that also carries the SPKI SHA-256 hashes of all 8 compromised keys (Chromium's compiled-in blocklist, as in
patched Electron 42.11.16, 43.8.1, 44.9.1 and later): those chains are rejected,
so the hits are marked `key-blocklist`. The bare-SPKI form compiled into
rustls-webpki 0.103.16 and later (`DISTRUSTED_SPKIS`, e.g. Signal's Rust core) counts
too, as do OneCRL issuer+serial entries for the 6 TLS CAs (Firefox 158.0.1 and later),
which cover NSS's built-in roots of the same application folder. A partial list is
reported but changes nothing.

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
    Dependency analysis of -p folders with lockfiles:
      --no-deps                  skip it
      --deps-online              resolve and download bundling dependencies, then scan them
      --deps-include-dev         also follow development-only dependencies
      --deps-cache-dir <DIR>     where downloaded packages are kept
    Output:
      -q, --quiet                result and findings only
      -j, --json                 one JSON document on stdout (schema 2)
      -h, --help / -V, --version

### Trust model per item

Each scanned item that shows any trust signal is listed in a `TRUST MODEL`
section (text) and in `items` (JSON):

| Field | Meaning | Evidence used |
|---|---|---|
| `model: bundled` | ships its own CA store | 2 or more distinct self-signed CA certificates, or a known root's key as a trust anchor (webpki-roots style) |
| `model: os-store` | uses the operating system's trust store | OS bundle paths (`/etc/ssl/certs/...`, `/etc/pki/tls/...`, `/etc/ssl/cert.pem`), `SSL_CERT_FILE`/`SSL_CERT_DIR`, OpenSSL default verify paths, Windows `CertGetCertificateChain`, macOS `SecTrustEvaluate`, Go system roots, rustls-native-certs / rustls-platform-verifier, Python `load_default_certs` / truststore, Node.js system-CA options, Java `Windows-ROOT` / `KeychainStore`, Android `AndroidCAStore` |
| `model: both` | a bundled store plus OS-store code (merged, or one as fallback) | both of the above |
| `pinning` | pins keys or installs a custom verifier | OkHttp `CertificatePinner` and `sha256/` pins, `pin-sha256`, Android `<pin digest=`, TrustKit, Alamofire evaluators, urllib3 `assert_fingerprint`, Electron `setCertificateVerifyProc`, .NET validation callbacks |
| `blocklist` | carries a blocklist | the compromised-key blocklist (complete or partial), JDK `blocked.certs`, p11-kit `x-distrusted`, distrust locations |

These are signals of capability found in the bytes, not proof of which path a
given connection takes. A CA bundle file scanned directly shows as `bundled`.

### Dependency analysis

A `-p` folder holding lockfiles (Cargo.lock, package-lock.json, uv.lock,
poetry.lock, Pipfile.lock, requirements*.txt, go.mod, Gemfile.lock,
composer.lock, mix.lock, rebar.lock, cpanfile.snapshot) also gets its
dependencies checked for packages that ship their own CA store: certifi,
grpcio, httplib2, botocore, webpki-roots, webpki-root-certs, ssl-root-cas,
Electron (counted even as a devDependency, because it ships in the app), Go
x509roots/fallback, excon, composer/ca-bundle, castore, Erlang certifi and
Mozilla-CA. Each is listed in a `DEPENDENCIES` section (text) and in
`dependencies` (JSON) with its dependency chain, whether it is reachable at
runtime, and any mitigation (rustls-webpki 0.103.16+, patched Electron, Go
toolchain 1.26.10+ / 1.27.3+).

By default this reads lockfiles only, with no network, and the results are
informational. With `--deps-online` the scanner resolves the full dependency
set (cargo metadata, uv), downloads each bundling package once per run and
scans it with the same certificate matching as everything else; a reachable,
unmitigated package whose bundle holds an affected certificate needs action
(exit 1). Downloaded packages are scanned as plain files, never analysed for
their own dependencies, so the analysis cannot recurse. This was formerly the
separate `ca-certs-in-code` tool; its history is kept in `scanner/deps`.

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
keychains, base64 runs (e.g. kubeconfig `certificate-authority-data`), PEM in
source comments or concatenated strings, byte literals in source (`b"\x30.."`,
`0x30, 0x82` arrays, decimal and Java signed-byte arrays, as used by
webpki-roots and webpki-root-certs), and
binaries (PEM strings and DER bytes regardless of architecture). Archives are
unpacked recursively, up to 5 levels: ZIP/JAR/WAR/APK (including executable
JARs with a script prefix; Deflate, Deflate64, bzip2, LZMA, XZ and PPMd
entries), gzip (multi-member; data after the last member is scanned as is), bzip2 (`.bz2`, `.bz`,
`.tbz`, `.tbz2`, multi-stream, and bzip2-compressed ZIP entries), xz, zstd,
tar, ar/`.deb`, RPM (cpio payload) and Electron `.asar`. Formats are detected
by content, not file name. Formats whose payload is not unpacked (SquashFS
images such as AppImage and snap, NSIS and Inno Setup installers, DMG, MSI,
UPX-packed binaries) get a raw-bytes scan; if that finds nothing the file is
reported as not inspected (exit 3), never as clean. Extract them
(`--appimage-extract`, `unsquashfs`, `7z x`, `innoextract`, or mount the DMG)
or scan the installed app folder.

Limits per top-level file: 2 GiB of decompressed output (enough for a whole
Electron app archive), 100,000 archive
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
  Windows, JDKs, AWS CLI, Python, Node.js, VS Code, Firefox profiles. The
  Windows CI job tests the store reader against the runner's stores.

## Development

    cd scanner
    cargo fmt --all --check && cargo clippy --release --workspace --all-targets -- -D warnings
    cargo test --release --workspace                    # unit + end-to-end tests, no network
    cargo test --release --workspace -- --include-ignored  # plus registry/PyPI tests (network, uv)
    tests/data/gen.sh               # regenerate OpenSSL-built test fixtures
    scripts/refresh-certs.sh        # re-download built-in certs from crt.sh and compare

    python3 tools/validate_data.py && python3 tools/build_site.py --check
    python3 -m unittest discover -s tools

Every fix in `ISSUES.md` has a true-positive and a false-positive test.
Test certificates are signed by a throwaway test CA; compromised CAs
contribute only public data (public keys, key identifiers).

## Sources

- [Mozilla Bugzilla 2083449](https://bugzilla.mozilla.org/show_bug.cgi?id=2083449): incident, 16 certificates, fingerprints
- [Mozilla Bugzilla 2084101](https://bugzilla.mozilla.org/show_bug.cgi?id=2084101): emSign ECC Root CA - G3 removal
- [Apple: About the compromised eMudhra intermediate CAs](https://support.apple.com/en-us/149555)
- [certifi advisory GHSA-6q48-6c7w-9gw2](https://osv.dev/vulnerability/GHSA-6q48-6c7w-9gw2)
- [Chrome Root Program](https://googlechrome.github.io/chromerootprogram/)
- [CCADB (Common CA Database)](https://www.ccadb.org/)
- Vendor documentation for each listed runtime and tool (cited per entry in the data file)
