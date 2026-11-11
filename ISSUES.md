# Validated issue list

Status key: `fixed` (fix in place and both a true-positive and a false-positive
test pass) · `fixed*` (fixed; the proof is a measurement or a build check
rather than a behavioural test, explained in the row) · `needs-owner` (a
decision only the repository owner can make).

Origin: review of 2026-11-02 (speed, correctness, cleanliness, data/docs
reviewers). **TP** = the scanner detects / does what it should; **FP** = it
does not flag the benign counterpart. Scanner tests live in
`scanner/tests/cli.rs` (end-to-end) and in `#[cfg(test)]` modules under
`scanner/src/`; data/site tests in `tools/test_data.py` and `tools/test_site.py`.

Last full run (2026-11-10, macOS arm64): scanner 122/122 (`cargo test --release`),
data/site 62/62 (`python3 -m unittest discover -s tools`), `cargo fmt --check`
clean, `cargo clippy --release --all-targets -D warnings` clean. Linux, Windows
and macOS runs are in CI (`.github/workflows/ci.yml`).

Glossary: CA = Certificate Authority; DER = Distinguished Encoding Rules
(binary certificate form); PEM = Privacy-Enhanced Mail (base64 text form);
SPKI = SubjectPublicKeyInfo; SKI/AKI = Subject/Authority Key Identifier;
PKCS#7/#12 = Public-Key Cryptography Standards container formats; NSS =
Network Security Services (Mozilla's certificate library); JKS = Java
KeyStore; OneCRL = Mozilla's pushed intermediate-revocation list; CS = code
signing; WCAG = Web Content Accessibility Guidelines; CI = continuous
integration.

## C: Correctness (wrong verdicts)

| ID | Issue | Status | Tests (TP / FP) |
|---|---|---|---|
| C01 | DER scan jumped past a non-matching `30 82` span, hiding certificates in `.p7b`, passwordless PKCS#12, signed binaries, or after a stray header | fixed | `c01_tp_p7b_p12_and_stray_header` / `c01_fp_clean_containers` |
| C02 | One malformed PEM block discarded the whole file; an unterminated `BEGIN` swallowed the next block | fixed | `c02_tp_bad_block_and_unterminated_begin`, `pem::tests::*` / `c02_fp_bad_block_with_clean_cert` |
| C03 | emSign Root CA - G1, C1, ECC C3 flagged "UNPATCHED" (exit 1); only ECC Root CA - G3 was distrusted | fixed | `c03_tp_ecc_g3_is_distrusted` / `c03_fp_g1_c1_c3_are_informational` |
| C04 | Failures exited 0; unknown flag exited 1; missing value dropped; help on stderr; no `--version` | fixed | `c04_tp_failures_are_not_clean`, `report::tests::verdicts` / `c04_fp_readable_clean_file_exits_zero` |
| C05 | 4 compromised code-signing intermediates missing | fixed | `c05_tp_code_signing_cas`, `profile::tests::builtin_table_hashes_and_counts` / `c05_fp_other_code_signing_cert` |
| C06 | Whole-certificate hash only; same-key re-issues and bare keys missed | fixed | `c06_tp_reissued_cert_and_bare_key` / `c06_fp_unrelated_key`, `c24_fp_large_clean_blob` |
| C07 | AAA Certificate Services cross-sign path untracked | fixed | `c07_tp_aaa_in_a_bundle` / `c07_fp_aaa_in_platform_store_is_informational` |
| C08 | Directory walk skipped symlinks, `.der`, upper-case, hash-named, `.p11-kit` files | fixed | `c08_tp_symlink_der_uppercase_hashname` / `c08_fp_same_layout_clean` |
| C09 | `koly` in the last 512 bytes skipped the file; MSI/OLE2 skipped | fixed | `c09_tp_koly_and_ole2_still_scanned`, `detect::tests::dmg_needs_full_trailer` / `c09_fp_clean_with_koly` |
| C10 | `TRUSTED CERTIFICATE` / `X509 CERTIFICATE` labels ignored | fixed | `c10_tp_trusted_and_x509_labels`, `scan::tests::trusted_aux_purposes` / `c10_fp_trusted_clean` |
| C11 | JSON-escaped PEM and base64-wrapped PEM/DER missed | fixed | `c11_tp_json_escaped_and_base64` / `c11_fp_base64_of_clean_cert` |
| C12 | Multi-member gzip: only the first member read | fixed | `c12_tp_second_gzip_member` / `c12_fp_multi_member_clean` |
| C13 | Encrypted PKCS#12 / ZIP entries reported CLEAN | fixed | `c13_tp_encrypted_p12_and_zip_are_incomplete` (exit 3) / `c13_fp_plain_containers_no_error` |
| C14 | Certificates in distrust / source locations, or with trust flags excluding TLS and code signing, flagged as compromised | fixed | `c14_tp_same_certs_in_active_locations` / `c14_fp_blocklist_source_and_trust_flags`, `locations::tests::distrust_path_component` |
| C15 | Location bugs: Windows Java globs, macOS Firefox `*`, `**`, Windows store never read, Snap/Flatpak, AWS CLI paths, `cert9.db-wal` | fixed | `locations::tests::{windows_java_glob_matches_under_program_files, macos_firefox_glob_expands, double_star_matches_any_depth, root_prefix_and_home_mapping}`, `c15_tp_aws_cli_and_snap_firefox_paths` / `c15_fp_same_paths_clean`. Windows CryptoAPI store reader (`src/winstore.rs`) is type-checked and clippy-clean for Windows here; the `scanner-platforms` CI job ran it on windows-latest (2026-11-02, run 41534853873): 11 locations scanned, 6 platform-store locations with certificates, 85 tests passed |
| C16 | `.cargo/registry` skip never matched | fixed | `c16_home_scan_skips_cargo_registry_but_finds_others` (TP and FP halves) |
| C17 | A decoder panic aborted the run and lost all findings | fixed | `tests::c17_panic_keeps_partial_findings_and_reports_error` / `tests::c17_no_panic_no_error` |
| C18 | Hand-built JSON broke on control characters; entry names could inject elements | fixed | `c18_tp_hostile_file_names_roundtrip` / `c18_fp_plain_names_valid_json` |
| C19 | "N locations checked" counted missing and duplicate paths | fixed | `c19_duplicates_scanned_once` (TP and FP halves) |
| C20 | Archive members over 50 MB decompressed then discarded | fixed | `c20_tp_entry_over_50mb_in_tar_gz` / `c20_fp_large_clean_entry` |
| C21 | ZIP with a prefix (executable JAR) not recognised | fixed | `c21_tp_prefixed_jar`, `detect::tests::trailing_zip` / `c21_fp_prefixed_jar_clean` |
| C22 | RPM payload never decoded | fixed | `c22_tp_rpm_payload` / `c22_fp_rpm_clean` |
| C23 | Electron binaries never scanned; `is_asar` never true | fixed | `c23_tp_asar`, `detect::tests::asar_detected_and_plain_json_not` / `c23_fp_asar_clean` |
| C24 | `--cert` missed certificates outside 200–8192 bytes or with 1/3-byte lengths | fixed | `c24_tp_large_cert_by_file_and_fingerprint`, `der::tests::header_forms` / `c24_fp_large_clean_blob` |
| C25 | `ar`: zero-size member stopped the archive | fixed | `c25_tp_member_after_empty_one` / `c25_fp_member_after_empty_one_clean` |
| C26 | Labels named the wrong issuer; inconsistent role names | fixed | `c26_labels` (asserts both correct issuer names and absence of the old label) |
| C27 | A fingerprint string in source/config reported as a compromise | fixed | `c27_fingerprint_in_source_is_informational` (TP: reported as reference; FP: other hex not reported) |
| C28 | False reassurance warning for PKCS#7 | fixed | `c28_no_pkcs7_reassurance_warning` (TP and FP halves) |
| C29 | Wrong candidate claims (cargo/rustc webpki-roots, Go/Terraform embedded bundle) | fixed | `locations::tests::no_duplicate_patterns_and_no_bogus_entries`; bare trust-anchor keys are now found anywhere by key matching (`c06_tp_reissued_cert_and_bare_key`) |
| C30 | Leaf certificates issued by a compromised CA not reported | fixed | `c30_tp_leaf_issued_by_compromised` / `c30_fp_leaf_issued_by_other_ca` |

## P: Speed / efficiency

| ID | Issue | Status | Tests / evidence |
|---|---|---|---|
| P01 | Scalar byte search, two passes per binary | fixed* | `memchr::memmem` / Aho-Corasick and table-driven loops. Measured on the 121 MB nvm `node` binary, one core: old 0.35 s CPU, new 0.53 s CPU. The new scanner runs more checks per byte (public keys, AKI, base64), so per-file CPU is higher, not lower |
| P02 | Source scan: two copies + ~38 passes | fixed* | Single pass for hex runs (text only), one Aho-Corasick pass for keywords; npm `node_modules` (1,945 files, 506 MB, every file now read per C08): 2.4 s CPU |
| P03 | Per-stream decompression limits; bombs; memory | fixed | `scan::tests::p03_tp_bomb_is_limited_and_partial_output_scanned` / `scan::tests::p03_fp_under_budget_no_error` |
| P04 | Whole-file heap reads; >200 MB skipped | fixed | `p04_large_file_mmap_path` (TP and FP halves); files ≥1 MiB are memory-mapped, limit raised to 4 GiB |
| P05 | Every DER candidate hashed with String allocation | fixed | Known-length prefilter + `[u8; 32]` keys: `scan::tests::p12_fp_known_length_targets_skip_hashing` |
| P06 | Same file read up to 4× | fixed | `c19_duplicates_scanned_once` (device+inode dedupe); default run on this host prints "already covered" for symlinked paths |
| P07 | Single-threaded | fixed | `p07_parallel_matches_serial` (`--jobs 4` result identical to `--jobs 1`) |
| P08 | Old zip, unused bzip2 C build, redundant `pem`/`hex` | fixed* | `cargo tree -i bzip2-sys|pem|hex` → no such package; zip 9.2.2 with zlib-rs backend |
| P09 | Release profile not tuned | fixed* | `opt-level = 3`, thin LTO for test builds; `dist` profile with fat LTO, `codegen-units = 1`, `strip` |
| P10 | Allocation churn | fixed* | tar/ar/cpio members sliced in place, preallocated decompression, no per-entry lowercase |
| P11 | Depth warning per entry; redundant stats | fixed | `p11_single_nesting_warning` (TP: one warning for 50 nested entries; FP: none when flat) |
| P12 | Hash-amplification hole for fingerprint-only targets | fixed | `scan::tests::p12_tp_hash_amplification_is_limited` / `scan::tests::p12_fp_known_length_targets_skip_hashing` |

## Q: Code cleanliness

| ID | Issue | Status | Evidence |
|---|---|---|---|
| Q01 | 1,675-line single `main.rs` | fixed* | library + modules: `builtin`, `der`, `detect`, `locations`, `pem`, `profile`, `report`, `scan`, `util`, `winstore`; `main.rs` is CLI only |
| Q02 | Hand-rolled argument parser | fixed | clap derive; `c04_tp_failures_are_not_clean` covers unknown flag, missing value, no selection |
| Q03 | Swallowed errors, `String` errors | fixed | `thiserror` `ProfileError`, structured `Issue { severity }`, per-location status; `c04_*`, `c13_*` |
| Q04 | Repetitive location list and hand-written glob | fixed | data table + `glob` crate; `locations::tests::*` |
| Q05 | Fingerprints in 3 places; hard-coded counts | fixed | one table of embedded DER files with their SHA-256, verified at start-up and by `profile::tests::builtin_table_hashes_and_counts`; counts derived from the table |
| Q06 | Duplicated plumbing, dead code | fixed* | one `FileScan` with shared helpers; dead "reference" branch and unused parameters removed; `cargo clippy -D warnings` clean |
| Q07 | Vacuous, network-dependent bash suite | fixed | replaced by Rust tests that always pass `--no-system` and assert exact certificates; fixtures built by `tests/data/gen.sh`; crt.sh refresh moved to `scripts/refresh-certs.sh` (not run by tests). Old suite and 9 MB of fixtures moved out of the repo |
| Q08 | Binary naming mismatch; stale binary | fixed | README/site use `ca-bundle-scanner`; stale `target/release/emudhra-scanner` removed |
| Q09 | Outdated crates | fixed* | zip 9.2.2, x509-parser 0.18.1, ruzstd 0.9.1; `pem`/`hex` dropped |
| Q10 | fmt/clippy failures, no `rust-version`/`[lints]` | fixed* | `cargo fmt --check` and `cargo clippy --all-targets -D warnings` clean (Linux + Windows target); `rust-version = "1.88"`, `[lints]` table |

## D: Data, docs, website

| ID | Issue | Status | Tests |
|---|---|---|---|
| D01 | AAA cross-sign path and macOS `/etc/ssl/cert.pem` gap absent | fixed | `test_data.IssueRegressions.test_d01_*`; README section; scanner side is C07 |
| D02 | Non-existent binary name; no-argument invocation | fixed | README + site use `ca-bundle-scanner --profile emudhra`; `c04_tp_failures_are_not_clean` (no selection → 2) |
| D03 | Inconsistent counts | fixed | `test_d03_incident_counts`; 16-certificate figure confirmed: both code-signing keys have AAA cross-signs (`EM_OV_CS_CA_G3{B,C}_AAA`, fingerprints per Bugzilla 2083449) |
| D04 | README omitted options/exit codes/formats; false Windows/macOS claims | fixed | README rewritten from `--help` and the code; claims backed by C15 tests |
| D05 | cargo row wrong | fixed | `test_d05_*` |
| D06 | Node.js versions | fixed | `test_d06_node_flag_versions` |
| D07 | pip / requests | fixed | `test_d07_*` |
| D08 | curl per-OS rows | fixed | `test_d08_curl_split_per_os` |
| D09 | Homebrew | fixed | `test_d09_homebrew_paths` |
| D10 | Dart/Flutter | fixed | `test_d10_dart_uses_os_store` |
| D11 | Firefox OneCRL | fixed | `test_d11_firefox_onecrl` |
| D12 | Android Conscrypt | fixed | `test_d12_android_conscrypt` |
| D13 | Chrome/Edge; Chrome link | fixed | `test_d13_*` |
| D14 | Smaller row errors | fixed | `test_d14_smaller_errors` |
| D15 | "Integers as small as 4" attribution | fixed | `test_d15_*`, `test_site.Wording` |
| D16 | Hand-maintained HTML diverged from JSON | fixed | `test_site.Freshness`, `test_site.RowParity` (TP + stale-copy FP) |
| D17 | No schema / sources / remediation fields | fixed | `test_data.SchemaValidation` (valid passes; broken copies rejected), `test_data.Sources` |
| D18 | Filter UX / accessibility | fixed | `test_site.Accessibility`, `test_site.FilterLogic` |
| D19 | Contrast below 4.5:1 | fixed | `test_site.Contrast` (all pairs ≥ 5.69:1; a failing pair is detected) |
| D20 | Sticky header; mobile overflow | fixed | `test_site.Layout` |
| D21 | Landmarks, captions, scope, favicon | fixed | `test_site.Accessibility` |
| D22 | Unverified rows presented as fact | fixed | `test_tp_unverified_rows_are_flagged`, `test_d22_*` |
| D23 | No CI; unused fixtures | fixed | `.github/workflows/ci.yml` (Linux scanner, Windows + macOS scanner with platform-store smoke run, data/site, link check), `test_site.ContinuousIntegration`; unused fixtures removed from the repo |
| D24 | No LICENSE / CONTRIBUTING / SECURITY | needs-owner | the licence choice belongs to the repository owner |

## Found during the fixes

| ID | Issue | Status | Tests |
|---|---|---|---|
| N01 | emSign Root TLS CA - G3 / Root CS CA - G3 (issuers of the compromised CAs, cross-signed and self-issued forms) were not tracked | fixed | `profile::tests::builtin_table_hashes_and_counts`; key needles cover all forms |
| N02 | OpenSSL trust flags: a `TRUSTED CERTIFICATE` allowed only for email is not a TLS/code-signing exposure (RHEL `ca-bundle.trust.crt` holds AAA as email + code signing, which still exposes the code-signing cross-signs) | fixed | `scan::tests::trusted_aux_purposes`, `c14_*` |
| N03 | JavaScript fragments containing `-----BEGIN CERTIFICATE-----` inside the `node` binary produced malformed-PEM warnings | fixed | `pem::looks_like_pem_body`; default host run shows no such warnings |
| N04 | `# SHA256 Fingerprint:` comments in certifi-style bundles produced a duplicate "reference" for every certificate already matched | fixed | `n04_fingerprint_comment_next_to_cert_not_duplicated` (FP); `c27_fingerprint_in_source_is_informational` still reports standalone fingerprints (TP) |
| N05 | Trust stores compiled in as source literals were reported only as informational references: webpki-roots (public keys as `b"\x.."` byte strings, PEM inside ` * ` comments) and webpki-root-certs (full DER as byte strings) came back clean while shipping emSign ECC Root CA - G3; same for C/Go/Java byte arrays and JavaScript-concatenated PEM (ssl-root-cas) | fixed | `n05_tp_*` / `n05_fp_*`, `literal::tests`, `pem::commented_tests` |
| N06 | Patched Electron (42.11.16, 43.8.1, 44.9.1, 45.0.0-beta.6 and later) was reported exactly like unpatched Electron: the fix keeps emSign ECC Root CA - G3 and AAA in the binary and adds the SPKI SHA-256 of the 8 compromised keys to Chromium's compiled-in blocklist (GHSA-jr5w-w6x2-84p9). A file carrying all 8 hashes now marks its root and compromised-CA hits `key-blocklist` (no action) and reports the blocklist; a partial list changes nothing | fixed | `n06_*`; Electron 43.8.0 found, 43.8.1 clean on Linux, macOS and Windows |
| N07 | Installers and images whose payload is not unpacked scanned clean (exit 0): an unpatched Logseq 2.0.2 AppImage (SquashFS), NSIS installer and DMG all returned clean. SquashFS, NSIS and Inno Setup are now detected, and these plus DMG, MSI and UPX are errors (exit 3) when the raw-bytes scan finds nothing. The 512 MiB decompression budget cut Electron app zips short (the blocklist could be missed); raised to 2 GiB | fixed | `n07_*`, `detect::tests::installers_and_squashfs` |
| N08 | Patched Signal 8.34.0 was reported as shipping all 8 compromised keys: its Rust core (libsignal-client.node) links rustls-webpki 0.103.16, whose compiled-in `DISTRUSTED_SPKIS` holds those keys as bare SPKI DER so chains through them are rejected. A file holding all 8 keys as bare SPKIs outside any certificate is now treated like the SPKI-hash blocklist (`key-blocklist`); the same keys inside the compromised certificates still need action | fixed | `n08_*`; Signal 8.34.0 .deb clean |
| N09 | bzip2 data (`.tar.bz2`, `.tbz`, `.bz2`, bzip2 ZIP entries) was reported "not supported" and its contents never scanned; Homebrew `gettext` ships `archive.dir.tar.bz2`, so real scans ended incomplete (exit 3) | fixed | `n09_tp_bzip2_every_form`, `scan::tests::n09_tp_bzip2_bomb_is_limited_and_partial_output_scanned` / `n09_fp_bzip2_every_form_clean`, `scan::tests::n09_fp_bzip2_under_budget_no_error`, `n09_truncated_bzip2_is_incomplete_not_clean`; pure-Rust decoder (`libbz2-rs-sys`), so `cargo tree -i bzip2-sys` still finds no C build (P08) |
| N10 | Deno 2.9.8 and pixi 0.82.1 (patched) were reported as shipping the 8 compromised keys: their rustls-webpki distrust list stores each key as SPKI contents without the outer SEQUENCE header, a form N08 did not match. Both forms now count | fixed | `n10_tp_inner_spki_distrust_list_mitigates`; Deno 2.9.7 found, 2.9.8 clean; pixi 0.82.0 found, 0.82.1 clean |
| N11 | Go 1.26.10+ keeps the SPKI SHA-256 blocklist as hex strings (`distrustedSPKIHashes` in crypto/x509), so Go binaries built with the fix showed no blocklist and a Go binary also embedding x509roots/fallback would have been reported as unmitigated. Hex text (either case) now counts | fixed | `n11_tp_hex_text_spki_hashes_mitigate`; gh 2.102.0 no blocklist, 2.102.1 complete blocklist |
| N12 | The report did not say how an item decides trust. Each scanned item with a signal now gets a trust model: bundles its own CA store (distinct self-signed CA certificates or known-root trust anchors), uses the OS store (store paths and OS verifier APIs), both, plus pinning and blocklist evidence. Signals show capability found in the bytes, not which path a given connection takes | fixed | `n12_tp_bundle_os_store_both_pinning_blocklist`, `fp_n12_single_cert_or_plain_file_has_no_trust_item`, `trust::tests` |
| N13 | Patched Firefox 158.0.1 was reported like 158.0: its fix is a baked-in OneCRL list (issuer + serial of the 6 TLS intermediates, in `browser/omni.ja`) while the G3 and AAA roots stay in NSS inside `libxul.so`. Issuer+serial lists are now recognised; covering all 6 TLS keys is accepted for OneCRL (NSS does not verify code signatures), and a OneCRL list mitigates the NSS root module only inside the same application folder (archive or installed), never a neighbouring app | fixed | `n13_tp_onecrl_mitigates_firefox_tarball_and_install_dir`, `n13_fp_incomplete_onecrl_or_other_app_does_not_mitigate`, `onecrl_scope_tests`; Firefox 158.0 found, 158.0.1 clean |
| N14 | Dependency analysis was a separate tool (ca-certs-in-code) that had to be installed and run on its own, and its deep scan shelled out to this scanner. It is now built in: `-p` folders with lockfiles get their CA-bundling dependencies listed (offline, informational), and `--deps-online` downloads and scans them in-process, so there is one binary and no recursion | fixed | `n14_tp_offline_lists_bundling_dependencies_without_changing_verdict`, `n14_fp_no_lockfile_or_no_deps_flag_means_no_analysis`, network tests `n14_tp_fp_online_*`; deps library tests in `scanner/deps` |
| N15 | ZIP entries compressed with LZMA (method 14), XZ (95) or PPMd (98) were reported "compression method not supported" and never scanned. Source-engine `.bsp` map paks use LZMA: a Windows run over Program Files (x86) logged ~662,000 such errors from Team Fortress 2 alone, burying real ones. The zip crate's pure-Rust `lzma`, `xz` and `ppmd` features are now on (no C build, P08 still holds); ZIP zstd (93) stays off because the zip crate's zstd backend is a C library | fixed | `n15_tp_lzma_xz_ppmd_zip_entries` / `n15_fp_lzma_xz_ppmd_zip_entries_clean` (LZMA fixtures from `tests/data/gen.sh`, since the zip crate cannot write LZMA); TF2 maps: 17,583 errors → 0 |
| N16 | gzip followed by non-gzip data (Serious Sam 3 saves, Chromium GPUCache entries) was an "invalid gzip header" error (exit 3) and the trailing data was never scanned; any file starting with the two bytes `1f 8b` was taken for gzip, so its contents were never scanned either. Members are now decoded one at a time, data after the last member is scanned as is, and detection requires a full gzip header (CM = 8, reserved flags clear). A truncated real member is still an error | fixed | `n16_tp_data_after_gzip_and_fake_gzip_magic_are_scanned` / `n16_fp_data_after_gzip_is_not_an_error`, `detect::tests::gzip_and_tar_need_valid_headers`; `c12_*` still pass |
| N17 | Text with `ustar` at offset 257 (node `tar-stream/headers.js`, Minecraft language JSON) was opened as tar, reported "tar header unreadable" and not scanned as text. Tar detection now also requires a valid header checksum | fixed | `n17_tp_text_with_ustar_is_scanned_and_real_tar_still_opened` / `n17_fp_text_with_ustar_is_not_a_broken_tar`, `detect::tests::gzip_and_tar_need_valid_headers` |
| N18 | Any file with `UPX!` in its first 4 KiB, including this scanner's own `detect.rs`, was reported as a UPX-packed binary (exit 3). It now has to be a PE, ELF or Mach-O executable | fixed | `n18_tp_upx_executable_still_reported` / `n18_fp_source_mentioning_upx_is_clean`, `detect::tests::upx_needs_an_executable` |
| N19 | Files that vanished between the directory walk and the read (browser and token caches) and, on Windows, reparse points the system cannot open as files (Docker Desktop's AF_UNIX sockets, WSL symlinks, app execution aliases: `ERROR_CANT_ACCESS_FILE`, 1920) were "unreadable" errors (exit 3). They hold no file data and are now skipped, as Unix walks already skip sockets. Access denied and files locked by another process (os error 32) are still errors | fixed | `tests::n19_vanished_files_and_unopenable_reparse_points_are_skipped`, `tests::n19_file_vanished_after_walk_is_not_an_error`; `%LOCALAPPDATA%\Docker\run`: 4 errors → 0 |

## Roadmap candidates

Ideas under consideration, not commitments; nothing here is implemented. Each
one moves into the tables above, with a true-positive and a false-positive test,
once work starts. Statements marked **to verify** are working assumptions that need
checking against the updater's source or a lab test first.

### R01: Do an app's updates check a signature or hash, and does that check survive the eMudhra compromise?

**Why.** [Electron, we have a problem](https://schaerli.org/briefs/electron-we-have-a-problem/)
(2026-11-10) shows the eMudhra keys matter most where an app trusts them *and*
installs updates without an independent check: an attacker who can mint a TLS
certificate can then push code. The scanner already answers the first half
(does the app still trust the compromised CAs). This item adds the second half
for each app it finds:

1. **Is the update verified at all?** Which update method the app uses, per
   platform, and whether that method checks a signature or a hash before
   installing.
2. **Does the check itself depend on the compromised CAs?** A check only helps
   if the attacker who controls TLS cannot also satisfy it.

**How each kind of check holds up**

| Update check | Example | Independent of the compromised CAs? |
|---|---|---|
| None | electron-updater on Linux (AppImage), Squirrel.Windows `Update.exe` | No protection |
| Hash only, fetched over the same TLS channel | electron-updater `sha512` in `latest.yml` | No: whoever forges TLS rewrites the hash too |
| X.509 code signing judged by a trust store | electron-updater on Windows with `publisherName` (Authenticode) | Only if that trust store rejects the compromised code-signing CAs (see below) |
| Platform signing with a vendor-only CA | Squirrel.Mac (Apple Developer ID), MSIX / Microsoft Store | Yes: eMudhra cannot issue for those |
| Pinned vendor key | Signal (ed25519), Tuta and KeeWeb (RSA), OneKey and Trezor (GPG) | Yes, as long as the key is not fetched over TLS |

**Authenticode is the case to check closely.** Two of the 8 compromised keys
are code-signing CAs (`EM OV CS CA - G3B` / `G3C`), trusted by Windows through
emSign ECC Root CA - G3, `emSign Root CS CA - G3` and the Sectigo AAA
cross-signs. Microsoft blocked all 8 keys in its disallowed list on
2026-10-19. A Windows machine that has not received that update, or an app
that validates Authenticode against its own bundled store, would accept a
code-signing certificate minted with those keys. **To verify:** electron-updater
compares the signer's subject name with `publisherName` from `app-update.yml`
rather than pinning a key, so a minted certificate carrying the same publisher
name would pass on such a machine. If that holds, "signed electron-updater" on
Windows is only as strong as the machine's trust list.

**Approach (static, no execution)**

- Identify the updater from files in the app: `app-update.yml` / `latest*.yml`
  and `electron-updater` in the `app.asar` package list; `ShipIt` and
  `Squirrel.framework` (Squirrel.Mac); `Update.exe` plus `.nupkg` (Squirrel.Windows);
  `AppxManifest.xml` (MSIX); custom updaters by known module names.
- Read the verification settings: `publisherName`,
  `verifyUpdateCodeSignature`, update URLs (`https://` or not), and embedded
  public keys (PEM, ed25519 hex, GPG armour) next to the update code.
- Classify each platform build into a row of the table above, and combine it
  with the existing trust verdict: *trusts the compromised CAs* × *update check
  that the same attacker can satisfy* = remote code execution path, reported as
  its own finding kind.
- Output per app: updater, check type, whether the check depends on a trust
  store, and which store (OS, bundled, Electron's).

**Tests.** True positive: an electron-updater app with no `publisherName`
(unverified) that still trusts the compromised CAs is reported as an update
risk. False positives: a Squirrel.Mac build, a pinned-key updater (Signal), and
an app with no auto-update are not.

**Limits.** Static inspection can be fooled by custom or obfuscated updaters,
so a "verified" result says what was found, not a guarantee. Update servers
are never contacted.

### R02: Unpack the installer formats that currently report "incomplete"

AppImage and snap (SquashFS), NSIS and Inno Setup installers, and DMG are
detected but not opened (N07), so users have to extract them first. Reading
SquashFS natively (pure-Rust decoders for its gzip, xz and zstd blocks) would
cover most Linux apps in the brief; NSIS and DMG are harder and may stay
"extract first".

### R03: Check every app in the Electron brief

Scan the latest build of each of the 36 apps in the brief's table on each
platform and compare the scanner's verdict with the brief's "Patched" column.
Disagreements are either scanner bugs or corrections for the brief. Each app's
verdict should follow from its bundled Electron version, plus native modules
with their own TLS stack (Signal's Rust core, Delta Chat's core).
