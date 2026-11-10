//! Recursive content scanner for one top-level file or in-memory blob.

use std::io::{Cursor, Read};

use x509_parser::prelude::*;

use crate::detect::{self, Container};
use crate::profile::{authority_key_id, first_cn, subject_key_id, NeedleKind, Profile};
use crate::report::{action_required, Context, Finding, Issue, Kind, Match, Severity};
use crate::trust::{self, TrustProfile};
use crate::util::{basename, hex, hex_val, is_source_name, sha256, CLASS, HEX_OR_COLON};
use crate::{der, literal, pem};

/// Resource limits, applied per top-level file across all nesting levels.
#[derive(Clone, Debug)]
pub struct Limits {
    pub max_depth: u32,
    /// Total bytes produced by decompression / base64 decoding.
    pub max_decompressed: u64,
    pub max_entries: u64,
    /// Bytes hashed for certificate candidates: this plus 8 × file size.
    pub hash_budget_base: u64,
    pub max_file: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_depth: 5,
            max_decompressed: 2 << 30,
            max_entries: 100_000,
            hash_budget_base: 256 << 20,
            max_file: 4 << 30,
        }
    }
}

/// Shortest base64 run worth decoding: a ~300-byte certificate.
const MIN_B64_RUN: usize = 400;
/// How far before a key / SKI hit to look for its enclosing certificate.
const ENCLOSING_WINDOW: usize = 16 << 10;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Once {
    Depth = 1,
    Budget = 2,
    Hash = 4,
    Entries = 8,
    Nested = 16,
}

pub struct FileScan<'a> {
    profile: &'a Profile,
    limits: &'a Limits,
    context: Context,
    pub findings: Vec<Finding>,
    pub issues: Vec<Issue>,
    decompressed_left: u64,
    entries_left: u64,
    hash_left: u64,
    once: u8,
    pub trust: TrustProfile,
    roots_seen: std::collections::HashSet<[u8; 32]>,
    /// Components holding a complete OneCRL-style (issuer+serial) blocklist.
    pub onecrl: Vec<String>,
}

impl<'a> FileScan<'a> {
    pub fn new(profile: &'a Profile, limits: &'a Limits, context: Context, top_len: u64) -> Self {
        Self {
            profile,
            limits,
            context,
            findings: Vec::new(),
            issues: Vec::new(),
            decompressed_left: limits.max_decompressed,
            entries_left: limits.max_entries,
            hash_left: limits
                .hash_budget_base
                .saturating_add(top_len.saturating_mul(8)),
            once: 0,
            trust: TrustProfile::default(),
            roots_seen: Default::default(),
            onecrl: Vec::new(),
        }
    }

    /// Count distinct self-signed CA certificates (evidence of a bundled store).
    fn note_cert(&mut self, der: &[u8], path: &str) {
        if !(300..=8192).contains(&der.len()) {
            return;
        }
        let Ok((_, c)) = X509Certificate::from_der(der) else {
            return;
        };
        if c.is_ca() && c.subject() == c.issuer() && self.roots_seen.insert(sha256(der)) {
            self.trust.bundled_roots += 1;
            let entry = path.rsplit(['/', ':']).next().unwrap_or(path);
            self.trust.add_bundle(format!("CA certificates in {entry}"));
        }
    }

    pub fn scan(&mut self, data: &[u8], path: &str) {
        self.scan_blob(data, path, 0);
        let lists = self.onecrl.clone();
        mitigate_nss_with_onecrl(&mut self.findings, &lists);
    }

    fn issue(&mut self, path: &str, severity: Severity, message: String) {
        self.issues.push(Issue {
            path: path.to_string(),
            severity,
            message,
        });
    }

    fn warn(&mut self, path: &str, message: String) {
        self.issue(path, Severity::Warning, message);
    }

    fn error(&mut self, path: &str, message: String) {
        self.issue(path, Severity::Error, message);
    }

    fn first(&mut self, flag: Once) -> bool {
        let new = self.once & flag as u8 == 0;
        self.once |= flag as u8;
        new
    }

    #[allow(clippy::too_many_arguments)]
    fn push(
        &mut self,
        path: &str,
        source: &str,
        cert: String,
        fp: Option<[u8; 32]>,
        kind: Kind,
        matched: Match,
        ctx: Option<Context>,
    ) {
        let context = ctx.unwrap_or(self.context);
        self.findings.push(Finding {
            path: path.to_string(),
            source: source.to_string(),
            cert,
            sha256: fp.map(|f| hex(&f)),
            kind,
            matched,
            context,
            action_required: action_required(kind, context),
        });
    }

    fn scan_blob(&mut self, data: &[u8], path: &str, depth: u32) {
        if depth > self.limits.max_depth {
            if self.first(Once::Depth) {
                let msg = format!(
                    "nested deeper than {} levels; inner content not scanned",
                    self.limits.max_depth
                );
                self.error(path, msg);
            }
            return;
        }
        if depth >= 3 && self.first(Once::Nested) {
            self.warn(path, format!("content nested {depth} levels deep"));
        }
        if data.is_empty() {
            return;
        }
        match detect::container(data) {
            Some(Container::Zip) => {
                if !self.scan_zip(data, path, depth) {
                    self.leaf(data, path, depth);
                }
            }
            Some(Container::Gzip) => {
                let out = self.decompress(
                    &mut flate2::read::MultiGzDecoder::new(data),
                    0,
                    path,
                    "gzip",
                );
                self.scan_blob(&out, path, depth + 1);
            }
            Some(Container::Xz) => {
                let out = self.unxz(data, path);
                self.scan_blob(&out, path, depth + 1);
            }
            Some(Container::Zstd) => {
                let out = self.unzstd(data, path);
                self.scan_blob(&out, path, depth + 1);
            }
            Some(Container::Bzip2) => {
                // Multi-stream: pbzip2/lbzip2 output and `cat a.bz2 b.bz2` are concatenated streams.
                let out = self.decompress(
                    &mut bzip2::read::MultiBzDecoder::new(data),
                    0,
                    path,
                    "bzip2",
                );
                self.scan_blob(&out, path, depth + 1);
            }
            Some(Container::Tar) => self.scan_tar(data, path, depth),
            Some(Container::Ar) => self.scan_ar(data, path, depth),
            Some(Container::Rpm) => self.scan_rpm(data, path, depth),
            Some(Container::Cpio) => self.scan_cpio(data, path, depth),
            None => self.leaf(data, path, depth),
        }
    }

    /// Read up to the remaining decompression budget; partial output is kept.
    fn decompress(&mut self, r: &mut dyn Read, hint: u64, path: &str, what: &str) -> Vec<u8> {
        let cap = self.decompressed_left;
        if cap == 0 {
            self.budget_exhausted(path);
            return Vec::new();
        }
        let mut buf = Vec::with_capacity(hint.min(cap).min(64 << 20) as usize);
        let res = r.take(cap + 1).read_to_end(&mut buf);
        if let Err(e) = res {
            let msg = format!("{what} data unreadable after {} bytes: {e}", buf.len());
            self.error(path, msg);
        }
        if buf.len() as u64 > cap {
            buf.truncate(cap as usize);
            self.budget_exhausted(path);
        }
        self.decompressed_left -= buf.len() as u64;
        buf
    }

    fn budget_exhausted(&mut self, path: &str) {
        if self.first(Once::Budget) {
            let msg = format!(
                "decompression budget ({} MiB per file) exhausted; only the first part was scanned",
                self.limits.max_decompressed >> 20
            );
            self.error(path, msg);
        }
    }

    fn unxz(&mut self, data: &[u8], path: &str) -> Vec<u8> {
        struct Cap {
            buf: Vec<u8>,
            cap: usize,
            hit: bool,
        }
        impl std::io::Write for Cap {
            fn write(&mut self, d: &[u8]) -> std::io::Result<usize> {
                let room = self.cap - self.buf.len();
                if d.len() > room {
                    self.buf.extend_from_slice(&d[..room]);
                    self.hit = true;
                    return Err(std::io::Error::other("limit"));
                }
                self.buf.extend_from_slice(d);
                Ok(d.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut w = Cap {
            buf: Vec::new(),
            cap: self.decompressed_left as usize,
            hit: false,
        };
        let res = lzma_rs::xz_decompress(&mut std::io::BufReader::new(data), &mut w);
        if w.hit {
            self.budget_exhausted(path);
        } else if let Err(e) = res {
            let msg = format!("xz data unreadable after {} bytes: {e}", w.buf.len());
            self.error(path, msg);
        }
        self.decompressed_left -= w.buf.len() as u64;
        w.buf
    }

    fn unzstd(&mut self, data: &[u8], path: &str) -> Vec<u8> {
        let mut cur = Cursor::new(data);
        let mut out = Vec::new();
        while (cur.position() as usize) < data.len() {
            let rest = &data[cur.position() as usize..];
            if !rest.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
                break;
            }
            match ruzstd::decoding::StreamingDecoder::new(&mut cur) {
                Ok(mut d) => {
                    let part = self.decompress(&mut d, 0, path, "zstd");
                    let short = part.is_empty();
                    out.extend_from_slice(&part);
                    if short || self.decompressed_left == 0 {
                        break;
                    }
                }
                Err(e) => {
                    self.error(path, format!("zstd frame unreadable: {e}"));
                    break;
                }
            }
        }
        out
    }

    fn take_entry(&mut self, path: &str) -> bool {
        if self.entries_left == 0 {
            if self.first(Once::Entries) {
                let msg = format!(
                    "archive entry limit ({}) reached; remaining entries not scanned",
                    self.limits.max_entries
                );
                self.error(path, msg);
            }
            return false;
        }
        self.entries_left -= 1;
        true
    }

    /// Returns false when the data cannot be opened as a ZIP at all.
    fn scan_zip(&mut self, data: &[u8], path: &str, depth: u32) -> bool {
        let mut ar = match zip::ZipArchive::new(Cursor::new(data)) {
            Ok(a) => a,
            Err(e) => {
                if data.starts_with(b"PK") {
                    self.error(
                        path,
                        format!("ZIP could not be opened ({e}); raw bytes scanned instead"),
                    );
                }
                return false;
            }
        };
        for i in 0..ar.len() {
            if !self.take_entry(path) {
                break;
            }
            let (entry_path, buf) = match ar.by_index(i) {
                Ok(mut f) => {
                    if f.is_dir() {
                        continue;
                    }
                    let name = f
                        .name()
                        .map(|n| n.into_owned())
                        .unwrap_or_else(|_| format!("#{i}"));
                    let ep = format!("{path}:{name}");
                    let size = f.size();
                    let buf = self.decompress(&mut f, size, &ep, "ZIP entry");
                    (ep, buf)
                }
                Err(e) => {
                    self.error(
                        &format!("{path}:#{i}"),
                        format!("ZIP entry not inspected: {e}"),
                    );
                    continue;
                }
            };
            self.scan_blob(&buf, &entry_path, depth + 1);
        }
        true
    }

    fn scan_tar(&mut self, data: &[u8], path: &str, depth: u32) {
        let mut ar = tar::Archive::new(Cursor::new(data));
        let entries = match ar.entries() {
            Ok(e) => e,
            Err(e) => {
                self.error(path, format!("tar unreadable: {e}"));
                return;
            }
        };
        for entry in entries {
            if !self.take_entry(path) {
                break;
            }
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    self.error(
                        path,
                        format!("tar header unreadable ({e}); remaining entries not scanned"),
                    );
                    break;
                }
            };
            if !entry.header().entry_type().is_file() || entry.size() == 0 {
                continue;
            }
            let name = entry
                .path()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| "<unreadable name>".into());
            let ep = format!("{path}:{name}");
            let start = entry.raw_file_position() as usize;
            match start
                .checked_add(entry.size() as usize)
                .and_then(|end| data.get(start..end))
            {
                Some(body) => self.scan_blob(body, &ep, depth + 1),
                None => self.error(&ep, "tar entry truncated; not scanned".into()),
            }
        }
    }

    fn scan_ar(&mut self, data: &[u8], path: &str, depth: u32) {
        let mut pos = 8usize;
        while pos + 60 <= data.len() {
            if !self.take_entry(path) {
                break;
            }
            let h = &data[pos..pos + 60];
            if &h[58..60] != b"`\n" {
                self.error(
                    path,
                    format!("ar header malformed at byte {pos}; rest not scanned"),
                );
                break;
            }
            let name = String::from_utf8_lossy(&h[..16])
                .trim()
                .trim_end_matches('/')
                .to_string();
            let size = std::str::from_utf8(&h[48..58])
                .ok()
                .and_then(|s| s.trim().parse::<usize>().ok());
            let Some(size) = size else {
                self.error(
                    path,
                    format!("ar member size unreadable at byte {pos}; rest not scanned"),
                );
                break;
            };
            pos += 60;
            let Some(body) = pos.checked_add(size).and_then(|end| data.get(pos..end)) else {
                self.error(path, format!("ar member {name:?} truncated; not scanned"));
                break;
            };
            let skip = name.is_empty() || name == "/SYM64" || name == "debian-binary";
            if !skip && size > 0 {
                self.scan_blob(body, &format!("{path}:{name}"), depth + 1);
            }
            pos += size + (size & 1);
        }
    }

    fn scan_rpm(&mut self, data: &[u8], path: &str, depth: u32) {
        let mut pos = 96usize;
        for pad in [true, false] {
            let Some(h) = data.get(pos..pos + 16) else {
                self.error(path, "RPM truncated; payload not scanned".into());
                return;
            };
            if h[..3] != [0x8e, 0xad, 0xe8] {
                self.error(
                    path,
                    "RPM header malformed; raw bytes scanned instead".into(),
                );
                self.leaf(data, path, depth);
                return;
            }
            let n = u32::from_be_bytes([h[8], h[9], h[10], h[11]]) as usize;
            let size = u32::from_be_bytes([h[12], h[13], h[14], h[15]]) as usize;
            pos += 16 + 16 * n + size;
            if pad {
                pos = (pos + 7) & !7;
            }
        }
        match data.get(pos..) {
            Some(payload) => self.scan_blob(payload, &format!("{path}:payload"), depth + 1),
            None => self.error(path, "RPM truncated; payload not scanned".into()),
        }
    }

    fn scan_cpio(&mut self, data: &[u8], path: &str, depth: u32) {
        let field = |h: &[u8], k: usize| -> Option<usize> {
            h.get(6 + 8 * k..14 + 8 * k)?
                .iter()
                .try_fold(0usize, |acc, &c| Some(acc * 16 + hex_val(c)? as usize))
        };
        let align = |x: usize| (x + 3) & !3;
        let mut pos = 0usize;
        while let Some(h) = data.get(pos..pos + 110) {
            if !(h.starts_with(b"070701") || h.starts_with(b"070702")) {
                self.error(
                    path,
                    format!("cpio header malformed at byte {pos}; rest not scanned"),
                );
                return;
            }
            let (Some(mode), Some(fsize), Some(nsize)) = (field(h, 1), field(h, 6), field(h, 11))
            else {
                self.error(path, format!("cpio header unreadable at byte {pos}"));
                return;
            };
            let name_start = pos + 110;
            let name = data
                .get(name_start..name_start + nsize.saturating_sub(1))
                .map(|n| String::from_utf8_lossy(n).into_owned())
                .unwrap_or_default();
            if name == "TRAILER!!!" {
                return;
            }
            if !self.take_entry(path) {
                return;
            }
            let body_start = align(name_start + nsize);
            let Some(body) = data.get(body_start..body_start + fsize) else {
                self.error(path, format!("cpio member {name:?} truncated"));
                return;
            };
            if mode & 0o170000 == 0o100000 && fsize > 0 {
                self.scan_blob(body, &format!("{path}:{name}"), depth + 1);
            }
            pos = align(body_start + fsize);
        }
    }

    /// Non-container data: PEM blocks, raw DER, base64 runs, text references.
    fn leaf(&mut self, data: &[u8], path: &str, depth: u32) {
        // Opaque formats: raw bytes are still scanned, but a clean result proves nothing.
        let opaque: Option<String> = if detect::has_squashfs(data) {
            Some("SquashFS image (AppImage or snap): compressed filesystem not unpacked; extract it (`./App.AppImage --appimage-extract` or `unsquashfs`) and scan the folder with -p".into())
        } else if let Some(kind) = detect::installer_kind(data) {
            Some(format!("{kind}: compressed payload not unpacked; extract it (`7z x`, or `innoextract` for Inno Setup) or install it and scan the install folder with -p"))
        } else if detect::is_ole2(data) {
            Some("OLE2/MSI compound file: compressed streams are not unpacked; raw bytes scanned (extract with `msiextract` or `7z x` and scan the folder with -p)".into())
        } else if detect::is_dmg(data) {
            Some("Apple disk image: compressed partitions are not unpacked; raw bytes scanned (mount it and scan with -p for full coverage)".into())
        } else if detect::has_upx(data) {
            Some("UPX-packed binary: run `upx -d` for full coverage; raw bytes scanned".into())
        } else {
            None
        };
        let found_before = self.findings.len();
        trust::scan_markers(data, path, &mut self.trust);
        if !data.starts_with(b"PK") && detect::has_trailing_zip(data) {
            self.scan_zip(data, path, depth);
        }

        let blocks = pem::blocks(data);
        let mut prev_end = 0;
        let mut ranges = Vec::with_capacity(blocks.len());
        for b in &blocks {
            ranges.push((b.start, b.end));
            let pre = &data[prev_end.min(b.start)..b.start];
            prev_end = b.end;
            let plain = pem::decode(b.body);
            // Quoted/commented lines can still "decode" (`+` is base64) into garbage.
            let commented = if plain.as_ref().is_ok_and(|d| der::cert_span(d).is_some()) {
                None
            } else {
                pem::decode_commented(b.body).filter(|d| der::cert_span(d).is_some())
            };
            if let Some(bytes) = commented {
                let label = String::from_utf8_lossy(b.label);
                let source = format!("PEM {label} (comment or string)");
                self.scan_der_bytes(&bytes, path, &source, None);
                continue;
            }
            match plain {
                Ok(bytes) => {
                    let mut source = format!("PEM {}", String::from_utf8_lossy(b.label));
                    let mut ctx = None;
                    if memchr::memmem::find(pre, b"x-distrusted: true").is_some() {
                        ctx = Some(Context::Distrust);
                    } else if b.label == b"TRUSTED CERTIFICATE" {
                        if let Some(aux) = der::trusted_aux(&bytes) {
                            if let Some(t) = &aux.trusted {
                                source.push_str(&format!(" (trusted for: {})", t.join(", ")));
                            }
                            if !aux.allows_relevant_use() {
                                ctx = Some(Context::Restricted);
                            }
                        }
                    }
                    self.scan_der_bytes(&bytes, path, &source, ctx);
                }
                Err(_) if pem::looks_like_pem_body(b.body) => {
                    let msg = format!(
                        "malformed PEM block at byte {} skipped; other blocks scanned",
                        b.start
                    );
                    self.warn(path, msg);
                }
                Err(_) => {}
            }
        }

        let source = if detect::is_asar(data) {
            "Electron .asar"
        } else if data.starts_with(&[0xfe, 0xed, 0xfe, 0xed]) {
            "Java KeyStore"
        } else {
            "DER/binary"
        };
        self.scan_der_bytes(data, path, source, None);

        for (off, run) in pem::base64_runs(data, MIN_B64_RUN, &ranges) {
            let Ok(dec) = pem::decode(run) else { continue };
            if dec.len() as u64 > self.decompressed_left {
                self.budget_exhausted(path);
                break;
            }
            self.decompressed_left -= dec.len() as u64;
            self.scan_blob(&dec, &format!("{path}@base64:{off}"), depth + 1);
        }

        if !data[..data.len().min(8192)].contains(&0) {
            // Keys and certificates compiled in as byte literals (webpki-roots, C/Go tables).
            let mut blobs = literal::escaped_strings(data);
            blobs.extend(literal::numeric_arrays(data));
            for (off, bytes) in blobs {
                if bytes.len() as u64 > self.decompressed_left {
                    self.budget_exhausted(path);
                    break;
                }
                self.decompressed_left -= bytes.len() as u64;
                let p = format!("{path}@literal:{off}");
                self.scan_der_bytes(&bytes, &p, "byte literal in source", None);
            }
            // References are informational; only look for them in text.
            self.scan_hex_refs(data, path);
        }
        if is_source_name(basename(path)) {
            if let Some(kw) = self.profile.first_keyword(data) {
                let cert = format!("CA name \"{kw}\"");
                self.push(
                    path,
                    "text",
                    cert,
                    None,
                    Kind::Reference,
                    Match::Keyword,
                    None,
                );
            }
        }
        if der::is_encrypted_pkcs12(data) && self.findings.len() == found_before {
            self.error(
                path,
                "password-protected PKCS#12: encrypted certificate bags not inspected".into(),
            );
        }
        self.apply_key_blocklist(data, path, found_before);
        for i in found_before..self.findings.len() {
            let f = &self.findings[i];
            let root = matches!(
                f.kind,
                Kind::DistrustedRoot | Kind::CrossSignRoot | Kind::InfoRoot
            );
            if root && f.matched == Match::PublicKey && f.sha256.is_none() {
                let note = format!("known root trust anchor ({})", f.cert);
                self.trust.add_bundle(note);
            }
            if f.context == Context::Distrust {
                let note = format!("distrust location {}", f.path);
                self.trust.add_blocklist(note);
            }
            if f.matched == Match::Blocklist {
                let note = format!("{} ({})", f.cert, f.path);
                self.trust.add_blocklist(note);
            }
        }
        if let Some(msg) = opaque {
            if self.findings.len() == found_before {
                self.error(path, msg);
            } else {
                self.warn(path, msg);
            }
        }
    }

    /// A blob that blocks every compromised TLS key (Chromium/Go SPKI-hash list,
    /// rustls-webpki bare SPKIs, or OneCRL issuer+serial entries) rejects those chains,
    /// so the same blob's root and compromised-CA hits stop needing action.
    fn apply_key_blocklist(&mut self, data: &[u8], path: &str, from: usize) {
        let c = self
            .profile
            .blocked_keys(data, |s, e| enclosing_cert(data, s, e).is_none());
        let (blocked, total) = (c.count(), c.total());
        if blocked == 0 {
            return;
        }
        // TLS-only coverage is accepted from OneCRL (NSS clients do not verify code
        // signatures); hash and bare-key lists must cover all keys.
        let mitigates = c.complete() || (c.tls_complete() && c.by_serial.contains(&true));
        let needs_action = self.findings[from..].iter().any(|f| f.action_required);
        if !mitigates && !needs_action {
            return;
        }
        if mitigates {
            for f in &mut self.findings[from..] {
                if chain_kind(f.kind) && f.action_required {
                    f.context = Context::KeyBlocklist;
                    f.action_required = false;
                }
            }
            if c.by_serial.contains(&true) {
                self.onecrl.push(path.to_string());
            }
        }
        let mut forms = Vec::new();
        if c.by_hash.contains(&true) {
            forms.push("SPKI SHA-256");
        }
        if c.by_der.contains(&true) {
            forms.push("bare-SPKI (as in rustls-webpki)");
        }
        if c.by_serial.contains(&true) {
            forms.push("issuer+serial (OneCRL)");
        }
        let form = format!("{} blocklist", forms.join(" and "));
        let cert = if c.complete() {
            format!("{form} covering all {total} compromised keys")
        } else if mitigates {
            let tls = c.tls.iter().filter(|&&t| t).count();
            format!("{form} covering all {tls} TLS keys (the code-signing keys are not listed; matters only for code-signature verification)")
        } else {
            format!("partial {form}: {blocked} of {total} compromised keys (not a mitigation)")
        };
        self.push(
            path,
            "DER/binary",
            cert,
            None,
            Kind::Reference,
            Match::Blocklist,
            None,
        );
    }

    /// Exact-certificate hashes plus key / SKI needles over DER-ish bytes.
    fn scan_der_bytes(&mut self, bytes: &[u8], path: &str, source: &str, ctx: Option<Context>) {
        let profile = self.profile;
        let mut matched: Vec<(usize, usize)> = Vec::new();
        let mut skip_until = 0;
        for i in memchr::memchr_iter(0x30, bytes) {
            if i < skip_until {
                continue;
            }
            let Some(total) = der::cert_span(&bytes[i..]) else {
                continue;
            };
            self.note_cert(&bytes[i..i + total], path);
            if !profile.wants_len(total) {
                continue;
            }
            if self.hash_left < total as u64 {
                if self.first(Once::Hash) {
                    self.error(path, "certificate-candidate hashing budget exhausted; rest of the data not checked".into());
                }
                break;
            }
            self.hash_left -= total as u64;
            let fp = sha256(&bytes[i..i + total]);
            if let Some(t) = profile.lookup(&fp) {
                self.push(
                    path,
                    source,
                    t.name.clone(),
                    Some(fp),
                    t.role.into(),
                    Match::Certificate,
                    ctx,
                );
                matched.push((i, i + total));
                skip_until = i + total;
            }
        }

        for (ni, s, e) in profile.needle_hits(bytes) {
            if matched.iter().any(|&(a, b)| s >= a && e <= b) {
                continue;
            }
            let needle = &profile.needles()[ni];
            let target = &profile.targets[needle.targets[0]];
            let enclosing = enclosing_cert(bytes, s, e);
            match (needle.kind, enclosing) {
                (NeedleKind::Key, Some((a, b))) => {
                    matched.push((a, b));
                    let fp = sha256(&bytes[a..b]);
                    if profile.lookup(&fp).is_some() {
                        continue;
                    }
                    let subject = cert_cn(&bytes[a..b]);
                    let cert =
                        format!("{subject}, which carries the public key of {}", target.name);
                    self.push(
                        path,
                        source,
                        cert,
                        Some(fp),
                        target.role.into(),
                        Match::PublicKey,
                        ctx,
                    );
                }
                (NeedleKind::Key, None) => {
                    let cert = format!(
                        "public key of {} outside any certificate (e.g. a trust-anchor list)",
                        target.name
                    );
                    self.push(
                        path,
                        source,
                        cert,
                        None,
                        target.role.into(),
                        Match::PublicKey,
                        ctx,
                    );
                }
                (NeedleKind::Ski, Some((a, b))) => {
                    let Ok((_, c)) = X509Certificate::from_der(&bytes[a..b]) else {
                        continue;
                    };
                    let n = needle.bytes.as_slice();
                    if authority_key_id(&c) != Some(n) || subject_key_id(&c) == Some(n) {
                        continue;
                    }
                    matched.push((a, b));
                    let fp = sha256(&bytes[a..b]);
                    if profile.lookup(&fp).is_some() {
                        continue;
                    }
                    let subject = first_cn(c.subject()).unwrap_or_else(|| "certificate".into());
                    let issuer = target
                        .name
                        .split(" (issued by")
                        .next()
                        .unwrap_or(&target.name);
                    let cert = format!("{subject} (issued by compromised {issuer})");
                    self.push(
                        path,
                        source,
                        cert,
                        Some(fp),
                        Kind::IssuedByCompromised,
                        Match::AuthorityKeyId,
                        ctx,
                    );
                }
                (NeedleKind::Ski, None) => {}
            }
        }
    }

    /// SHA-256 fingerprints written as hex (optionally colon-separated) in text.
    fn scan_hex_refs(&mut self, data: &[u8], path: &str) {
        let profile = self.profile;
        let mut i = 0;
        while i < data.len() {
            if CLASS[data[i] as usize] & HEX_OR_COLON == 0 {
                i += 1;
                continue;
            }
            let s = i;
            let mut digits = 0usize;
            while i < data.len() && CLASS[data[i] as usize] & HEX_OR_COLON != 0 {
                digits += (data[i] != b':') as usize;
                i += 1;
            }
            if digits < 64 {
                continue;
            }
            let ds: Vec<u8> = data[s..i].iter().filter_map(|&c| hex_val(c)).collect();
            let mut windows = vec![&ds[..64]];
            if ds.len() > 64 {
                windows.push(&ds[ds.len() - 64..]);
            }
            for w in windows {
                let mut fp = [0u8; 32];
                for (k, pair) in w.chunks(2).enumerate() {
                    fp[k] = (pair[0] << 4) | pair[1];
                }
                if let Some(t) = profile.lookup(&fp) {
                    // Bundle comments ("# SHA256 Fingerprint: ...") next to the cert itself.
                    let hexfp = hex(&fp);
                    if self.findings.iter().any(|f| {
                        (f.path == path || f.path.starts_with(&format!("{path}@")))
                            && f.sha256.as_deref() == Some(&hexfp)
                    }) {
                        continue;
                    }
                    let cert = format!("fingerprint of {}", t.name);
                    self.push(
                        path,
                        "text",
                        cert,
                        Some(fp),
                        Kind::Reference,
                        Match::FingerprintText,
                        None,
                    );
                }
            }
        }
    }
}

fn chain_kind(k: Kind) -> bool {
    matches!(
        k,
        Kind::DistrustedRoot | Kind::CrossSignRoot | Kind::Compromised | Kind::IssuedByCompromised
    )
}

/// NSS's built-in root module (Firefox, Thunderbird) consults OneCRL.
const NSS_BUILTINS: &[&str] = &[
    "libxul.so",
    "XUL",
    "xul.dll",
    "libnssckbi.so",
    "libnssckbi.dylib",
    "nssckbi.dll",
];
/// Path components of a scan path (archive members are joined with ':').
fn segments(p: &str) -> Vec<&str> {
    p.split(['/', '\\', ':'])
        .filter(|s| !s.is_empty() && *s != ".")
        .collect()
}

/// Whether `list` lies inside the application folder of the NSS module at `nss`:
/// the module's own folder, or `Contents` for a macOS bundle (`Contents/MacOS/XUL`).
fn same_app_dir(list: &str, nss: &str) -> bool {
    let (l, n) = (segments(list), segments(nss));
    let nss_dir = &n[..n.len().saturating_sub(1)];
    let anchor = match nss_dir.last() {
        Some(&"MacOS") => &nss_dir[..nss_dir.len() - 1],
        _ => nss_dir,
    };
    !anchor.is_empty() && l.len() > anchor.len() && l.starts_with(anchor)
}

/// A complete OneCRL list mitigates NSS built-in roots of the same application.
pub fn mitigate_nss_with_onecrl(findings: &mut [Finding], onecrl: &[String]) {
    if onecrl.is_empty() {
        return;
    }
    for f in findings
        .iter_mut()
        .filter(|f| f.action_required && chain_kind(f.kind))
    {
        let file = f.path.rsplit(['/', '\\', ':']).next().unwrap_or(&f.path);
        if NSS_BUILTINS.contains(&file) && onecrl.iter().any(|l| same_app_dir(l, &f.path)) {
            f.context = Context::KeyBlocklist;
            f.action_required = false;
        }
    }
}

#[cfg(test)]
mod onecrl_scope_tests {
    use super::same_app_dir;

    #[test]
    fn tp_firefox_layouts() {
        assert!(same_app_dir(
            "ff.tar.xz:firefox/browser/omni.ja:defaults/settings/security-state/onecrl.json",
            "ff.tar.xz:firefox/libxul.so"
        ));
        assert!(same_app_dir(
            "/Applications/Firefox.app/Contents/Resources/browser/omni.ja:x/onecrl.json",
            "/Applications/Firefox.app/Contents/MacOS/XUL"
        ));
        assert!(same_app_dir(
            "C:\\Program Files\\Mozilla Firefox\\browser\\omni.ja:x/onecrl.json",
            "C:\\Program Files\\Mozilla Firefox\\xul.dll"
        ));
    }

    #[test]
    fn fp_neighbouring_apps_and_other_bundles() {
        assert!(!same_app_dir(
            "/opt/apps/a/browser/omni.ja:x/onecrl.json",
            "/opt/apps/b/libxul.so"
        ));
        assert!(!same_app_dir(
            "/Applications/Other.app/Contents/Resources/omni.ja:x",
            "/Applications/Firefox.app/Contents/MacOS/XUL"
        ));
        assert!(!same_app_dir("onecrl.json", "libxul.so"));
    }
}

fn cert_cn(der: &[u8]) -> String {
    X509Certificate::from_der(der)
        .ok()
        .and_then(|(_, c)| first_cn(c.subject()))
        .unwrap_or_else(|| "certificate".into())
}

/// The closest certificate-shaped span that starts before `s`, covers `[s, e)`, and parses.
fn enclosing_cert(bytes: &[u8], s: usize, e: usize) -> Option<(usize, usize)> {
    let lo = s.saturating_sub(ENCLOSING_WINDOW);
    for j in memchr::memrchr_iter(0x30, &bytes[lo..s]) {
        let j = lo + j;
        if let Some(total) = der::cert_span(&bytes[j..]) {
            if j + total >= e && X509Certificate::from_der(&bytes[j..j + total]).is_ok() {
                return Some((j, j + total));
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const TARGET: &[u8] = include_bytes!("../certs/emudhra/EM_DV_TLS_CA_G3B_emSign.der");

    fn gz(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// (findings, issues) for `data` scanned with `limits`.
    fn run(profile: &Profile, limits: &Limits, data: &[u8]) -> (usize, Vec<Issue>) {
        let mut fs = FileScan::new(profile, limits, Context::Trust, data.len() as u64);
        fs.scan(data, "t");
        (fs.findings.len(), fs.issues)
    }

    fn header_tiling() -> Vec<u8> {
        let mut data = Vec::new();
        for _ in 0..4096 {
            data.extend_from_slice(&[0x30, 0x82, 0x1f, 0xfc, 0x30, 0x82, 0x1f, 0xf8]);
        }
        data.resize(64 << 10, 0);
        data
    }

    #[test]
    fn p03_tp_bomb_is_limited_and_partial_output_scanned() {
        let p = Profile::emudhra().unwrap();
        let limits = Limits {
            max_decompressed: 1 << 20,
            ..Limits::default()
        };
        let mut plain = TARGET.to_vec();
        plain.extend(vec![0u8; 8 << 20]);
        let (found, issues) = run(&p, &limits, &gz(&gz(&plain)));
        assert_eq!(found, 1, "target in the first MiB must still be found");
        assert!(issues
            .iter()
            .any(|i| i.severity == Severity::Error && i.message.contains("budget")));
    }

    fn bz(data: &[u8]) -> Vec<u8> {
        let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn n09_tp_bzip2_bomb_is_limited_and_partial_output_scanned() {
        let p = Profile::emudhra().unwrap();
        let limits = Limits {
            max_decompressed: 1 << 20,
            ..Limits::default()
        };
        let mut plain = TARGET.to_vec();
        plain.extend(vec![0u8; 8 << 20]);
        let (found, issues) = run(&p, &limits, &bz(&bz(&plain)));
        assert_eq!(found, 1, "target in the first MiB must still be found");
        assert!(issues
            .iter()
            .any(|i| i.severity == Severity::Error && i.message.contains("budget")));
    }

    #[test]
    fn n09_fp_bzip2_under_budget_no_error() {
        let p = Profile::emudhra().unwrap();
        let mut plain = b"no certificates here\n".to_vec();
        plain.extend(vec![0u8; 1 << 20]);
        let (found, issues) = run(&p, &Limits::default(), &bz(&plain));
        assert_eq!(found, 0);
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn p03_fp_under_budget_no_error() {
        let p = Profile::emudhra().unwrap();
        let limits = Limits {
            max_decompressed: 16 << 20,
            ..Limits::default()
        };
        let mut plain = TARGET.to_vec();
        plain.extend(vec![0u8; 1 << 20]);
        let (found, issues) = run(&p, &limits, &gz(&plain));
        assert_eq!(found, 1);
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn p12_tp_hash_amplification_is_limited() {
        let mut p = Profile::new("custom");
        p.add_fingerprint(&"ab".repeat(32), crate::profile::Role::Compromised)
            .unwrap();
        p.finalize();
        let limits = Limits {
            hash_budget_base: 1 << 20,
            ..Limits::default()
        };
        // Nested cert-shaped headers: every offset is a ~8 KiB candidate.
        let (_, issues) = run(&p, &limits, &header_tiling());
        assert!(issues.iter().any(|i| i.message.contains("hashing budget")));
    }

    #[test]
    fn p12_fp_known_length_targets_skip_hashing() {
        let p = Profile::emudhra().unwrap();
        let limits = Limits {
            hash_budget_base: 1 << 20,
            ..Limits::default()
        };
        let (found, issues) = run(&p, &limits, &header_tiling());
        assert_eq!(found, 0);
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn trusted_aux_purposes() {
        let pem = include_str!("../tests/data/trusted_g3_email.pem");
        let b = &pem::blocks(pem.as_bytes())[0];
        let aux = der::trusted_aux(&pem::decode(b.body).unwrap()).unwrap();
        assert_eq!(aux.trusted.as_deref(), Some(&["email"][..]));
        assert!(!aux.allows_relevant_use());
        let pem = include_str!("../tests/data/trusted_g3_tls.pem");
        let b = &pem::blocks(pem.as_bytes())[0];
        assert!(der::trusted_aux(&pem::decode(b.body).unwrap())
            .unwrap()
            .allows_relevant_use());
        let pem = include_str!("../tests/data/trusted_g3_rejected.pem");
        let b = &pem::blocks(pem.as_bytes())[0];
        assert!(!der::trusted_aux(&pem::decode(b.body).unwrap())
            .unwrap()
            .allows_relevant_use());
    }
}
