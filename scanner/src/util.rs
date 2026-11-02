//! Small helpers shared by the scanner modules.

use sha2::{Digest, Sha256};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 15) as usize] as char);
    }
    s
}

/// Byte classes for the hot scanning loops: base64 alphabet (incl. '='), hex digit or ':'.
pub const B64: u8 = 1;
pub const HEX_OR_COLON: u8 = 2;
pub static CLASS: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut c = 0;
    while c < 256 {
        let b = c as u8;
        if b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' {
            t[c] |= B64;
        }
        if b.is_ascii_hexdigit() || b == b':' {
            t[c] |= HEX_OR_COLON;
        }
        c += 1;
    }
    t
};

pub fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Parse a SHA-256 fingerprint; colons and whitespace are ignored, any other non-hex rejects.
pub fn parse_hex32(raw: &str) -> Option<[u8; 32]> {
    let digits: Vec<u8> = raw
        .bytes()
        .filter(|c| *c != b':' && !c.is_ascii_whitespace())
        .map(hex_val)
        .collect::<Option<_>>()?;
    if digits.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in digits.chunks(2).enumerate() {
        out[i] = (pair[0] << 4) | pair[1];
    }
    Some(out)
}

/// Last path component of a scan path (archive entries are joined with ':').
pub fn basename(path: &str) -> &str {
    path.rsplit(['/', '\\', ':']).next().unwrap_or(path)
}

/// File extensions treated as source/config text for CA-name keyword hints.
pub fn is_source_name(name: &str) -> bool {
    const EXTS: &[&str] = &[
        "go",
        "rs",
        "c",
        "h",
        "cpp",
        "cc",
        "cxx",
        "py",
        "js",
        "mjs",
        "cjs",
        "ts",
        "tsx",
        "jsx",
        "java",
        "rb",
        "cs",
        "swift",
        "kt",
        "scala",
        "php",
        "json",
        "yaml",
        "yml",
        "toml",
        "xml",
        "conf",
        "cfg",
        "ini",
        "properties",
        "tf",
        "hcl",
        "gradle",
    ];
    match name.rsplit_once('.') {
        Some((_, ext)) => EXTS.iter().any(|e| e.eq_ignore_ascii_case(ext)),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let fp = sha256(b"abc");
        assert_eq!(parse_hex32(&hex(&fp)), Some(fp));
        let colon: String = hex(&fp)
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap().to_uppercase())
            .collect::<Vec<_>>()
            .join(":");
        assert_eq!(parse_hex32(&colon), Some(fp));
    }

    #[test]
    fn hex_rejects_bad() {
        assert_eq!(parse_hex32("abc"), None);
        assert_eq!(parse_hex32(&"g".repeat(64)), None);
        assert_eq!(parse_hex32(&"a".repeat(65)), None);
    }

    #[test]
    fn source_names() {
        assert!(is_source_name("main.RS"));
        assert!(is_source_name("x.yaml"));
        assert!(!is_source_name("cacert.pem"));
        assert!(!is_source_name("Makefile"));
    }

    #[test]
    fn basename_handles_archive_paths() {
        assert_eq!(basename("/a/b.jar:META-INF/x.json"), "x.json");
        assert_eq!(basename("C:\\x\\y.pem"), "y.pem");
    }
}
