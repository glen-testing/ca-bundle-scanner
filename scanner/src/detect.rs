//! Container / format sniffing by magic bytes.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Container {
    Zip,
    Gzip,
    Xz,
    Zstd,
    Bzip2,
    Tar,
    Ar,
    Rpm,
    Cpio,
}

pub fn container(data: &[u8]) -> Option<Container> {
    let starts = |m: &[u8]| data.starts_with(m);
    if starts(b"PK\x03\x04") || starts(b"PK\x05\x06") || starts(b"PK\x07\x08") {
        Some(Container::Zip)
    } else if starts(&[0x1f, 0x8b]) {
        Some(Container::Gzip)
    } else if starts(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        Some(Container::Xz)
    } else if starts(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Some(Container::Zstd)
    } else if is_bzip2(data) {
        Some(Container::Bzip2)
    } else if data.len() > 262 && &data[257..262] == b"ustar" {
        Some(Container::Tar)
    } else if starts(b"!<arch>\n") {
        Some(Container::Ar)
    } else if starts(&[0xed, 0xab, 0xee, 0xdb]) {
        Some(Container::Rpm)
    } else if starts(b"070701") || starts(b"070702") {
        Some(Container::Cpio)
    } else {
        None
    }
}

fn is_bzip2(data: &[u8]) -> bool {
    data.len() >= 10
        && data.starts_with(b"BZh")
        && (b'1'..=b'9').contains(&data[3])
        && data[4..10] == [0x31, 0x41, 0x59, 0x26, 0x53, 0x59]
}

/// A ZIP end-of-central-directory record near the end, with data before the
/// first local header (self-extractors, Spring Boot executable JARs).
pub fn has_trailing_zip(data: &[u8]) -> bool {
    let tail_start = data.len().saturating_sub(22 + 65535);
    memchr::memmem::rfind(&data[tail_start..], b"PK\x05\x06").is_some()
}

/// Apple disk image trailer: "koly" magic, version 4, header size 512, at len-512.
pub fn is_dmg(data: &[u8]) -> bool {
    if data.len() < 512 {
        return false;
    }
    let t = &data[data.len() - 512..];
    t.starts_with(b"koly") && t[4..8] == [0, 0, 0, 4] && t[8..12] == [0, 0, 2, 0]
}

/// OLE2 compound file (MSI installers, legacy Office documents).
pub fn is_ole2(data: &[u8]) -> bool {
    data.starts_with(&[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1])
}

pub fn has_upx(data: &[u8]) -> bool {
    memchr::memmem::find(&data[..data.len().min(4096)], b"UPX!").is_some()
}

/// Electron .asar: 4-byte pickle size (always 4), header size, then JSON `{"files"`.
pub fn is_asar(data: &[u8]) -> bool {
    data.len() > 24
        && data[..4] == [4, 0, 0, 0]
        && data[16] == b'{'
        && memchr::memmem::find(&data[16..data.len().min(16 + 64)], b"\"files\"").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dmg_needs_full_trailer() {
        let mut v = vec![0u8; 1024];
        v.extend_from_slice(b"koly");
        assert!(!is_dmg(&v), "bare 'koly' near the end must not count");
        let mut d = vec![0u8; 1024];
        let mut t = vec![0u8; 512];
        t[..4].copy_from_slice(b"koly");
        t[4..8].copy_from_slice(&[0, 0, 0, 4]);
        t[8..12].copy_from_slice(&[0, 0, 2, 0]);
        d.extend_from_slice(&t);
        assert!(is_dmg(&d));
    }

    #[test]
    fn asar_detected_and_plain_json_not() {
        let mut a = vec![4, 0, 0, 0, 0x20, 0, 0, 0, 0x1c, 0, 0, 0, 0x18, 0, 0, 0];
        a.extend_from_slice(b"{\"files\":{\"a\":{}}}        ");
        assert!(is_asar(&a));
        assert!(!is_asar(
            b"{\"files\":{}}                                  "
        ));
    }

    #[test]
    fn container_magic() {
        assert_eq!(container(b"PK\x03\x04rest"), Some(Container::Zip));
        assert_eq!(container(b"070701000"), Some(Container::Cpio));
        assert_eq!(container(b"BZh9notblock"), None);
        assert_eq!(container(b"plain text"), None);
    }

    #[test]
    fn trailing_zip() {
        let mut v = b"#!/bin/sh\nexec java -jar $0\n".to_vec();
        v.extend_from_slice(b"PK\x05\x06");
        v.extend_from_slice(&[0u8; 18]);
        assert!(has_trailing_zip(&v));
        assert!(!has_trailing_zip(b"no zip here"));
    }
}
