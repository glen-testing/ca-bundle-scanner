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
    } else if is_gzip(data) {
        Some(Container::Gzip)
    } else if starts(&[0xfd, b'7', b'z', b'X', b'Z', 0x00]) {
        Some(Container::Xz)
    } else if starts(&[0x28, 0xb5, 0x2f, 0xfd]) {
        Some(Container::Zstd)
    } else if is_bzip2(data) {
        Some(Container::Bzip2)
    } else if is_tar(data) {
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

/// gzip member header (RFC 1952): magic, CM = 8 (deflate), reserved FLG bits clear.
/// The two magic bytes alone occur by chance in binary data.
pub fn is_gzip(data: &[u8]) -> bool {
    data.len() >= 18 && data[..3] == [0x1f, 0x8b, 0x08] && data[3] & 0xe0 == 0
}

/// POSIX/GNU tar: "ustar" magic plus a valid header checksum, so text that happens
/// to hold "ustar" at offset 257 (tar libraries, JSON) is not taken for an archive.
fn is_tar(data: &[u8]) -> bool {
    let Some(h) = data.get(..512) else {
        return false;
    };
    if &h[257..262] != b"ustar" {
        return false;
    }
    let digits: Vec<u8> = h[148..156]
        .iter()
        .copied()
        .skip_while(|&b| b == b' ')
        .take_while(u8::is_ascii_digit)
        .collect();
    if digits.is_empty() || digits.iter().any(|&d| d > b'7') {
        return false;
    }
    let stored = digits
        .iter()
        .fold(0u32, |a, &d| (a << 3) | (d - b'0') as u32);
    let sum: u32 = h
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if (148..156).contains(&i) {
                b' ' as u32
            } else {
                b as u32
            }
        })
        .sum();
    stored == sum
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

/// SquashFS v4 superblock (snap packages; AppImages carry one after an ELF runtime).
pub fn has_squashfs(data: &[u8]) -> bool {
    let window = &data[..data.len().min(16 << 20)];
    memchr::memmem::find_iter(window, b"hsqs").any(|o| {
        let Some(sb) = data.get(o..o + 32) else {
            return false;
        };
        let u16_at = |i: usize| u16::from_le_bytes([sb[i], sb[i + 1]]);
        let block = u32::from_le_bytes([sb[12], sb[13], sb[14], sb[15]]);
        (1..=6).contains(&u16_at(20))
            && u16_at(28) == 4
            && block.is_power_of_two()
            && (4096..=1 << 20).contains(&block)
            && 1u32.checked_shl(u16_at(22) as u32) == Some(block)
    })
}

/// Installer formats whose payload is compressed with schemes this scanner does not unpack.
/// Requires a Windows executable plus the format's own header, so tools that merely
/// mention the signatures (7-Zip, innoextract) are not mistaken for installers.
pub fn installer_kind(data: &[u8]) -> Option<&'static str> {
    if !data.starts_with(b"MZ") {
        return None;
    }
    // NSIS first header: u32 flags, 0xDEADBEEF, "NullsoftInst", on a 512-byte boundary.
    let nsis =
        memchr::memmem::find_iter(data, b"\xef\xbe\xad\xdeNullsoftInst").any(|o| o % 512 == 4);
    if nsis {
        return Some("NSIS installer");
    }
    let sig = b"Inno Setup Setup Data (";
    let inno = memchr::memmem::find_iter(data, sig)
        .any(|o| data.get(o + sig.len()).is_some_and(u8::is_ascii_digit));
    inno.then_some("Inno Setup installer")
}

/// UPX stub marker in the first 4 KiB of an executable (PE, ELF or Mach-O). Source
/// files and tools that only mention "UPX!" are not packed binaries.
pub fn has_upx(data: &[u8]) -> bool {
    const EXE: &[&[u8]] = &[
        b"MZ",
        b"\x7fELF",
        &[0xfe, 0xed, 0xfa, 0xce],
        &[0xfe, 0xed, 0xfa, 0xcf],
        &[0xce, 0xfa, 0xed, 0xfe],
        &[0xcf, 0xfa, 0xed, 0xfe],
    ];
    EXE.iter().any(|m| data.starts_with(m))
        && memchr::memmem::find(&data[..data.len().min(4096)], b"UPX!").is_some()
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
    fn installers_and_squashfs() {
        let mut nsis = b"MZ".to_vec();
        nsis.resize(512, 0);
        nsis.extend_from_slice(&[0, 0, 0, 0]);
        nsis.extend_from_slice(b"\xef\xbe\xad\xdeNullsoftInst");
        assert_eq!(installer_kind(&nsis), Some("NSIS installer"));
        // fp: same bytes off the 512-byte boundary, or without an MZ header (e.g. inside 7-Zip).
        let mut off = b"MZ".to_vec();
        off.resize(700, 0);
        off.extend_from_slice(b"\xef\xbe\xad\xdeNullsoftInst");
        assert_eq!(installer_kind(&off), None);
        assert_eq!(installer_kind(&nsis[2..]), None);
        assert_eq!(
            installer_kind(b"MZ...Inno Setup Setup Data (6.2.0)"),
            Some("Inno Setup installer")
        );
        assert_eq!(installer_kind(b"MZ...Inno Setup Setup Data (%s"), None);

        let mut sq = vec![0u8; 64];
        sq[..4].copy_from_slice(b"hsqs");
        sq[12..16].copy_from_slice(&131072u32.to_le_bytes());
        sq[20..22].copy_from_slice(&6u16.to_le_bytes()); // zstd
        sq[22..24].copy_from_slice(&17u16.to_le_bytes());
        sq[28..30].copy_from_slice(&4u16.to_le_bytes());
        let mut appimage = b"\x7fELF".to_vec();
        appimage.resize(4096, 0);
        appimage.extend_from_slice(&sq);
        assert!(has_squashfs(&appimage));
        // fp: the magic alone, or with an inconsistent block size.
        assert!(!has_squashfs(
            b"....hsqs........................................"
        ));
        sq[22..24].copy_from_slice(&16u16.to_le_bytes());
        assert!(!has_squashfs(&sq));
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

    #[test]
    fn gzip_and_tar_need_valid_headers() {
        let mut gz = vec![0x1f, 0x8b, 0x08, 0x00];
        gz.resize(32, 0);
        assert!(is_gzip(&gz));
        assert!(!is_gzip(&[
            0x1f, 0x8b, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
        ]));
        let mut bad_flags = gz.clone();
        bad_flags[3] = 0x20;
        assert!(!is_gzip(&bad_flags));

        let mut h = vec![0u8; 1024];
        h[..6].copy_from_slice(b"ca.pem");
        h[257..263].copy_from_slice(b"ustar\0");
        let sum: u32 = h[..512].iter().map(|&b| b as u32).sum::<u32>() + 8 * b' ' as u32;
        h[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
        h[155] = b' ';
        assert_eq!(container(&h), Some(Container::Tar));
        h[0] ^= 1;
        assert_eq!(container(&h), None, "checksum mismatch is not tar");
    }

    #[test]
    fn upx_needs_an_executable() {
        let mut exe = b"\x7fELF".to_vec();
        exe.extend_from_slice(b"....UPX!");
        assert!(has_upx(&exe));
        assert!(!has_upx(b"// matches b\"UPX!\" in the first 4 KiB"));
    }
}
