//! Lenient PEM (Privacy-Enhanced Mail) block splitting and base64 decoding.
//! Each block is decoded on its own so one bad block never hides the others.

use memchr::memmem;

#[derive(Debug, Clone, Copy)]
pub struct Block<'a> {
    pub label: &'a [u8],
    /// Offset of `-----BEGIN`.
    pub start: usize,
    /// Offset just past the closing `-----END ...-----` (or the body end if unterminated).
    pub end: usize,
    pub body: &'a [u8],
    pub terminated: bool,
}

const BEGIN: &[u8] = b"-----BEGIN ";
const END: &[u8] = b"-----END ";
const DASHES: &[u8] = b"-----";

/// Every `-----BEGIN X-----` block. A BEGIN with no END before the next BEGIN
/// is returned unterminated (body up to that next BEGIN) so it cannot swallow it.
pub fn blocks(data: &[u8]) -> Vec<Block<'_>> {
    let begins: Vec<usize> = memmem::find_iter(data, BEGIN).collect();
    let mut out = Vec::with_capacity(begins.len());
    for (n, &start) in begins.iter().enumerate() {
        let label_start = start + BEGIN.len();
        let Some(label_len) =
            memmem::find(&data[label_start..data.len().min(label_start + 80)], DASHES)
        else {
            continue;
        };
        let label = &data[label_start..label_start + label_len];
        let body_start = label_start + label_len + DASHES.len();
        let limit = begins
            .get(n + 1)
            .copied()
            .unwrap_or(data.len())
            .max(body_start);
        let region = &data[body_start..limit];
        match memmem::find(region, END) {
            Some(e) => {
                let end_label = body_start + e + END.len();
                let close = memmem::find(&data[end_label..limit], DASHES)
                    .map(|d| end_label + d + DASHES.len())
                    .unwrap_or(limit);
                out.push(Block {
                    label,
                    start,
                    end: close,
                    body: &data[body_start..body_start + e],
                    terminated: true,
                });
            }
            None => out.push(Block {
                label,
                start,
                end: limit,
                body: region,
                terminated: false,
            }),
        }
    }
    out
}

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct DecodeError;

/// Decode a PEM body or base64 run. Whitespace, quotes, commas and
/// string escapes (`\n`, `\r`, `\t`, `\/`) are tolerated; anything else is an error.
pub fn decode(body: &[u8]) -> Result<Vec<u8>, DecodeError> {
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut pad = 0usize;
    let mut i = 0;
    while i < body.len() {
        let c = body[i];
        i += 1;
        if c == b'\\' {
            match body.get(i) {
                Some(b'n' | b'r' | b't') => i += 1,
                Some(b'/') => {}
                _ => return Err(DecodeError),
            }
            continue;
        }
        if c.is_ascii_whitespace() || c == b'"' || c == b',' {
            continue;
        }
        if c == b'=' {
            pad += 1;
            continue;
        }
        if pad > 0 {
            return Err(DecodeError);
        }
        let v = b64_val(c).ok_or(DecodeError)?;
        acc = (acc << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if pad > 2 || bits >= 6 {
        return Err(DecodeError);
    }
    Ok(out)
}

/// A body that is mostly base64 (as opposed to a PEM marker inside program text).
pub fn looks_like_pem_body(body: &[u8]) -> bool {
    let chars = body.iter().filter(|c| !c.is_ascii_whitespace()).count();
    let b64 = body
        .iter()
        .filter(|&&c| b64_val(c).is_some() || c == b'=')
        .count();
    chars >= 64 && b64 * 10 >= chars * 9
}

/// Runs of at least `min` base64 characters outside the given excluded ranges.
pub fn base64_runs<'a>(
    data: &'a [u8],
    min: usize,
    exclude: &[(usize, usize)],
) -> Vec<(usize, &'a [u8])> {
    use crate::util::{B64, CLASS};
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if CLASS[data[i] as usize] & B64 == 0 {
            i += 1;
            continue;
        }
        let s = i;
        while i < data.len() && CLASS[data[i] as usize] & B64 != 0 {
            i += 1;
        }
        if i - s >= min && !exclude.iter().any(|&(a, b)| s < b && i > a) {
            out.push((s, &data[s..i]));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const CERT: &str = "-----BEGIN CERTIFICATE-----\nTWFu\n-----END CERTIFICATE-----\n";

    #[test]
    fn decodes_plain_and_escaped() {
        assert_eq!(decode(b"TWFu").unwrap(), b"Man");
        assert_eq!(decode(b"TW\\nFu").unwrap(), b"Man");
        assert_eq!(decode(b"TWE=").unwrap(), b"Ma");
        assert_eq!(decode(b"TQ==").unwrap(), b"M");
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(decode(b"TW!u"), Err(DecodeError));
        assert_eq!(decode(b"T"), Err(DecodeError));
        assert_eq!(decode(b"TQ==TQ"), Err(DecodeError));
    }

    #[test]
    fn splits_blocks_and_keeps_good_after_bad() {
        let text =
            format!("{CERT}-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n{CERT}");
        let b = blocks(text.as_bytes());
        assert_eq!(b.len(), 3);
        assert!(decode(b[0].body).is_ok());
        assert!(decode(b[1].body).is_err());
        assert!(decode(b[2].body).is_ok());
    }

    #[test]
    fn unterminated_begin_does_not_swallow_next() {
        let text = format!("-----BEGIN CERTIFICATE-----\nTWFu\n{CERT}");
        let b = blocks(text.as_bytes());
        assert_eq!(b.len(), 2);
        assert!(!b[0].terminated);
        assert!(b[1].terminated);
        assert_eq!(decode(b[1].body).unwrap(), b"Man");
    }

    #[test]
    fn labels() {
        let text = "-----BEGIN TRUSTED CERTIFICATE-----\nTWFu\n-----END TRUSTED CERTIFICATE-----";
        assert_eq!(blocks(text.as_bytes())[0].label, b"TRUSTED CERTIFICATE");
    }

    #[test]
    fn base64_runs_respect_min_and_exclusions() {
        let data = b"xx AAAAAAAAAAAA yy BBBB";
        let runs = base64_runs(data, 10, &[]);
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].1, b"AAAAAAAAAAAA");
        assert!(base64_runs(data, 10, &[(0, data.len())]).is_empty());
    }
}
