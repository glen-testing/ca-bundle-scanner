//! Byte strings written as source-code literals: escaped strings (`b"\x30\x82..."`,
//! C/Go/Python `"\x.."` or octal `"\060"`) and numeric arrays (`0x30, 0x82`, `48, 130`,
//! Java `(byte) -126`). Compiled-in trust stores (webpki-roots, webpki-root-certs,
//! embedded C/Go roots) hold keys and certificates in these forms.

/// Shortest decoded literal worth scanning (a P-256 point is 65 bytes).
pub const MIN_LITERAL: usize = 64;
/// Longest single literal decoded; longer ones are cut off (keeps the scan linear).
const MAX_LITERAL: usize = 1 << 20;

/// (offset, bytes) for every string literal (or run of adjacent concatenated
/// literals) that contains at least one `\x` or octal escape.
pub fn escaped_strings(data: &[u8]) -> Vec<(usize, Vec<u8>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let q = data[i];
        let opens = q == b'"' || (q == b'\'' && i > 0 && data[i - 1] == b'b');
        // `'"'` is a char literal, not a string start.
        if !opens || (q == b'"' && i > 0 && data[i - 1] == b'\'' && data.get(i + 1) == Some(&b'\''))
        {
            i += 1;
            continue;
        }
        let start = i;
        let mut buf = Vec::new();
        let mut escaped = false;
        let mut j = i + 1;
        let mut quote = q;
        loop {
            let (end, closed, esc) = decode_one(data, j, quote, &mut buf);
            escaped |= esc;
            j = end;
            if !closed || buf.len() >= MAX_LITERAL {
                break;
            }
            // Adjacent literals: C/Python implicit concatenation, `+` in Go/Java/JS, `\` continuation.
            let mut k = j + 1;
            while k < data.len() && matches!(data[k], b' ' | b'\t' | b'\r' | b'\n' | b'+' | b'\\') {
                k += 1;
            }
            match data.get(k) {
                Some(&c) if c == b'"' || (c == b'\'' && k > 0 && data[k - 1] == b'b') => {
                    quote = c;
                    j = k + 1;
                }
                Some(&b'b') if matches!(data.get(k + 1), Some(b'"' | b'\'')) => {
                    quote = data[k + 1];
                    j = k + 2;
                }
                _ => break,
            }
        }
        if escaped && buf.len() >= MIN_LITERAL {
            out.push((start, buf));
        }
        i = j.max(i + 1) + 1;
    }
    out
}

/// Decode one literal body starting at `j`; returns (index of the closing quote or
/// where decoding stopped, whether it closed, whether any byte escape was seen).
fn decode_one(data: &[u8], mut j: usize, quote: u8, buf: &mut Vec<u8>) -> (usize, bool, bool) {
    let mut escaped = false;
    while j < data.len() && buf.len() < MAX_LITERAL {
        match data[j] {
            c if c == quote => return (j, true, escaped),
            b'\\' if j + 1 < data.len() => {
                j += 1;
                match data[j] {
                    b'x' => {
                        let h = data.get(j + 1).copied().and_then(hex);
                        let l = data.get(j + 2).copied().and_then(hex);
                        match (h, l) {
                            (Some(h), Some(l)) => {
                                buf.push((h << 4) | l);
                                escaped = true;
                                j += 2;
                            }
                            (Some(h), None) => {
                                buf.push(h);
                                escaped = true;
                                j += 1;
                            }
                            _ => buf.push(b'x'),
                        }
                    }
                    b'0'..=b'7' => {
                        let mut v: u32 = 0;
                        let mut n = 0;
                        while n < 3 && matches!(data.get(j + n), Some(b'0'..=b'7')) {
                            v = v * 8 + (data[j + n] - b'0') as u32;
                            n += 1;
                        }
                        buf.push(v as u8);
                        escaped |= n > 1 || v != 0;
                        j += n - 1;
                    }
                    b'n' => buf.push(b'\n'),
                    b'r' => buf.push(b'\r'),
                    b't' => buf.push(b'\t'),
                    b'\n' => {}
                    other => buf.push(other),
                }
            }
            c => buf.push(c),
        }
        j += 1;
    }
    (j, false, escaped)
}

fn hex(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

/// (offset, bytes) for every run of at least `MIN_LITERAL` byte-valued numbers
/// (`0xNN`, `0..=255`, or `-128..=-1`) separated only by commas, whitespace, and casts.
pub fn numeric_arrays(data: &[u8]) -> Vec<(usize, Vec<u8>)> {
    let mut out = Vec::new();
    let mut run: Vec<u8> = Vec::new();
    let mut run_start = 0;
    let mut i = 0;
    let flush = |run: &mut Vec<u8>, start: usize, out: &mut Vec<(usize, Vec<u8>)>| {
        if run.len() >= MIN_LITERAL {
            out.push((start, std::mem::take(run)));
        } else {
            run.clear();
        }
    };
    while i < data.len() {
        let c = data[i];
        if matches!(c, b',' | b' ' | b'\t' | b'\r' | b'\n') {
            i += 1;
            continue;
        }
        if data[i..].starts_with(b"(byte)") {
            i += 6;
            continue;
        }
        let token_start = i;
        let prev_ok = i == 0
            || !(data[i - 1].is_ascii_alphanumeric() || data[i - 1] == b'_' || data[i - 1] == b'.');
        let mut value: Option<i32> = None;
        if prev_ok && c == b'0' && matches!(data.get(i + 1), Some(b'x' | b'X')) {
            let mut k = i + 2;
            let mut v = 0i32;
            while k < data.len() && k < i + 4 && hex(data[k]).is_some() {
                v = v * 16 + hex(data[k]).unwrap() as i32;
                k += 1;
            }
            if k > i + 2 {
                value = Some(v);
                i = k;
            }
        } else if prev_ok
            && (c.is_ascii_digit()
                || (c == b'-' && data.get(i + 1).is_some_and(u8::is_ascii_digit)))
        {
            let mut k = i + usize::from(c == b'-');
            while k < data.len() && k < token_start + 4 && data[k].is_ascii_digit() {
                k += 1;
            }
            if let Some(v) = std::str::from_utf8(&data[token_start..k])
                .ok()
                .and_then(|s| s.parse::<i32>().ok())
            {
                value = Some(v);
                i = k;
            }
        }
        let clean_end = data
            .get(i)
            .is_none_or(|&n| !(n.is_ascii_alphanumeric() || n == b'_' || n == b'.'));
        match value {
            Some(v) if clean_end && (-128..=255).contains(&v) => {
                if run.is_empty() {
                    run_start = token_start;
                }
                run.push(v as u8);
            }
            _ => {
                flush(&mut run, run_start, &mut out);
                i = token_start + 1;
            }
        }
    }
    flush(&mut run, run_start, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blob(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 37 + 0x30) as u8).collect()
    }
    fn esc(b: &[u8]) -> String {
        b.iter().map(|x| format!("\\x{x:02x}")).collect()
    }

    #[test]
    fn tp_rust_byte_string_mixed_escapes() {
        let b = blob(100);
        let mut src = String::from("Der::from_slice(b\"0\\r\\x06\\t");
        src.push_str(&esc(&b));
        src.push_str("\"),");
        let got = escaped_strings(src.as_bytes());
        assert_eq!(got.len(), 1);
        assert_eq!(&got[0].1[..4], b"0\r\x06\t");
        assert_eq!(&got[0].1[4..], &b[..]);
    }

    #[test]
    fn tp_adjacent_c_literals_and_octal_concatenate() {
        let b = blob(80);
        let (a, c) = b.split_at(40);
        let oct: String = c.iter().map(|x| format!("\\{x:03o}")).collect();
        let src = format!("static const char k[] =\n  \"{}\"\n  \"{oct}\";\n", esc(a));
        let got = escaped_strings(src.as_bytes());
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, b);
    }

    #[test]
    fn tp_python_bytes_single_quotes() {
        let b = blob(70);
        let src = format!("KEY = b'{}'\n", esc(&b));
        assert_eq!(escaped_strings(src.as_bytes())[0].1, b);
    }

    #[test]
    fn fp_plain_strings_and_short_literals_ignored() {
        let src = format!(
            "let s = \"hello world {}\"; let t = \"{}\";",
            "x".repeat(200),
            esc(&blob(10))
        );
        assert!(escaped_strings(src.as_bytes()).is_empty());
    }

    #[test]
    fn fp_unterminated_literal_is_linear_and_empty() {
        let src = format!("\"{}", esc(&blob(50)).repeat(3000));
        assert!(escaped_strings(src.as_bytes()).len() <= 1);
    }

    #[test]
    fn tp_numeric_arrays_hex_decimal_signed() {
        let b = blob(90);
        let hexs = b
            .iter()
            .map(|x| format!("0x{x:02x}"))
            .collect::<Vec<_>>()
            .join(", ");
        let decs = b
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let java = b
            .iter()
            .map(|&x| format!("(byte) {}", x as i8))
            .collect::<Vec<_>>()
            .join(", ");
        for src in [
            format!("{{ {hexs} }}"),
            format!("[{decs}]"),
            format!("{{{java}}}"),
        ] {
            let got = numeric_arrays(src.as_bytes());
            assert_eq!(got.len(), 1, "{src:.60}");
            assert_eq!(got[0].1, b);
        }
    }

    #[test]
    fn fp_numbers_in_prose_and_large_values_ignored() {
        let prose = "Version 1.2.3 released 2026, see items 1, 2, 3 and 400, 500.".repeat(20);
        assert!(numeric_arrays(prose.as_bytes()).is_empty());
        let big = (0..100)
            .map(|i| (i + 1000).to_string())
            .collect::<Vec<_>>()
            .join(", ");
        assert!(numeric_arrays(big.as_bytes()).is_empty());
    }
}
