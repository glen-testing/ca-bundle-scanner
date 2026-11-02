//! Minimal DER (Distinguished Encoding Rules) structure helpers.

/// (header length, content length) of the TLV (tag-length-value) at `data[0]`.
/// Definite lengths of up to 3 length bytes (16 MiB) are supported.
pub fn header(data: &[u8]) -> Option<(usize, usize)> {
    let b = *data.get(1)?;
    match b {
        0x00..=0x7f => Some((2, b as usize)),
        0x81 => Some((3, *data.get(2)? as usize)),
        0x82 => Some((
            4,
            u16::from_be_bytes([*data.get(2)?, *data.get(3)?]) as usize,
        )),
        0x83 => {
            let l = ((*data.get(2)? as usize) << 16)
                | ((*data.get(3)? as usize) << 8)
                | *data.get(4)? as usize;
            Some((5, l))
        }
        _ => None,
    }
}

/// Total length of a certificate-shaped SEQUENCE at `data[0]`, or `None`.
/// Shape: SEQUENCE (long-form length) whose first element is a SEQUENCE that fits.
pub fn cert_span(data: &[u8]) -> Option<usize> {
    if data.first() != Some(&0x30) || *data.get(1)? < 0x81 {
        return None;
    }
    let (h, l) = header(data)?;
    let total = h.checked_add(l)?;
    if total > data.len() {
        return None;
    }
    let inner = &data[h..total];
    if inner.first() != Some(&0x30) {
        return None;
    }
    let (ih, il) = header(inner)?;
    (ih + il <= inner.len()).then_some(total)
}

/// Extended-key-usage purposes named in OpenSSL `TRUSTED CERTIFICATE` aux data.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct TrustAux {
    /// `None` when no trust list is present (all purposes allowed).
    pub trusted: Option<Vec<&'static str>>,
    pub rejected: Vec<&'static str>,
}

const PURPOSES: &[(&[u8], &str)] = &[
    (&[0x2b, 6, 1, 5, 5, 7, 3, 1], "tls-server"),
    (&[0x2b, 6, 1, 5, 5, 7, 3, 2], "tls-client"),
    (&[0x2b, 6, 1, 5, 5, 7, 3, 3], "code-signing"),
    (&[0x2b, 6, 1, 5, 5, 7, 3, 4], "email"),
    (&[0x55, 0x1d, 0x25, 0x00], "any"),
];

fn purposes(mut seq: &[u8]) -> Vec<&'static str> {
    let mut out = Vec::new();
    while let Some((h, l)) = header(seq) {
        let Some(v) = seq.get(h..h + l) else { break };
        if seq[0] == 0x06 {
            out.push(
                PURPOSES
                    .iter()
                    .find(|(o, _)| *o == v)
                    .map_or("other", |p| p.1),
            );
        }
        seq = &seq[h + l..];
    }
    out
}

/// Parse the X509_CERT_AUX that follows the certificate in a `TRUSTED CERTIFICATE` body.
pub fn trusted_aux(body: &[u8]) -> Option<TrustAux> {
    let aux = &body[cert_span(body)?..];
    if aux.first() != Some(&0x30) {
        return None;
    }
    let (h, l) = header(aux)?;
    let mut inner = aux.get(h..h + l)?;
    let mut out = TrustAux::default();
    while !inner.is_empty() {
        let (eh, el) = header(inner)?;
        let content = inner.get(eh..eh + el)?;
        match inner[0] {
            0x30 => out.trusted = Some(purposes(content)),
            0xa0 => out.rejected = purposes(content),
            _ => {}
        }
        inner = &inner[eh + el..];
    }
    Some(out)
}

impl TrustAux {
    /// Usable for TLS server authentication or code signing.
    pub fn allows_relevant_use(&self) -> bool {
        if self.rejected.contains(&"any") {
            return false;
        }
        let allowed: Vec<&str> = match &self.trusted {
            Some(t) => t.clone(),
            None => vec!["any"],
        };
        allowed.iter().any(|&p| match p {
            "any" => {
                !(self.rejected.contains(&"tls-server") && self.rejected.contains(&"code-signing"))
            }
            "tls-server" | "code-signing" => !self.rejected.contains(&p),
            _ => false,
        })
    }
}

/// PKCS#12 (PFX) whose content includes an encryptedData bag: certificates
/// may be hidden behind a password.
pub fn is_encrypted_pkcs12(data: &[u8]) -> bool {
    const ENCRYPTED_DATA_OID: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x06,
    ];
    if data.first() != Some(&0x30) {
        return false;
    }
    let Some((h, _)) = header(data) else {
        return false;
    };
    data.get(h..h + 3) == Some(&[0x02, 0x01, 0x03])
        && memchr::memmem::find(&data[..data.len().min(1 << 16)], ENCRYPTED_DATA_OID).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_forms() {
        assert_eq!(header(&[0x30, 0x05]), Some((2, 5)));
        assert_eq!(header(&[0x30, 0x81, 0xc8]), Some((3, 200)));
        assert_eq!(header(&[0x30, 0x82, 0x01, 0x00]), Some((4, 256)));
        assert_eq!(header(&[0x30, 0x83, 0x01, 0x00, 0x00]), Some((5, 65536)));
        assert_eq!(header(&[0x30, 0x84, 0, 0, 0, 1]), None);
        assert_eq!(header(&[0x30, 0x82, 0x01]), None);
    }

    #[test]
    fn cert_span_requires_inner_sequence() {
        let mut v = vec![0x30, 0x81, 0x83, 0x30, 0x81, 0x80];
        v.extend(std::iter::repeat_n(0u8, 0x80));
        assert_eq!(cert_span(&v), Some(v.len()));
        v[3] = 0x02;
        assert_eq!(cert_span(&v), None);
        // Truncated outer length.
        assert_eq!(cert_span(&[0x30, 0x82, 0xff, 0xff, 0x30, 0x00]), None);
    }
}
