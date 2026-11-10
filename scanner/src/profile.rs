//! Certificates to search for, with the role each one plays.

use std::collections::{HashMap, HashSet};

use aho_corasick::AhoCorasick;
use serde::Serialize;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::*;

use crate::util::{hex, parse_hex32, sha256};

/// Why a certificate is on the list.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// CA certificate whose private key is compromised.
    Compromised,
    /// Root or issuing CA above compromised CAs that has been distrusted.
    DistrustedRoot,
    /// Root that cross-signed compromised CAs and is still trusted by some vendors.
    CrossSignRoot,
    /// Same operator, not distrusted; reported for information only.
    InfoRoot,
}

#[derive(Clone, Debug)]
pub struct Target {
    pub name: String,
    pub sha256: [u8; 32],
    pub role: Role,
    pub der_len: Option<usize>,
    /// Contents of the subjectPublicKey BIT STRING (EC point or RSAPublicKey).
    pub key: Option<Vec<u8>>,
    pub ski: Option<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NeedleKind {
    /// A compromised or distrusted public key.
    Key,
    /// Subject Key Identifier of a compromised CA; matches children's AKI.
    Ski,
}

#[derive(Debug)]
pub struct Needle {
    pub kind: NeedleKind,
    pub bytes: Vec<u8>,
    /// Indexes into `Profile::targets` that carry this key / SKI.
    pub targets: Vec<usize>,
}

#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("{0}: not a valid DER certificate")]
    BadCert(String),
    #[error("cannot read {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("{0}: no PEM or DER certificate found")]
    NoCert(String),
    #[error("fingerprint must be 64 hex characters (SHA-256): {0}")]
    BadFingerprint(String),
    #[error("built-in certificate {name} hashes to {got}, table says {want}")]
    BuiltinMismatch {
        name: String,
        got: String,
        want: String,
    },
}

/// Text attached to a built-in profile.
#[derive(Clone, Debug, Default)]
pub struct ProfileText {
    pub headline: String,
    pub references: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Profile {
    pub name: String,
    pub text: ProfileText,
    pub targets: Vec<Target>,
    by_hash: HashMap<[u8; 32], usize>,
    lengths: HashSet<usize>,
    any_length: bool,
    needles: Vec<Needle>,
    needle_ac: Option<AhoCorasick>,
    keywords: Vec<String>,
    keyword_ac: Option<AhoCorasick>,
    /// SHA-256 of each distinct compromised SubjectPublicKeyInfo (as in Chromium's SPKI blocklist).
    blocked_spki: Vec<[u8; 32]>,
    /// The hashes as raw bytes and as hex text (Go keeps them as hex strings); `.1` indexes `blocked_spki`.
    blocked_hash_pats: Vec<(Vec<u8>, usize)>,
    blocked_ac: Option<AhoCorasick>,
    /// The same keys as bare SPKI DER, full and without the outer SEQUENCE header
    /// (both appear in compiled distrust lists); `.1` is the index into `blocked_spki`.
    blocked_spki_der: Vec<(Vec<u8>, usize)>,
    blocked_der_ac: Option<AhoCorasick>,
}

/// Minimum needle length; shorter keys would risk chance matches.
const MIN_NEEDLE: usize = 20;

impl Profile {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Default::default()
        }
    }

    /// Add a certificate by its DER encoding.
    pub fn add_der(&mut self, der: &[u8], role: Role) -> Result<(), ProfileError> {
        let fp = sha256(der);
        if self.by_hash.contains_key(&fp) {
            return Ok(());
        }
        let (_, cert) = X509Certificate::from_der(der)
            .map_err(|_| ProfileError::BadCert(format!("cert {}", &hex(&fp)[..16])))?;
        let cn = first_cn(cert.subject()).unwrap_or_else(|| format!("cert {}", &hex(&fp)[..16]));
        let name = match first_cn(cert.issuer()) {
            Some(issuer) if issuer != cn => format!("{cn} (issued by {issuer})"),
            _ => cn.clone(),
        };
        let key = cert.public_key().subject_public_key.data.to_vec();
        if role == Role::Compromised {
            let h = sha256(cert.public_key().raw);
            if !self.blocked_spki.contains(&h) {
                let idx = self.blocked_spki.len();
                self.blocked_spki.push(h);
                let hx = hex(&h);
                for pat in [
                    h.to_vec(),
                    hx.clone().into_bytes(),
                    hx.to_uppercase().into_bytes(),
                ] {
                    self.blocked_hash_pats.push((pat, idx));
                }
                let raw = cert.public_key().raw;
                self.blocked_spki_der.push((raw.to_vec(), idx));
                if let Some((hdr, _)) = crate::der::header(raw) {
                    self.blocked_spki_der.push((raw[hdr..].to_vec(), idx));
                }
            }
        }
        let ski = subject_key_id(&cert).map(|s| s.to_vec());
        if matches!(role, Role::Compromised | Role::DistrustedRoot) {
            self.add_keyword(&cn);
            if let Some(org) = cert.subject().iter_organization().next() {
                if let Ok(o) = org.as_str() {
                    self.add_keyword(o);
                }
            }
        }
        let idx = self.targets.len();
        self.targets.push(Target {
            name,
            sha256: fp,
            role,
            der_len: Some(der.len()),
            key: Some(key.clone()),
            ski: ski.clone(),
        });
        self.by_hash.insert(fp, idx);
        self.lengths.insert(der.len());
        if role != Role::InfoRoot && key.len() >= MIN_NEEDLE {
            self.add_needle(NeedleKind::Key, key, idx);
        }
        if role == Role::Compromised {
            if let Some(s) = ski.filter(|s| s.len() >= MIN_NEEDLE) {
                self.add_needle(NeedleKind::Ski, s, idx);
            }
        }
        Ok(())
    }

    /// Add a target known only by SHA-256 (length unknown, so every candidate is hashed).
    pub fn add_fingerprint(&mut self, raw: &str, role: Role) -> Result<(), ProfileError> {
        let fp = parse_hex32(raw).ok_or_else(|| ProfileError::BadFingerprint(raw.into()))?;
        if self.by_hash.contains_key(&fp) {
            return Ok(());
        }
        let idx = self.targets.len();
        self.targets.push(Target {
            name: format!("cert {}…", &hex(&fp)[..16]),
            sha256: fp,
            role,
            der_len: None,
            key: None,
            ski: None,
        });
        self.by_hash.insert(fp, idx);
        self.any_length = true;
        Ok(())
    }

    /// Load every certificate in a PEM or DER file.
    pub fn add_file(&mut self, path: &std::path::Path, role: Role) -> Result<usize, ProfileError> {
        let data = std::fs::read(path).map_err(|source| ProfileError::Io {
            path: path.display().to_string(),
            source,
        })?;
        let mut ders: Vec<Vec<u8>> = crate::pem::blocks(&data)
            .iter()
            .filter_map(|b| crate::pem::decode(b.body).ok())
            .filter_map(|d| crate::der::cert_span(&d).map(|n| d[..n].to_vec()))
            .collect();
        if ders.is_empty() {
            if let Some(n) = crate::der::cert_span(&data) {
                ders.push(data[..n].to_vec());
            }
        }
        if ders.is_empty() {
            return Err(ProfileError::NoCert(path.display().to_string()));
        }
        for d in &ders {
            self.add_der(d, role)
                .map_err(|_| ProfileError::BadCert(path.display().to_string()))?;
        }
        Ok(ders.len())
    }

    fn add_keyword(&mut self, kw: &str) {
        if kw.len() >= 8 && !self.keywords.iter().any(|k| k == kw) {
            self.keywords.push(kw.to_string());
        }
    }

    fn add_needle(&mut self, kind: NeedleKind, bytes: Vec<u8>, idx: usize) {
        if let Some(n) = self
            .needles
            .iter_mut()
            .find(|n| n.kind == kind && n.bytes == bytes)
        {
            n.targets.push(idx);
        } else {
            self.needles.push(Needle {
                kind,
                bytes,
                targets: vec![idx],
            });
        }
    }

    /// Build search automata; call once after all targets are added.
    pub fn finalize(&mut self) {
        let pats: Vec<&[u8]> = self.needles.iter().map(|n| n.bytes.as_slice()).collect();
        self.needle_ac = (!pats.is_empty()).then(|| AhoCorasick::new(pats).expect("needles"));
        self.keyword_ac =
            (!self.keywords.is_empty()).then(|| AhoCorasick::new(&self.keywords).expect("kw"));
        self.blocked_ac = (!self.blocked_hash_pats.is_empty()).then(|| {
            AhoCorasick::new(self.blocked_hash_pats.iter().map(|(b, _)| b)).expect("spki hashes")
        });
        self.blocked_der_ac = (!self.blocked_spki_der.is_empty()).then(|| {
            AhoCorasick::new(self.blocked_spki_der.iter().map(|(b, _)| b)).expect("spki der")
        });
    }

    /// Compromised keys blocked in `data`: (by SPKI SHA-256, by bare SPKI DER, total keys).
    /// `outside_cert` says whether a bare-DER hit at (start, end) lies outside any certificate.
    pub fn blocked_keys(
        &self,
        data: &[u8],
        outside_cert: impl Fn(usize, usize) -> bool,
    ) -> (Vec<bool>, Vec<bool>, usize) {
        let total = self.blocked_spki.len();
        let mut by_hash = vec![false; total];
        let mut by_der = vec![false; total];
        if let Some(ac) = &self.blocked_ac {
            for m in ac.find_overlapping_iter(data) {
                by_hash[self.blocked_hash_pats[m.pattern().as_usize()].1] = true;
            }
        }
        if let Some(ac) = &self.blocked_der_ac {
            for m in ac.find_overlapping_iter(data) {
                if outside_cert(m.start(), m.end()) {
                    by_der[self.blocked_spki_der[m.pattern().as_usize()].1] = true;
                }
            }
        }
        (by_hash, by_der, total)
    }

    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    pub fn lookup(&self, fp: &[u8; 32]) -> Option<&Target> {
        self.by_hash.get(fp).map(|&i| &self.targets[i])
    }

    /// Whether a DER candidate of this total length could be a target.
    pub fn wants_len(&self, len: usize) -> bool {
        self.any_length || self.lengths.contains(&len)
    }

    pub fn needles(&self) -> &[Needle] {
        &self.needles
    }

    /// (needle index, start, end) for every key / SKI occurrence in `data`.
    pub fn needle_hits(&self, data: &[u8]) -> Vec<(usize, usize, usize)> {
        match &self.needle_ac {
            Some(ac) => ac
                .find_overlapping_iter(data)
                .map(|m| (m.pattern().as_usize(), m.start(), m.end()))
                .collect(),
            None => Vec::new(),
        }
    }

    pub fn first_keyword(&self, data: &[u8]) -> Option<&str> {
        let m = self.keyword_ac.as_ref()?.find(data)?;
        Some(&self.keywords[m.pattern().as_usize()])
    }

    pub fn count(&self, role: Role) -> usize {
        self.targets.iter().filter(|t| t.role == role).count()
    }

    /// Built-in profile for the October 2026 eMudhra compromise.
    pub fn emudhra() -> Result<Self, ProfileError> {
        let mut p = Self::new("emudhra");
        for (name, der, role, want) in crate::builtin::EMUDHRA {
            let got = hex(&sha256(der));
            if got != *want {
                return Err(ProfileError::BuiltinMismatch {
                    name: (*name).into(),
                    got,
                    want: (*want).into(),
                });
            }
            p.add_der(der, *role)?;
        }
        p.add_keyword("eMudhra Technologies Limited");
        p.add_keyword("eMudhra Inc");
        p.text = ProfileText {
            headline: crate::builtin::EMUDHRA_HEADLINE.into(),
            references: crate::builtin::EMUDHRA_REFERENCES
                .iter()
                .map(|s| s.to_string())
                .collect(),
        };
        p.finalize();
        Ok(p)
    }
}

pub fn first_cn(name: &X509Name<'_>) -> Option<String> {
    name.iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(str::to_string)
}

pub fn subject_key_id<'a>(cert: &'a X509Certificate<'_>) -> Option<&'a [u8]> {
    cert.iter_extensions()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(k) => Some(k.0),
            _ => None,
        })
}

pub fn authority_key_id<'a>(cert: &'a X509Certificate<'_>) -> Option<&'a [u8]> {
    cert.iter_extensions()
        .find_map(|e| match e.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(a) => a.key_identifier.as_ref().map(|k| k.0),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_table_hashes_and_counts() {
        let p = Profile::emudhra().expect("every built-in DER matches its listed SHA-256");
        assert_eq!(p.count(Role::Compromised), 16);
        assert_eq!(p.count(Role::DistrustedRoot), 5);
        assert_eq!(p.count(Role::CrossSignRoot), 1);
        assert_eq!(p.count(Role::InfoRoot), 3);
        // 8 compromised keys + ECC G3 + 2 issuing-CA keys + AAA = 12 key needles; 8 SKIs.
        let keys = p
            .needles()
            .iter()
            .filter(|n| n.kind == NeedleKind::Key)
            .count();
        let skis = p
            .needles()
            .iter()
            .filter(|n| n.kind == NeedleKind::Ski)
            .count();
        assert_eq!((keys, skis), (12, 8));
        // The 8 compromised keys, each shared by the emSign and Sectigo certificates.
        assert_eq!(p.blocked_keys(b"", |_, _| true).2, 8);
    }

    #[test]
    fn fingerprint_only_target_has_unknown_length() {
        let mut p = Profile::new("t");
        assert!(p
            .add_fingerprint(&"ab".repeat(31), Role::Compromised)
            .is_err());
        p.add_fingerprint(&"ab".repeat(32), Role::Compromised)
            .unwrap();
        assert!(p.wants_len(12345));
        let q = Profile::emudhra().unwrap();
        assert!(q.wants_len(876) && !q.wants_len(12345));
    }
}
