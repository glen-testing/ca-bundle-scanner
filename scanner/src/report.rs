//! Findings, issues, exit-code policy and output rendering.

use std::io::{self, Write};

use serde::Serialize;

use crate::profile::{Profile, Role};

/// How the location a certificate was found in is used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Context {
    /// An active trust bundle / keystore with no revocation checking.
    Trust,
    /// A vendor-managed platform store (macOS keychains, Windows stores, NSS
    /// databases) whose vendor can block certificates by other means.
    PlatformStore,
    /// A source directory that is not itself used for trust decisions.
    Source,
    /// A distrust / blocklist location: presence here is the remediation.
    Distrust,
    /// Trust flags exclude TLS server authentication and code signing.
    Restricted,
    /// The same file also blocks every compromised key by SPKI SHA-256 hash
    /// (Chromium's compiled-in blocklist, as in patched Electron), so chains through
    /// the compromised CAs are rejected even though the roots are still present.
    KeyBlocklist,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Compromised,
    DistrustedRoot,
    CrossSignRoot,
    InfoRoot,
    IssuedByCompromised,
    Reference,
    /// A project dependency ships a CA store containing affected certificates.
    DependencyBundle,
}

impl From<Role> for Kind {
    fn from(r: Role) -> Self {
        match r {
            Role::Compromised => Kind::Compromised,
            Role::DistrustedRoot => Kind::DistrustedRoot,
            Role::CrossSignRoot => Kind::CrossSignRoot,
            Role::InfoRoot => Kind::InfoRoot,
        }
    }
}

/// What matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Match {
    /// Exact certificate (SHA-256 of the DER).
    Certificate,
    /// Same public key in a different certificate, or a bare key / trust anchor.
    PublicKey,
    /// Child certificate whose Authority Key Identifier names a compromised CA.
    AuthorityKeyId,
    /// SHA-256 fingerprint written as hex text.
    FingerprintText,
    /// CA name in source / config text.
    Keyword,
    /// The compromised public keys listed for rejection (SPKI SHA-256 hashes or bare SPKIs).
    Blocklist,
    /// Found through dependency analysis of a lockfile.
    Dependency,
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub path: String,
    pub source: String,
    pub cert: String,
    pub sha256: Option<String>,
    #[serde(rename = "type")]
    pub kind: Kind,
    #[serde(rename = "match")]
    pub matched: Match,
    pub context: Context,
    pub action_required: bool,
}

/// Whether a finding of this kind in this context needs remediation.
pub fn action_required(kind: Kind, ctx: Context) -> bool {
    !matches!(
        (kind, ctx),
        (
            _,
            Context::Source | Context::Distrust | Context::Restricted | Context::KeyBlocklist
        ) | (Kind::InfoRoot | Kind::Reference, _)
            | (Kind::CrossSignRoot, Context::PlatformStore)
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Informational; coverage unaffected.
    Warning,
    /// Something in scope could not be inspected: the verdict is incomplete.
    Error,
}

#[derive(Clone, Debug, Serialize)]
pub struct Issue {
    pub path: String,
    pub severity: Severity,
    pub message: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LocationStatus {
    Scanned,
    Missing,
    Error,
}

#[derive(Clone, Debug, Serialize)]
pub struct LocationResult {
    pub label: String,
    pub path: String,
    pub status: LocationStatus,
    pub files: usize,
    pub findings: usize,
    pub action_findings: usize,
    pub errors: usize,
    /// Files skipped because an earlier location already scanned them.
    pub duplicates: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Clean,
    Found,
    Incomplete,
}

impl Verdict {
    /// 0 clean, 1 action required, 3 incomplete (2 is reserved for usage errors).
    pub fn exit_code(self) -> i32 {
        match self {
            Verdict::Clean => 0,
            Verdict::Found => 1,
            Verdict::Incomplete => 3,
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub issues: Vec<Issue>,
    pub locations: Vec<LocationResult>,
    pub files_scanned: usize,
    /// Trust model of each scanned item that showed any trust signal.
    pub items: Vec<crate::trust::TrustProfile>,
    /// Dependencies of scanned projects that bundle a CA store.
    pub dependencies: Vec<ca_certs_in_code::report::Finding>,
}

impl Report {
    pub fn verdict(&self) -> Verdict {
        if self.findings.iter().any(|f| f.action_required) {
            Verdict::Found
        } else if self.issues.iter().any(|i| i.severity == Severity::Error) {
            Verdict::Incomplete
        } else {
            Verdict::Clean
        }
    }

    /// Drop duplicate findings (same path, certificate, kind and match).
    pub fn dedup(&mut self) {
        let mut seen = std::collections::HashSet::new();
        self.findings.retain(|f| {
            seen.insert((
                f.path.clone(),
                f.sha256.clone(),
                f.cert.clone(),
                f.kind,
                f.matched,
            ))
        });
    }
}

#[derive(Serialize)]
struct JsonOut<'a> {
    schema: u32,
    profile: &'a str,
    verdict: Verdict,
    exit_code: i32,
    files_scanned: usize,
    findings: &'a [Finding],
    items: &'a [crate::trust::TrustProfile],
    dependencies: &'a [ca_certs_in_code::report::Finding],
    issues: &'a [Issue],
    locations: &'a [LocationResult],
}

pub fn write_json(w: &mut dyn Write, report: &Report, profile: &Profile) -> io::Result<()> {
    let v = report.verdict();
    let out = JsonOut {
        schema: 2,
        profile: &profile.name,
        verdict: v,
        exit_code: v.exit_code(),
        files_scanned: report.files_scanned,
        findings: &report.findings,
        items: &report.items,
        dependencies: &report.dependencies,
        issues: &report.issues,
        locations: &report.locations,
    };
    serde_json::to_writer_pretty(&mut *w, &out)?;
    writeln!(w)
}

fn section_title(kind: Kind) -> &'static str {
    match kind {
        Kind::Compromised => "COMPROMISED CA CERTIFICATES",
        Kind::DistrustedRoot => "DISTRUSTED ROOT / ISSUING CA STILL TRUSTED",
        Kind::CrossSignRoot => "CROSS-SIGNING ROOT TRUSTED BY A BUNDLE WITHOUT REVOCATION CHECKS",
        Kind::IssuedByCompromised => "CERTIFICATES ISSUED BY A COMPROMISED CA",
        Kind::InfoRoot => "SAME-OPERATOR ROOTS (not distrusted)",
        Kind::Reference => "REFERENCES IN TEXT",
        Kind::DependencyBundle => "DEPENDENCIES THAT BUNDLE AN AFFECTED CA STORE",
    }
}

fn advice(kind: Kind) -> &'static str {
    match kind {
        Kind::Compromised => "Remove these certificates; anyone can sign with their keys.",
        Kind::DistrustedRoot => {
            "These anchors make the bundle trust the compromised intermediates. Update the bundle."
        }
        Kind::CrossSignRoot => {
            "The Sectigo cross-signed compromised intermediates chain to this root, and bundle \
             consumers (OpenSSL, Python, Java) do not check revocation. Update to a bundle without it."
        }
        Kind::IssuedByCompromised => "Replace these certificates; their issuer's key is public.",
        Kind::InfoRoot => "Informational: these roots were not distrusted.",
        Kind::Reference => "Informational: text mentions a listed certificate or CA name.",
        Kind::DependencyBundle => "Update the dependency (or what pulls it in, see the chain) to a release without these certificates.",
    }
}

fn ctx_note(ctx: Context) -> &'static str {
    match ctx {
        Context::Trust => "",
        Context::PlatformStore => " [platform store]",
        Context::Source => " [source dir, not active trust]",
        Context::Distrust => " [distrust list: already blocked]",
        Context::Restricted => " [trust flags exclude TLS and code signing]",
        Context::KeyBlocklist => " [same binary blocks every compromised key by hash]",
    }
}

/// Informational findings listed per kind before summarising.
const INFO_LIST_LIMIT: usize = 8;

pub fn write_text(w: &mut dyn Write, report: &Report, profile: &Profile) -> io::Result<()> {
    let action: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| f.action_required)
        .collect();
    let info: Vec<&Finding> = report
        .findings
        .iter()
        .filter(|f| !f.action_required)
        .collect();
    let errors = report
        .issues
        .iter()
        .filter(|i| i.severity == Severity::Error)
        .count();
    let scanned_locs = report
        .locations
        .iter()
        .filter(|l| !matches!(l.status, LocationStatus::Missing))
        .count();
    match report.verdict() {
        Verdict::Found => writeln!(w, "Result: FOUND. {} finding(s) need action", action.len())?,
        Verdict::Incomplete => writeln!(
            w,
            "Result: INCOMPLETE. Nothing found, but {errors} item(s) could not be inspected (see errors above)"
        )?,
        Verdict::Clean => writeln!(
            w,
            "Result: CLEAN. No {} found in {} file(s) across {} location(s)",
            if profile.name == "custom" { "matching certificates".to_string() } else { format!("{} certificates", profile.name) },
            report.files_scanned,
            scanned_locs
        )?,
    }
    writeln!(w)?;
    let kinds = [
        Kind::Compromised,
        Kind::DistrustedRoot,
        Kind::CrossSignRoot,
        Kind::IssuedByCompromised,
        Kind::InfoRoot,
        Kind::Reference,
    ];
    for (title, group) in [("ACTION REQUIRED", &action), ("INFORMATIONAL", &info)] {
        if group.is_empty() {
            continue;
        }
        writeln!(w, "== {title} ==")?;
        for kind in kinds {
            let items: Vec<&&Finding> = group.iter().filter(|f| f.kind == kind).collect();
            if items.is_empty() {
                continue;
            }
            writeln!(w, "{} ({}):", section_title(kind), items.len())?;
            let limit = if title == "INFORMATIONAL" {
                INFO_LIST_LIMIT
            } else {
                usize::MAX
            };
            if items.len() > limit {
                writeln!(
                    w,
                    "  ... {} more not listed (use --json for all)",
                    items.len() - limit
                )?;
            }
            for f in items.into_iter().take(limit) {
                let fp = f.sha256.as_deref().unwrap_or("-");
                writeln!(w, "  {} ({fp})", f.cert)?;
                writeln!(
                    w,
                    "    in: {} [{}; {:?} match]{}",
                    f.path,
                    f.source,
                    f.matched,
                    ctx_note(f.context)
                )?;
            }
            writeln!(w, "  → {}", advice(kind))?;
            writeln!(w)?;
        }
    }
    write_trust(w, &report.items)?;
    write_dependencies(w, &report.dependencies)?;
    if !report.findings.is_empty() && !profile.text.references.is_empty() {
        writeln!(w, "References:")?;
        for r in &profile.text.references {
            writeln!(w, "  {r}")?;
        }
    }
    Ok(())
}

fn write_dependencies(
    w: &mut dyn Write,
    deps: &[ca_certs_in_code::report::Finding],
) -> io::Result<()> {
    if deps.is_empty() {
        return Ok(());
    }
    writeln!(w, "== DEPENDENCIES THAT BUNDLE A CA STORE ==")?;
    for d in deps.iter().take(TRUST_LIST_LIMIT) {
        let status = match (&d.mitigated_by, &d.bundle, d.reachable) {
            (_, _, false) => "not on a runtime path".to_string(),
            (Some(m), _, _) => format!("mitigated: {m}"),
            (None, Some(b), _) if b.affected => {
                format!("AFFECTED: {}", b.affected_certs.join(", "))
            }
            (None, Some(_), _) => "bundle checked: clean".to_string(),
            (None, None, _) => "bundle not checked (run with --deps-online)".to_string(),
        };
        writeln!(
            w,
            "  {} {} ({}) in {}",
            d.package, d.version, d.ecosystem, d.lockfile
        )?;
        if let Some(c) = &d.dep_chain {
            writeln!(w, "    chain: {}", c.join(" -> "))?;
        }
        writeln!(w, "    {status}")?;
    }
    if deps.len() > TRUST_LIST_LIMIT {
        writeln!(
            w,
            "  … {} more (see --json `dependencies`)",
            deps.len() - TRUST_LIST_LIMIT
        )?;
    }
    writeln!(w)
}

/// Items listed in the text report's trust-model section.
const TRUST_LIST_LIMIT: usize = 25;

fn write_trust(w: &mut dyn Write, items: &[crate::trust::TrustProfile]) -> io::Result<()> {
    use crate::trust::Model;
    if items.is_empty() {
        return Ok(());
    }
    writeln!(w, "== TRUST MODEL (per item) ==")?;
    for t in items.iter().take(TRUST_LIST_LIMIT) {
        let model = match t.model {
            Model::Bundled => format!("bundles its own CA store ({} roots)", t.bundled_roots),
            Model::OsStore => "trusts the OS store".to_string(),
            Model::Both => format!(
                "bundles a CA store ({} roots) and also uses the OS store",
                t.bundled_roots
            ),
            Model::NoneDetected => "no CA store or OS-store use detected".to_string(),
        };
        writeln!(w, "  {}: {model}", t.path)?;
        for (label, list) in [
            ("bundle", &t.bundle),
            ("OS store", &t.os_store),
            ("pinning", &t.pinning),
            ("blocklist", &t.blocklist),
        ] {
            if !list.is_empty() {
                writeln!(w, "    {label}: {}", list.join("; "))?;
            }
        }
        if t.pinning.is_empty() {
            writeln!(w, "    pinning: none detected")?;
        }
        if t.blocklist.is_empty() {
            writeln!(w, "    blocklist: none detected")?;
        }
    }
    if items.len() > TRUST_LIST_LIMIT {
        writeln!(
            w,
            "  … {} more (see --json `items`)",
            items.len() - TRUST_LIST_LIMIT
        )?;
    }
    writeln!(w)
}

pub fn write_issues(w: &mut dyn Write, report: &Report) -> io::Result<()> {
    for (sev, title) in [
        (Severity::Error, "Errors (coverage incomplete)"),
        (Severity::Warning, "Warnings"),
    ] {
        let items: Vec<&Issue> = report.issues.iter().filter(|i| i.severity == sev).collect();
        if items.is_empty() {
            continue;
        }
        writeln!(w, "{title}:")?;
        for i in items {
            writeln!(w, "  [!] {}: {}", i.path, i.message)?;
        }
        writeln!(w)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_matrix() {
        assert!(action_required(Kind::Compromised, Context::Trust));
        assert!(action_required(Kind::Compromised, Context::PlatformStore));
        assert!(!action_required(Kind::Compromised, Context::Distrust));
        assert!(!action_required(Kind::Compromised, Context::Source));
        assert!(action_required(Kind::DistrustedRoot, Context::Trust));
        assert!(!action_required(Kind::InfoRoot, Context::Trust));
        assert!(action_required(Kind::CrossSignRoot, Context::Trust));
        assert!(!action_required(
            Kind::CrossSignRoot,
            Context::PlatformStore
        ));
        assert!(!action_required(Kind::Reference, Context::Trust));
    }

    fn finding(action: bool) -> Finding {
        Finding {
            path: "p".into(),
            source: "s".into(),
            cert: "c".into(),
            sha256: None,
            kind: Kind::Compromised,
            matched: Match::Certificate,
            context: Context::Trust,
            action_required: action,
        }
    }

    #[test]
    fn verdicts() {
        let mut r = Report::default();
        assert_eq!(r.verdict(), Verdict::Clean);
        r.issues.push(Issue {
            path: "x".into(),
            severity: Severity::Warning,
            message: "m".into(),
        });
        assert_eq!(r.verdict(), Verdict::Clean);
        r.issues.push(Issue {
            path: "x".into(),
            severity: Severity::Error,
            message: "m".into(),
        });
        assert_eq!(r.verdict(), Verdict::Incomplete);
        r.findings.push(finding(false));
        assert_eq!(r.verdict(), Verdict::Incomplete);
        r.findings.push(finding(true));
        assert_eq!(r.verdict(), Verdict::Found);
        assert_eq!(Verdict::Found.exit_code(), 1);
    }
}
