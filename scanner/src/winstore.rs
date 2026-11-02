//! Windows certificate stores (CryptoAPI system stores).

use windows_sys::Win32::Security::Cryptography::{
    CertCloseStore, CertEnumCertificatesInStore, CertOpenStore, CERT_CONTEXT,
    CERT_STORE_OPEN_EXISTING_FLAG, CERT_STORE_PROV_SYSTEM_W, CERT_STORE_READONLY_FLAG,
    CERT_SYSTEM_STORE_CURRENT_USER, CERT_SYSTEM_STORE_LOCAL_MACHINE,
};

use crate::profile::Profile;
use crate::report::{Context, LocationResult, LocationStatus, Report, Severity};
use crate::scan::Limits;

/// (store name, context). `Disallowed` holds certificates Windows refuses to trust.
const STORES: &[(&str, Context)] = &[
    ("ROOT", Context::PlatformStore),
    ("AuthRoot", Context::PlatformStore),
    ("CA", Context::PlatformStore),
    ("TrustedPublisher", Context::PlatformStore),
    ("Disallowed", Context::Distrust),
];

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// DER blobs of every certificate in one system store, or `None` if it cannot be opened.
fn certificates(location: u32, store: &str) -> Option<Vec<Vec<u8>>> {
    let name = wide(store);
    let flags = location | CERT_STORE_READONLY_FLAG | CERT_STORE_OPEN_EXISTING_FLAG;
    // SAFETY: valid provider constant, NUL-terminated name; handle closed below.
    let h = unsafe { CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0, flags, name.as_ptr().cast()) };
    if h.is_null() {
        return None;
    }
    let mut out = Vec::new();
    let mut ctx: *const CERT_CONTEXT = std::ptr::null();
    loop {
        // SAFETY: `h` is open; passing the previous context continues the enumeration.
        ctx = unsafe { CertEnumCertificatesInStore(h, ctx) };
        if ctx.is_null() {
            break;
        }
        // SAFETY: a non-null CERT_CONTEXT points at cbCertEncoded valid bytes.
        let der = unsafe {
            let c = &*ctx;
            std::slice::from_raw_parts(c.pbCertEncoded, c.cbCertEncoded as usize).to_vec()
        };
        out.push(der);
    }
    // SAFETY: closing the handle opened above.
    unsafe { CertCloseStore(h, 0) };
    Some(out)
}

pub fn scan(
    profile: &Profile,
    limits: &Limits,
    report: &mut Report,
    progress: &mut dyn FnMut(&LocationResult),
) {
    for (loc_name, loc) in [
        ("LocalMachine", CERT_SYSTEM_STORE_LOCAL_MACHINE),
        ("CurrentUser", CERT_SYSTEM_STORE_CURRENT_USER),
    ] {
        for &(store, context) in STORES {
            let label = format!("Windows certificate store {loc_name}\\{store}");
            let mut lr = LocationResult {
                label: label.clone(),
                path: format!("cert:{loc_name}\\{store}"),
                status: LocationStatus::Scanned,
                files: 0,
                findings: 0,
                action_findings: 0,
                errors: 0,
                duplicates: 0,
            };
            match certificates(loc, store) {
                Some(certs) => {
                    for der in certs {
                        let (f, i) = crate::scan_bytes(&der, &lr.path, context, profile, limits);
                        lr.files += 1;
                        lr.findings += f.len();
                        lr.action_findings += f.iter().filter(|x| x.action_required).count();
                        report.files_scanned += 1;
                        report.findings.extend(f);
                        report.issues.extend(i);
                    }
                }
                None => {
                    lr.status = LocationStatus::Missing;
                    report.issues.push(crate::report::Issue {
                        path: lr.path.clone(),
                        severity: Severity::Warning,
                        message: "store could not be opened".into(),
                    });
                }
            }
            progress(&lr);
            report.locations.push(lr);
        }
    }
}
