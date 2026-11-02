//! Built-in certificate sets. Certificates are public; their SHA-256 is
//! re-checked at startup (and in tests) against the value from the sources.

use crate::profile::Role;

macro_rules! cert {
    ($file:literal) => {
        include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/certs/emudhra/",
            $file
        ))
    };
}

/// (file name, DER, role, SHA-256 per Mozilla Bugzilla 2083449 / crt.sh).
pub type BuiltinCert = (&'static str, &'static [u8], Role, &'static str);

#[rustfmt::skip]
pub const EMUDHRA: &[BuiltinCert] = &[
    // 6 TLS + 2 code-signing compromised keys, each issued by emSign and cross-signed by Sectigo.
    ("EM_EV_TLS_CA_G3B_emSign", cert!("EM_EV_TLS_CA_G3B_emSign.der"), Role::Compromised, "e7568fe6e12331f4fd7de61da4c7559d0f8eb192a218d4741a3ba75184333838"),
    ("EM_OV_TLS_CA_G3B_emSign", cert!("EM_OV_TLS_CA_G3B_emSign.der"), Role::Compromised, "98b896625c0c230adeec3eb2cf6aad5001ecf9156a68644e82374ce5833bc25b"),
    ("EM_DV_TLS_CA_G3B_emSign", cert!("EM_DV_TLS_CA_G3B_emSign.der"), Role::Compromised, "42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493"),
    ("EM_EV_TLS_CA_G3C_emSign", cert!("EM_EV_TLS_CA_G3C_emSign.der"), Role::Compromised, "432ec25f0d28de9006d97bf752f17bbb2cd41f669933fcb072d9a1148d0261f3"),
    ("EM_OV_TLS_CA_G3C_emSign", cert!("EM_OV_TLS_CA_G3C_emSign.der"), Role::Compromised, "cb6e15165ac802e9b3f993f16c25d41f4e81c21ebde71ae1b012ac00bf9c7c3f"),
    ("EM_DV_TLS_CA_G3C_emSign", cert!("EM_DV_TLS_CA_G3C_emSign.der"), Role::Compromised, "0164d7ceae5bb909c272af151ff44b1177ae9b47d9424b94f1d9558c30934d19"),
    ("EM_EV_TLS_CA_G3B_AAA",    cert!("EM_EV_TLS_CA_G3B_AAA.der"),    Role::Compromised, "579480aea166290bd3c643589e795fc0d0e54e86505d180f1dff99efd3199512"),
    ("EM_OV_TLS_CA_G3B_AAA",    cert!("EM_OV_TLS_CA_G3B_AAA.der"),    Role::Compromised, "5f1ded4dd590af74631290cf073b122a2aac6a1fa479778a0bd43579bd832699"),
    ("EM_DV_TLS_CA_G3B_AAA",    cert!("EM_DV_TLS_CA_G3B_AAA.der"),    Role::Compromised, "45a883f349aedfd5f3a649b5498ffb121712ba8b448f3f2a91dbc5a766fcddbe"),
    ("EM_EV_TLS_CA_G3C_AAA",    cert!("EM_EV_TLS_CA_G3C_AAA.der"),    Role::Compromised, "fd9d5c2dbbd4995ab69b8d50c439d9527b00529199c2fd01b2174eb58f07021f"),
    ("EM_OV_TLS_CA_G3C_AAA",    cert!("EM_OV_TLS_CA_G3C_AAA.der"),    Role::Compromised, "7485b51c0ed192878fa1d2f948fb529ae1842cc5086c4b67f7be5b2039de9489"),
    ("EM_DV_TLS_CA_G3C_AAA",    cert!("EM_DV_TLS_CA_G3C_AAA.der"),    Role::Compromised, "62b7f9868263f72f6911fc78ceaf72c1979158b7368bf648683bb2aa39b02e72"),
    ("EM_OV_CS_CA_G3B_emSign",  cert!("EM_OV_CS_CA_G3B_emSign.der"),  Role::Compromised, "9e39de2881273acc225a149c72ba3e0f51424963669ab633ee1dc7df5db067b4"),
    ("EM_OV_CS_CA_G3C_emSign",  cert!("EM_OV_CS_CA_G3C_emSign.der"),  Role::Compromised, "4b2460a466f95fd40113bcdcca2ceb29b3b093921de45474da7df48874c630b1"),
    ("EM_OV_CS_CA_G3B_AAA",     cert!("EM_OV_CS_CA_G3B_AAA.der"),     Role::Compromised, "a496e23ac0cab8155fc9b117b97eae368efcbb9041aec8804d5a308d2d01c2d8"),
    ("EM_OV_CS_CA_G3C_AAA",     cert!("EM_OV_CS_CA_G3C_AAA.der"),     Role::Compromised, "84112972b8e59d14560ae7e7119654474aad119990cf3722bfc1e3b91615e1fd"),
    // Root distrusted for this incident, and the issuing CAs beneath it (both encodings).
    ("emSign_ECC_Root_G3", cert!("emSign_ECC_Root_G3.der"), Role::DistrustedRoot, "86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b"),
    ("emSign_Root_TLS_CA_G3_crosssigned_by_ECC_G3", cert!("emSign_Root_TLS_CA_G3_crosssigned_by_ECC_G3.der"), Role::DistrustedRoot, "3094025792039a68af6e553686410bdab7c0d4a36b9084cba64202e35d6ebbdd"),
    ("emSign_Root_TLS_CA_G3_selfissued", cert!("emSign_Root_TLS_CA_G3_selfissued.der"), Role::DistrustedRoot, "7dd78d5f4f13459a83dff9abbba62edbaf6f2d102bf257fd712f4d9f2746ed8d"),
    ("emSign_Root_CS_CA_G3_crosssigned_by_ECC_G3", cert!("emSign_Root_CS_CA_G3_crosssigned_by_ECC_G3.der"), Role::DistrustedRoot, "7137fa71ad46ba686f746d1014ac57e8e6c6e9af4aa2f73c0c44a5cf27debb59"),
    ("emSign_Root_CS_CA_G3_selfissued", cert!("emSign_Root_CS_CA_G3_selfissued.der"), Role::DistrustedRoot, "f2edaaff3d9b701fb4d14c9f285f8c0bad90fc3bcc1fa07d47f4718edaba34a5"),
    // Sectigo root that cross-signed all 8 compromised keys.
    ("Sectigo_AAA_Certificate_Services", cert!("Sectigo_AAA_Certificate_Services.der"), Role::CrossSignRoot, "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4"),
    // Same operator, not distrusted for this incident (C1/C3 left Mozilla for an unrelated transition).
    ("emSign_ECC_Root_C3", cert!("emSign_ECC_Root_C3.der"), Role::InfoRoot, "bc4d809b15189d78db3e1d8cf4f9726a795da1643ca5f1358e1ddb0edc0d7eb3"),
    ("emSign_Root_C1",     cert!("emSign_Root_C1.der"),     Role::InfoRoot, "125609aa301da0a249b97a8239cb6a34216f44dcac9f3954b14292f2e8c8608f"),
    ("emSign_Root_G1",     cert!("emSign_Root_G1.der"),     Role::InfoRoot, "40f6af0346a99aa1cd1d555a4e9cce62c7f9634603ee406615833dc8c8d00367"),
];

pub const EMUDHRA_HEADLINE: &str =
    "eMudhra October 2026: 8 compromised CA keys (16 certificates), distrusted emSign ECC Root CA - G3 and its issuing CAs, Sectigo AAA cross-sign root";

pub const EMUDHRA_REFERENCES: &[&str] = &[
    "https://bugzilla.mozilla.org/show_bug.cgi?id=2083449",
    "https://bugzilla.mozilla.org/show_bug.cgi?id=2084101",
    "https://support.apple.com/en-us/149555",
    "https://osv.dev/vulnerability/GHSA-6q48-6c7w-9gw2",
];
