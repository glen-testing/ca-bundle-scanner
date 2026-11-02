//! Where trust stores and bundles live on each operating system.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::report::Context;

pub type Env = HashMap<String, String>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    /// One file (or, if it is a directory, a walk of `depth` levels).
    Path { depth: usize },
    /// A glob pattern; each match is treated like `Path`.
    Glob { depth: usize },
}

#[derive(Clone, Debug)]
pub struct Location {
    pub label: String,
    pub pattern: String,
    pub kind: Kind,
    pub context: Context,
    /// Explicitly requested by the user: absence or unreadability is an error.
    pub required: bool,
}

#[derive(Clone, Copy)]
enum Base {
    /// Absolute path (prefixed with `--root` if given).
    Abs,
    /// Relative to an environment variable (HOME, APPDATA, ...).
    Env(&'static str),
}

#[derive(Clone, Copy, PartialEq)]
enum Os {
    Unix,
    Mac,
    Win,
    Any,
}

use Context::{Distrust, PlatformStore, Source, Trust};

/// (OS, label, base, pattern relative to base, context, directory walk depth).
type Entry = (Os, &'static str, Base, &'static str, Context, usize);

#[rustfmt::skip]
const TABLE: &[Entry] = &[
    // Operating system bundles and directories (Linux / BSD).
    (Os::Unix, "OS CA bundle (Debian/Ubuntu)", Base::Abs, "/etc/ssl/certs/ca-certificates.crt", Trust, 0),
    (Os::Unix, "OS CA directory (Debian/Ubuntu/OpenSSL)", Base::Abs, "/etc/ssl/certs", Trust, 2),
    (Os::Unix, "Debian CA source (not active trust)", Base::Abs, "/usr/share/ca-certificates", Source, 3),
    (Os::Unix, "Local CA source (installed by update-ca-certificates)", Base::Abs, "/usr/local/share/ca-certificates", Source, 3),
    (Os::Unix, "OS CA bundle (RHEL/Fedora)", Base::Abs, "/etc/pki/tls/certs/ca-bundle.crt", Trust, 0),
    (Os::Unix, "OS CA bundle with trust flags (RHEL)", Base::Abs, "/etc/pki/tls/certs/ca-bundle.trust.crt", Trust, 0),
    (Os::Unix, "OS CA bundle (RHEL p11-kit extract)", Base::Abs, "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", Trust, 0),
    (Os::Unix, "OS CA bundle, OpenSSL trust format (RHEL)", Base::Abs, "/etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt", Trust, 0),
    (Os::Unix, "Admin trust anchors (RHEL)", Base::Abs, "/etc/pki/ca-trust/source/anchors", Trust, 2),
    (Os::Unix, "Admin blocklist (RHEL)", Base::Abs, "/etc/pki/ca-trust/source/blocklist", Distrust, 2),
    (Os::Unix, "Admin blocklist, old name (RHEL)", Base::Abs, "/etc/pki/ca-trust/source/blacklist", Distrust, 2),
    (Os::Unix, "Package CA source (RHEL, not active trust)", Base::Abs, "/usr/share/pki/ca-trust-source", Source, 3),
    (Os::Unix, "OS CA bundle (Alpine/BSD)", Base::Abs, "/etc/ssl/cert.pem", Trust, 0),
    (Os::Unix, "OS CA bundle (SUSE)", Base::Abs, "/var/lib/ca-certificates/ca-bundle.pem", Trust, 0),
    (Os::Unix, "OS CA bundle (SUSE, legacy)", Base::Abs, "/etc/ssl/ca-bundle.pem", Trust, 0),
    (Os::Unix, "OS CA bundle (Arch)", Base::Abs, "/etc/ca-certificates/extracted/tls-ca-bundle.pem", Trust, 0),
    (Os::Unix, "OS CA bundle (NixOS)", Base::Abs, "/etc/ssl/certs/ca-bundle.crt", Trust, 0),
    (Os::Unix, "OS CA bundle (FreeBSD)", Base::Abs, "/usr/local/share/certs/ca-root-nss.crt", Trust, 0),
    (Os::Unix, "System NSS database", Base::Abs, "/etc/pki/nssdb/cert9.db*", PlatformStore, 0),
    (Os::Unix, "curl CA bundle", Base::Abs, "/usr/share/curl/ca-bundle.crt", Trust, 0),
    (Os::Unix, "Docker daemon registry certs", Base::Abs, "/etc/docker/certs.d", Trust, 3),
    (Os::Unix, "Kubernetes service-account CA", Base::Abs, "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt", Trust, 0),
    // Java.
    (Os::Unix, "Java cacerts", Base::Abs, "/usr/lib/jvm/*/lib/security/cacerts", Trust, 0),
    (Os::Unix, "Java cacerts (JRE layout)", Base::Abs, "/usr/lib/jvm/*/jre/lib/security/cacerts", Trust, 0),
    (Os::Unix, "Java cacerts (/usr/java)", Base::Abs, "/usr/java/*/lib/security/cacerts", Trust, 0),
    (Os::Unix, "Java cacerts (/usr/local/java)", Base::Abs, "/usr/local/java/*/lib/security/cacerts", Trust, 0),
    (Os::Unix, "Java cacerts (Debian ca-certificates-java)", Base::Abs, "/etc/ssl/certs/java/cacerts", Trust, 0),
    (Os::Unix, "Java cacerts (RHEL ca-certificates)", Base::Abs, "/etc/pki/java/cacerts", Trust, 0),
    (Os::Mac, "Java cacerts (macOS JDK)", Base::Abs, "/Library/Java/JavaVirtualMachines/*/Contents/Home/lib/security/cacerts", Trust, 0),
    (Os::Win, "Java cacerts (Windows)", Base::Env("ProgramFiles"), "Java/*/lib/security/cacerts", Trust, 0),
    (Os::Win, "Java cacerts (Windows, 32-bit)", Base::Env("ProgramFiles(x86)"), "Java/*/lib/security/cacerts", Trust, 0),
    (Os::Win, "Java cacerts (Eclipse Adoptium)", Base::Env("ProgramFiles"), "Eclipse Adoptium/*/lib/security/cacerts", Trust, 0),
    (Os::Win, "Java cacerts (Microsoft OpenJDK)", Base::Env("ProgramFiles"), "Microsoft/jdk-*/lib/security/cacerts", Trust, 0),
    (Os::Any, "Java cacerts ($JAVA_HOME)", Base::Env("JAVA_HOME"), "lib/security/cacerts", Trust, 0),
    (Os::Any, "Java cacerts ($JAVA_HOME/jre)", Base::Env("JAVA_HOME"), "jre/lib/security/cacerts", Trust, 0),
    // Python certifi, pip, botocore / AWS CLI, gcloud.
    (Os::Unix, "Python certifi", Base::Abs, "/usr/lib/python3*/site-packages/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "Python certifi (lib64)", Base::Abs, "/usr/lib64/python3*/site-packages/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "Python certifi (Debian)", Base::Abs, "/usr/lib/python3/dist-packages/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "Python certifi (/usr/local)", Base::Abs, "/usr/local/lib/python3*/*-packages/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "pip vendored certifi", Base::Abs, "/usr/lib/python3*/site-packages/pip/_vendor/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "botocore CA bundle", Base::Abs, "/usr/lib/python3*/site-packages/botocore/cacert.pem", Trust, 0),
    (Os::Unix, "AWS CLI v2 (distribution package)", Base::Abs, "/usr/lib/python3*/site-packages/awscli/botocore/cacert.pem", Trust, 0),
    (Os::Unix, "AWS CLI v2 (official installer)", Base::Abs, "/usr/local/aws-cli/**/botocore/cacert.pem", Trust, 0),
    (Os::Win, "AWS CLI v2 (Windows)", Base::Env("ProgramFiles"), "Amazon/AWSCLIV2/awscli/botocore/cacert.pem", Trust, 0),
    (Os::Unix, "gcloud SDK certifi", Base::Abs, "/usr/lib/google-cloud-sdk/lib/third_party/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "gcloud SDK certifi (/usr/share)", Base::Abs, "/usr/share/google-cloud-sdk/lib/third_party/certifi/cacert.pem", Trust, 0),
    (Os::Mac, "Python certifi (python.org framework)", Base::Abs, "/Library/Frameworks/Python.framework/Versions/*/lib/python3*/site-packages/certifi/cacert.pem", Trust, 0),
    (Os::Win, "Python certifi (Windows)", Base::Env("LOCALAPPDATA"), "Programs/Python/*/Lib/site-packages/certifi/cacert.pem", Trust, 0),
    // Ruby, Node.js, Electron.
    (Os::Unix, "RubyGems bundled certs", Base::Abs, "/usr/lib/ruby/**/rubygems/ssl_certs/**/*.pem", Trust, 0),
    (Os::Unix, "RubyGems bundled certs (/usr/local)", Base::Abs, "/usr/local/lib/ruby/**/rubygems/ssl_certs/**/*.pem", Trust, 0),
    (Os::Unix, "Node.js binary (bundled root store)", Base::Abs, "/usr/bin/node", Trust, 0),
    (Os::Unix, "Node.js binary (bundled root store, /usr/local)", Base::Abs, "/usr/local/bin/node", Trust, 0),
    (Os::Unix, "VS Code (Electron; Node bundled roots)", Base::Abs, "/usr/share/code/code", Trust, 0),
    (Os::Mac, "Electron apps (Node bundled roots)", Base::Abs, "/Applications/*.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework", Trust, 0),
    (Os::Win, "Node.js binary (Windows)", Base::Env("ProgramFiles"), "nodejs/node.exe", Trust, 0),
    (Os::Win, "VS Code (Electron; Node bundled roots)", Base::Env("LOCALAPPDATA"), "Programs/Microsoft VS Code/Code.exe", Trust, 0),
    (Os::Any, "$NODE_EXTRA_CA_CERTS", Base::Env("NODE_EXTRA_CA_CERTS"), "", Trust, 0),
    (Os::Any, "$SSL_CERT_FILE", Base::Env("SSL_CERT_FILE"), "", Trust, 0),
    (Os::Any, "$SSL_CERT_DIR", Base::Env("SSL_CERT_DIR"), "", Trust, 1),
    (Os::Any, "$REQUESTS_CA_BUNDLE", Base::Env("REQUESTS_CA_BUNDLE"), "", Trust, 0),
    (Os::Any, "$CURL_CA_BUNDLE", Base::Env("CURL_CA_BUNDLE"), "", Trust, 0),
    (Os::Any, "$AWS_CA_BUNDLE", Base::Env("AWS_CA_BUNDLE"), "", Trust, 0),
    // macOS stores and Homebrew.
    (Os::Mac, "macOS /etc/ssl/cert.pem (command-line tools; not covered by Apple's fix)", Base::Abs, "/etc/ssl/cert.pem", Trust, 0),
    (Os::Mac, "macOS system roots keychain", Base::Abs, "/System/Library/Keychains/SystemRootCertificates.keychain", PlatformStore, 0),
    (Os::Mac, "macOS system keychain", Base::Abs, "/Library/Keychains/System.keychain", PlatformStore, 0),
    (Os::Mac, "Homebrew CA bundle (Apple Silicon)", Base::Abs, "/opt/homebrew/etc/ca-certificates/cert.pem", Trust, 0),
    (Os::Mac, "Homebrew CA bundle (Intel)", Base::Abs, "/usr/local/etc/ca-certificates/cert.pem", Trust, 0),
    (Os::Mac, "Homebrew Mozilla bundle (Apple Silicon)", Base::Abs, "/opt/homebrew/share/ca-certificates/cacert.pem", Trust, 0),
    (Os::Mac, "Homebrew Mozilla bundle (Intel)", Base::Abs, "/usr/local/share/ca-certificates/cacert.pem", Trust, 0),
    (Os::Mac, "AWS CLI v2 (macOS installer)", Base::Abs, "/usr/local/aws-cli/**/botocore/cacert.pem", Trust, 0),
    // Git for Windows.
    (Os::Win, "Git for Windows CA bundle", Base::Env("ProgramFiles"), "Git/mingw64/etc/ssl/certs/ca-bundle.crt", Trust, 0),
    (Os::Win, "Git for Windows CA bundle (32-bit)", Base::Env("ProgramFiles(x86)"), "Git/mingw32/etc/ssl/certs/ca-bundle.crt", Trust, 0),
    // Per-user locations (HOME is mapped to /root and /home/* under --root).
    (Os::Unix, "Firefox NSS database", Base::Env("HOME"), ".mozilla/firefox/*/cert9.db*", PlatformStore, 0),
    (Os::Unix, "Firefox NSS database (legacy)", Base::Env("HOME"), ".mozilla/firefox/*/cert8.db", PlatformStore, 0),
    (Os::Unix, "Firefox NSS database (Snap)", Base::Env("HOME"), "snap/firefox/common/.mozilla/firefox/*/cert9.db*", PlatformStore, 0),
    (Os::Unix, "Firefox NSS database (Flatpak)", Base::Env("HOME"), ".var/app/org.mozilla.firefox/.mozilla/firefox/*/cert9.db*", PlatformStore, 0),
    (Os::Unix, "Thunderbird NSS database", Base::Env("HOME"), ".thunderbird/*/cert9.db*", PlatformStore, 0),
    (Os::Unix, "Chrome/Chromium NSS database", Base::Env("HOME"), ".pki/nssdb/cert9.db*", PlatformStore, 0),
    (Os::Mac, "Firefox NSS database (macOS)", Base::Env("HOME"), "Library/Application Support/Firefox/Profiles/*/cert9.db*", PlatformStore, 0),
    (Os::Mac, "Firefox NSS database (macOS, all users)", Base::Abs, "/Users/*/Library/Application Support/Firefox/Profiles/*/cert9.db*", PlatformStore, 0),
    (Os::Mac, "macOS login keychain", Base::Env("HOME"), "Library/Keychains/login.keychain-db", PlatformStore, 0),
    (Os::Win, "Firefox NSS database (Windows)", Base::Env("APPDATA"), "Mozilla/Firefox/Profiles/*/cert9.db*", PlatformStore, 0),
    (Os::Win, "Thunderbird NSS database (Windows)", Base::Env("APPDATA"), "Thunderbird/Profiles/*/cert9.db*", PlatformStore, 0),
    (Os::Unix, "Python certifi (user)", Base::Env("HOME"), ".local/lib/python3*/site-packages/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "botocore CA bundle (user)", Base::Env("HOME"), ".local/lib/python3*/site-packages/botocore/cacert.pem", Trust, 0),
    (Os::Unix, "pip vendored certifi (user)", Base::Env("HOME"), ".local/lib/python3*/site-packages/pip/_vendor/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "Python certifi (venv in home)", Base::Env("HOME"), "*/lib/python3*/site-packages/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "Python certifi (.venv in home)", Base::Env("HOME"), "*/.venv/lib/python3*/site-packages/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "Python certifi (uv-managed Python)", Base::Env("HOME"), ".local/share/uv/python/*/lib/python3*/site-packages/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "pip vendored certifi (uv-managed Python)", Base::Env("HOME"), ".local/share/uv/python/*/lib/python3*/site-packages/pip/_vendor/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "Python certifi (uv tool)", Base::Env("HOME"), ".local/share/uv/tools/*/lib/python3*/site-packages/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "Python certifi (uv environment cache)", Base::Env("HOME"), ".cache/uv/environments-v2/*/lib/python3*/site-packages/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "Python certifi (uv archive cache)", Base::Env("HOME"), ".cache/uv/archive-v0/*/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "pip vendored certifi (trunk)", Base::Env("HOME"), ".cache/trunk/tools/python/*/lib/python3*/site-packages/pip/_vendor/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "Python certifi (pyenv)", Base::Env("HOME"), ".pyenv/versions/*/lib/python3*/site-packages/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "Python certifi (conda)", Base::Env("HOME"), "{miniconda3,miniforge3,anaconda3}/lib/python3*/site-packages/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "Python certifi (conda env)", Base::Env("HOME"), "{miniconda3,miniforge3,anaconda3}/envs/*/lib/python3*/site-packages/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "Python certifi (conda, ~/.local/share)", Base::Env("HOME"), ".local/share/{miniconda3,miniforge3,anaconda3}/lib/python3*/site-packages/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "gcloud SDK certifi (user install)", Base::Env("HOME"), "google-cloud-sdk/lib/third_party/certifi/cacert.pem", Trust, 0),
    (Os::Unix, "Node.js binary (nvm)", Base::Env("HOME"), ".nvm/versions/node/*/bin/node", Trust, 0),
];

/// Expand `{a,b}` alternatives (the glob crate has no brace support).
fn expand_braces(p: &str) -> Vec<String> {
    let (Some(open), Some(close)) = (p.find('{'), p.find('}')) else {
        return vec![p.to_string()];
    };
    if close < open {
        return vec![p.to_string()];
    }
    p[open + 1..close]
        .split(',')
        .flat_map(|alt| expand_braces(&format!("{}{alt}{}", &p[..open], &p[close + 1..])))
        .collect()
}

fn os_matches(entry: Os, os: &str) -> bool {
    match entry {
        Os::Any => true,
        Os::Win => os == "windows",
        Os::Mac => os == "macos",
        Os::Unix => os != "windows",
    }
}

/// Built-in system locations for `os`. With `root`, absolute paths are
/// resolved under it and HOME becomes `<root>/root` plus `<root>/home/*`.
pub fn system(env: &Env, os: &str, root: Option<&Path>) -> Vec<Location> {
    let mut out: Vec<Location> = Vec::new();
    for &(eos, label, base, rel, context, depth) in TABLE {
        if !os_matches(eos, os) {
            continue;
        }
        let bases: Vec<String> = match (base, root) {
            (Base::Abs, None) => vec![String::new()],
            (Base::Abs, Some(r)) => vec![glob::Pattern::escape(&r.to_string_lossy())],
            (Base::Env("HOME"), Some(r)) => {
                let r = glob::Pattern::escape(&r.to_string_lossy());
                vec![format!("{r}/root"), format!("{r}/home/*")]
            }
            (Base::Env(_), Some(_)) => vec![],
            (Base::Env(var), None) => match env.get(var).filter(|v| !v.is_empty()) {
                Some(v) if var == "SSL_CERT_DIR" => {
                    let sep = if os == "windows" { ';' } else { ':' };
                    v.split(sep)
                        .filter(|s| !s.is_empty())
                        .map(glob::Pattern::escape)
                        .collect()
                }
                Some(v) => vec![glob::Pattern::escape(v)],
                None => vec![],
            },
        };
        for b in bases {
            for rel in expand_braces(rel) {
                let pattern = match base {
                    Base::Abs => format!("{b}{rel}"),
                    // `b` is already escaped (or a deliberate `/home/*` glob).
                    Base::Env(_) => {
                        if rel.is_empty() {
                            b.clone()
                        } else {
                            format!("{}/{rel}", b.trim_end_matches(['/', '\\']))
                        }
                    }
                };
                let is_glob = pattern.contains(['*', '?', '[']);
                out.push(Location {
                    label: label.to_string(),
                    pattern,
                    kind: if is_glob {
                        Kind::Glob { depth }
                    } else {
                        Kind::Path { depth }
                    },
                    context,
                    required: false,
                });
            }
        }
    }
    let mut seen = std::collections::HashSet::new();
    out.retain(|l| seen.insert(l.pattern.clone()));
    out
}

/// A user-supplied path (`-p` / `-b`).
pub fn explicit(label: &str, path: &Path, depth: usize) -> Location {
    Location {
        label: label.to_string(),
        pattern: path.to_string_lossy().into_owned(),
        kind: Kind::Path { depth },
        context: Context::Trust,
        required: true,
    }
}

/// Expand a location to existing paths.
pub fn resolve(loc: &Location) -> Vec<PathBuf> {
    match loc.kind {
        Kind::Path { .. } => {
            let p = PathBuf::from(&loc.pattern);
            if p.exists() || loc.required {
                vec![p]
            } else {
                vec![]
            }
        }
        Kind::Glob { .. } => {
            let opts = glob::MatchOptions {
                case_sensitive: true,
                require_literal_separator: true,
                require_literal_leading_dot: false,
            };
            match glob::glob_with(&loc.pattern, opts) {
                Ok(paths) => paths.filter_map(Result::ok).collect(),
                Err(_) => vec![],
            }
        }
    }
}

/// A path component naming a distrust list overrides the location context.
pub fn context_for(path: &Path, base: Context) -> Context {
    let distrust = path.components().any(|c| {
        let s = c.as_os_str().to_string_lossy().to_ascii_lowercase();
        s == "blocklist" || s == "blacklist" || s == "distrusted" || s == "disallowed"
    });
    if distrust {
        Context::Distrust
    } else {
        base
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn env(pairs: &[(&str, &str)]) -> Env {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn touch(p: &Path) {
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, b"x").unwrap();
    }

    fn resolved(locs: &[Location], label: &str) -> Vec<PathBuf> {
        locs.iter()
            .filter(|l| l.label == label)
            .flat_map(resolve)
            .collect()
    }

    #[test]
    fn windows_java_glob_matches_under_program_files() {
        let t = tempfile::tempdir().unwrap();
        let pf = t.path().join("Program Files");
        let cacerts = pf.join("Java/jdk-21/lib/security/cacerts");
        touch(&cacerts);
        touch(&pf.join("Java/jdk-21/lib/security/other"));
        let locs = system(
            &env(&[("ProgramFiles", pf.to_str().unwrap())]),
            "windows",
            None,
        );
        assert_eq!(resolved(&locs, "Java cacerts (Windows)"), vec![cacerts]);
        // Not on Linux.
        let linux = system(
            &env(&[("ProgramFiles", pf.to_str().unwrap())]),
            "linux",
            None,
        );
        assert!(resolved(&linux, "Java cacerts (Windows)").is_empty());
    }

    #[test]
    fn double_star_matches_any_depth() {
        let t = tempfile::tempdir().unwrap();
        let deep = t
            .path()
            .join("usr/local/aws-cli/v2/2.30.0/dist/awscli/botocore/cacert.pem");
        let shallow = t
            .path()
            .join("usr/local/aws-cli/awscli/botocore/cacert.pem");
        touch(&deep);
        touch(&shallow);
        let locs = system(&Env::new(), "linux", Some(t.path()));
        let mut got = resolved(&locs, "AWS CLI v2 (official installer)");
        got.sort();
        let mut want = vec![shallow, deep];
        want.sort();
        assert_eq!(got, want);
    }

    #[test]
    fn macos_firefox_glob_expands() {
        let t = tempfile::tempdir().unwrap();
        let db = t
            .path()
            .join("Library/Application Support/Firefox/Profiles/abc.default/cert9.db");
        let wal = db.with_file_name("cert9.db-wal");
        touch(&db);
        touch(&wal);
        let locs = system(&env(&[("HOME", t.path().to_str().unwrap())]), "macos", None);
        let mut got = resolved(&locs, "Firefox NSS database (macOS)");
        got.sort();
        assert_eq!(got, vec![db, wal]);
    }

    #[test]
    fn root_prefix_and_home_mapping() {
        let t = tempfile::tempdir().unwrap();
        let ff = t
            .path()
            .join("home/alice/snap/firefox/common/.mozilla/firefox/x/cert9.db");
        touch(&ff);
        let locs = system(&Env::new(), "linux", Some(t.path()));
        assert_eq!(resolved(&locs, "Firefox NSS database (Snap)"), vec![ff]);
        assert!(locs
            .iter()
            .all(|l| l.pattern.starts_with(&*t.path().to_string_lossy())));
    }

    #[test]
    fn braces_expand() {
        assert_eq!(expand_braces("a/{x,y}/b"), vec!["a/x/b", "a/y/b"]);
        assert_eq!(expand_braces("plain"), vec!["plain"]);
    }

    #[test]
    fn no_duplicate_patterns_and_no_bogus_entries() {
        let locs = system(&Env::new(), "linux", None);
        let mut pats: Vec<_> = locs.iter().map(|l| &l.pattern).collect();
        let n = pats.len();
        pats.sort();
        pats.dedup();
        assert_eq!(n, pats.len());
        assert!(!locs.iter().any(|l| l.pattern.contains("CertEnroll")));
        assert!(!locs
            .iter()
            .any(|l| l.pattern.ends_with("/bin/go") || l.pattern.ends_with("terraform")));
        assert!(!locs.iter().any(|l| l.pattern.contains(".rustup")));
    }

    #[test]
    fn distrust_path_component() {
        assert_eq!(
            context_for(
                Path::new("/usr/share/pki/ca-trust-source/blocklist/x.pem"),
                Context::Source
            ),
            Context::Distrust
        );
        assert_eq!(
            context_for(Path::new("/etc/ssl/certs/x.pem"), Context::Trust),
            Context::Trust
        );
        assert_eq!(
            context_for(Path::new("/etc/blocklisted-not/x.pem"), Context::Trust),
            Context::Trust
        );
    }
}
