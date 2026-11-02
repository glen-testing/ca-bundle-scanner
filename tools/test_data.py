"""Data tests: schema validation, sources, and per-issue content regressions.

Each check has a true-positive (current data passes) and a false-positive
(a deliberately broken or legacy copy is rejected) test.
"""
import copy
import json
import re
import unittest
from pathlib import Path

import validate_data

HERE = Path(__file__).resolve().parent
LEGACY_JSON = HERE / "testdata" / "legacy-ca-bundle-sources.json"
DATE_RE = re.compile(r"^20\d{2}-\d{2}-\d{2}$")


def entry(data, entry_id):
    for e in data["entries"]:
        if e["id"] == entry_id:
            return e
    raise KeyError(entry_id)


def text_of(e):
    return json.dumps(e, ensure_ascii=False)


class SchemaValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data, cls.schema = validate_data.load()

    def errors_for(self, mutate):
        broken = copy.deepcopy(self.data)
        mutate(broken)
        return validate_data.validate(broken, self.schema)

    def test_tp_data_is_valid(self):
        self.assertEqual(validate_data.validate(self.data, self.schema), [])

    def test_fp_missing_sources_rejected(self):
        errs = self.errors_for(lambda d: d["entries"][0].pop("sources"))
        self.assertTrue(any("missing required property 'sources'" in e for e in errs), errs)

    def test_fp_empty_sources_rejected(self):
        errs = self.errors_for(lambda d: d["entries"][0].__setitem__("sources", []))
        self.assertTrue(any("sources: fewer than 1 items" in e for e in errs), errs)

    def test_fp_bad_trust_source_enum_rejected(self):
        errs = self.errors_for(lambda d: d["entries"][1].__setitem__("trust_source", "bundled-ish"))
        self.assertTrue(any("not in enum" in e for e in errs), errs)

    def test_fp_bad_category_enum_rejected(self):
        errs = self.errors_for(lambda d: d["entries"][1].__setitem__("category", "browsers"))
        self.assertTrue(any("not in enum" in e for e in errs), errs)

    def test_fp_bad_revocation_channel_rejected(self):
        errs = self.errors_for(lambda d: d["entries"][1].__setitem__("revocation_channel", ["CRLite"]))
        self.assertTrue(any("not in enum" in e for e in errs), errs)

    def test_fp_missing_last_verified_rejected(self):
        errs = self.errors_for(lambda d: d["entries"][2].pop("last_verified"))
        self.assertTrue(any("missing required property 'last_verified'" in e for e in errs), errs)

    def test_fp_duplicate_name_rejected(self):
        def dup(d):
            clone = copy.deepcopy(d["entries"][0])
            clone["id"] = clone["id"] + "-copy"
            d["entries"].append(clone)
        errs = self.errors_for(dup)
        self.assertTrue(any("duplicate name" in e for e in errs), errs)

    def test_fp_duplicate_id_rejected(self):
        def dup(d):
            clone = copy.deepcopy(d["entries"][0])
            clone["name"] = clone["name"] + " copy"
            d["entries"].append(clone)
        errs = self.errors_for(dup)
        self.assertTrue(any("duplicate id" in e for e in errs), errs)

    def test_fp_placeholder_instead_of_null_rejected(self):
        errs = self.errors_for(lambda d: d["entries"][0].__setitem__("override", "N/A"))
        self.assertTrue(any("use null" in e for e in errs), errs)

    def test_fp_empty_string_rejected(self):
        errs = self.errors_for(lambda d: d["entries"][0].__setitem__("notes", ""))
        self.assertTrue(any("shorter than 1" in e for e in errs), errs)

    def test_fp_unverified_without_note_rejected(self):
        def mut(d):
            d["entries"][0]["verified"] = False
            d["entries"][0]["unverified_note"] = None
        errs = self.errors_for(mut)
        self.assertTrue(any("unverified_note: expected type string" in e for e in errs), errs)

    def test_fp_verified_with_stray_note_rejected(self):
        def mut(d):
            e = next(x for x in d["entries"] if x["verified"])
            e["unverified_note"] = "stray"
        errs = self.errors_for(mut)
        self.assertTrue(any("unverified_note: expected type null" in e for e in errs), errs)

    def test_fp_unknown_property_rejected(self):
        errs = self.errors_for(lambda d: d["entries"][0].__setitem__("embedded_in", "binary"))
        self.assertTrue(any("unexpected property 'embedded_in'" in e for e in errs), errs)

    def test_fp_legacy_data_rejected(self):
        legacy = json.loads(LEGACY_JSON.read_text(encoding="utf-8"))
        self.assertNotEqual(validate_data.validate(legacy, self.schema), [])

    def test_fp_unsupported_keyword_is_loud(self):
        with self.assertRaises(ValueError):
            validate_data.schema_errors(1, {"maximum": 3})


class Sources(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data, cls.schema = validate_data.load()

    @staticmethod
    def entries_missing_sources(data):
        bad = []
        for e in data["entries"]:
            srcs = e.get("sources") or []
            ok = [s for s in srcs if str(s.get("url", "")).startswith("https://")
                  and DATE_RE.match(str(s.get("retrieved", "")))]
            if not ok:
                bad.append(e.get("name"))
        return bad

    def test_tp_every_entry_has_dated_source(self):
        self.assertEqual(self.entries_missing_sources(self.data), [])
        for n in self.data["metadata"]["notices"]:
            self.assertTrue(n["sources"], n["id"])

    def test_fp_undated_source_detected(self):
        broken = copy.deepcopy(self.data)
        broken["entries"][3]["sources"] = [{"url": "https://example.org/", "title": "x"}]
        self.assertEqual(self.entries_missing_sources(broken), [broken["entries"][3]["name"]])
        self.assertTrue(validate_data.validate(broken, self.schema))

    def test_fp_legacy_entries_have_no_sources(self):
        legacy = json.loads(LEGACY_JSON.read_text(encoding="utf-8"))
        self.assertEqual(len(self.entries_missing_sources(legacy)), len(legacy["entries"]))

    def test_tp_unverified_rows_are_flagged(self):
        flagged = {e["id"] for e in self.data["entries"] if not e["verified"]}
        # D22: rows the reviewer could not confirm must stay flagged until sourced.
        for must in ("brave", "opera", "vivaldi", "arc"):
            self.assertIn(must, flagged)


class IssueRegressions(unittest.TestCase):
    """Content checks per issue ID. Each checker returns a list of problems."""

    @classmethod
    def setUpClass(cls):
        cls.data, _ = validate_data.load()
        cls.legacy = json.loads(LEGACY_JSON.read_text(encoding="utf-8"))

    @staticmethod
    def find(data, pred):
        return [e for e in data["entries"] if pred(e)]

    def check(self, fn):
        self.assertEqual(fn(self.data), [], fn.__name__)
        self.assertNotEqual(fn(self.legacy), [], fn.__name__ + " should reject legacy data")

    def test_d01_aaa_cross_sign_and_macos_cli_gap(self):
        def fn(d):
            notices = {n["id"]: json.dumps(n) for n in d.get("metadata", {}).get("notices", [])}
            probs = []
            if "AAA Certificate Services" not in notices.get("aaa-cross-sign", ""):
                probs.append("no AAA notice")
            if "/etc/ssl/cert.pem" not in notices.get("macos-cli-gap", ""):
                probs.append("no macOS /etc/ssl/cert.pem notice")
            if not self.find(d, lambda e: "2.38.4" in text_of(e) and "AAA" in text_of(e)):
                probs.append("AWS CLI row lacks AAA removal version")
            return probs
        self.check(fn)

    def test_d03_incident_counts(self):
        def fn(d):
            inc = d.get("metadata", {}).get("incident", {})
            if (inc.get("compromised_keys"), inc.get("ca_certificates")) != (8, 16):
                return ["counts are not 8 keys / 16 certificates"]
            if (inc.get("tls_keys"), inc.get("code_signing_keys")) != (6, 2):
                return ["split is not 6 TLS + 2 code signing"]
            return []
        self.check(fn)

    def test_d05_cargo_uses_libcurl_and_rustup_platform_verifier(self):
        def fn(d):
            cargo = self.find(d, lambda e: e["name"].lower().startswith("cargo"))
            probs = []
            if not cargo or cargo[0]["trust_source"] != "os" or "libcurl" not in text_of(cargo[0]):
                probs.append("cargo row not OS store via libcurl")
            if not self.find(d, lambda e: e["name"].lower().startswith("rustup")
                             and "rustls-platform-verifier" in text_of(e)):
                probs.append("rustup row missing")
            return probs
        self.check(fn)

    def test_d06_node_flag_versions(self):
        def fn(d):
            node = self.find(d, lambda e: e["name"].startswith("Node.js"))
            t = text_of(node[0]) if node else ""
            need = ("v22.15.0", "v23.8.0", "v22.19.0", "v24.6.0", "OpenSSL default")
            return [n for n in need if n not in t]
        self.check(fn)

    def test_d07_pip_truststore_and_requests_env(self):
        def fn(d):
            pip = self.find(d, lambda e: e["name"] == "pip")
            req = self.find(d, lambda e: e["name"].startswith("Python (requests"))
            probs = []
            if not pip or pip[0]["trust_source"] == "bundled" or "24.2" not in text_of(pip[0]):
                probs.append("pip row still bundled-only")
            if not req or "CURL_CA_BUNDLE" not in text_of(req[0]) or "--use-feature=truststore" in text_of(req[0]):
                probs.append("requests env vars wrong")
            return probs
        self.check(fn)

    def test_d08_curl_split_per_os(self):
        def fn(d):
            names = {e["name"] for e in d["entries"]}
            want = {"curl (macOS system)", "curl (Windows system)", "curl (Linux distributions)"}
            probs = sorted(want - names)
            mac = self.find(d, lambda e: e["name"] == "curl (macOS system)")
            if mac and "/etc/ssl/cert.pem" not in text_of(mac[0]):
                probs.append("macOS curl path")
            return probs
        self.check(fn)

    def test_d09_homebrew_paths(self):
        def fn(d):
            t = " ".join(text_of(e) for e in self.find(d, lambda e: "Homebrew" in e["name"]))
            return [p for p in ("etc/ca-certificates/cert.pem", "Portable Ruby") if p not in t]
        self.check(fn)

    def test_d10_dart_uses_os_store(self):
        def fn(d):
            dart = self.find(d, lambda e: e["name"].startswith("Dart"))
            return [] if dart and dart[0]["trust_source"] == "fallback" else ["Dart row still bundled"]
        self.check(fn)

    def test_d11_firefox_onecrl(self):
        def fn(d):
            ff = self.find(d, lambda e: e["name"] == "Firefox")
            if not ff or "OneCRL" not in ff[0].get("revocation_channel", []) or "2026-10-17" not in text_of(ff[0]):
                return ["Firefox OneCRL push missing"]
            return []
        self.check(fn)

    def test_d12_android_conscrypt(self):
        def fn(d):
            a = self.find(d, lambda e: e["name"].startswith("Android"))
            t = " ".join(text_of(e) for e in a)
            return [p for p in ("Conscrypt", "2026-10-19") if p not in t]
        self.check(fn)

    def test_d13_chrome_edge_platforms_and_link(self):
        def fn(d):
            t = " ".join(text_of(e) for e in self.find(d, lambda e: e["name"].startswith(("Chrome", "Microsoft Edge"))))
            probs = [p for p in ("105", "114", "112") if p not in t]
            if "chromium.org/Home/chromium-security/root-ca-policy" in json.dumps(d):
                probs.append("redirecting Chrome root program link")
            return probs
        self.check(fn)

    def test_d14_smaller_errors(self):
        def fn(d):
            t = json.dumps(d)
            need = ("NODE_EXTRA_CA_CERTS", "esp_crt_bundle_set", "go1.27", "cacerts_get",
                    "/etc/pki/java/cacerts", "Install Certificates", "rustls-platform-verifier",
                    "http.systemCertificates", "WebView2")
            return [n for n in need if n not in t]
        self.check(fn)

    def test_d22_resolved_rows_carry_official_facts(self):
        def fn(d):
            want = {
                "suse": "/var/lib/ca-certificates/ca-bundle.pem",
                "windows": "daily",
                "gcloud": "lib/third_party/certifi/cacert.pem",
                "macos": "Certificates.bundle",
                "dotnet": "SSL_CERT_FILE",
                "zoom": "trusted root store",
            }
            ids = {e.get("id"): e for e in d["entries"]}
            return [k for k, v in want.items() if k not in ids or v not in text_of(ids[k])
                    or ids[k].get("verified") is not True]
        self.check(fn)

    def test_d15_small_integer_claim_attributed(self):
        def fn(d):
            s = d.get("metadata", {}).get("incident", {}).get("summary", "")
            probs = []
            if "as small as 4" in s and "comment" not in s:
                probs.append("unattributed 'as small as 4'")
            if "256" not in s:
                probs.append("bug-body wording missing")
            return probs
        self.check(fn)
        self.assertEqual(fn({"metadata": {"incident": {"summary": "integers as small as 4"}}}),
                         ["unattributed 'as small as 4'", "bug-body wording missing"])


if __name__ == "__main__":
    unittest.main()
