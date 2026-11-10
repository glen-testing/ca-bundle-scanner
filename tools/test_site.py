"""Site tests: generated page freshness, row parity with JSON, WCAG contrast,
accessibility markup, phone-width layout rules and the filter logic.

True-positive tests run on docs/index.html; false-positive tests run on a
mutated copy or on the legacy hand-written page (tools/testdata/).
"""
import copy
import json
import re
import shutil
import subprocess
import tempfile
import unittest
from html.parser import HTMLParser
from pathlib import Path

import build_site
import validate_data

HERE = Path(__file__).resolve().parent
LEGACY_HTML = HERE / "testdata" / "legacy-index.html"


class PageModel(HTMLParser):
    """Collects the structures the tests assert on."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = []
        self.sections = []  # [(category, [row dict])]
        self.style_attrs = 0
        self.event_attrs = 0
        self.th_without_scope = 0
        self.tables = 0
        self.captions = 0
        self.meta_description = None
        self.icon_href = None
        self.buttons = []
        self.live_region = None
        self.css = ""
        self.scripts = []
        self._in_style = self._in_script = False
        self._row = None
        self._in_row_th = False
        self._in_name = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        self.tags.append(tag)
        if "style" in a:
            self.style_attrs += 1
        self.event_attrs += sum(1 for k in a if k.startswith("on"))
        if tag == "section" and "data-section" in a:
            self.sections.append((a["data-section"], []))
        elif tag == "tr" and "data-entry" in a:
            self._row = {"id": a["data-entry"], "type": a.get("data-type"), "name": ""}
        elif tag == "th":
            if "scope" not in a:
                self.th_without_scope += 1
            if self._row is not None and a.get("scope") == "row":
                self._in_row_th = True
        elif tag == "span" and self._in_row_th and a.get("class") == "name":
            self._in_name = True
        elif tag == "table":
            self.tables += 1
        elif tag == "caption":
            self.captions += 1
        elif tag == "meta" and a.get("name") == "description":
            self.meta_description = a.get("content")
        elif tag == "link" and a.get("rel") == "icon":
            self.icon_href = a.get("href")
        elif tag == "button":
            self.buttons.append(a)
        elif tag == "style":
            self._in_style = True
        elif tag == "script":
            self._in_script = True
            self.scripts.append("")
        if a.get("role") == "status":
            self.live_region = a

    def handle_endtag(self, tag):
        if tag == "style":
            self._in_style = False
        elif tag == "script":
            self._in_script = False
        elif tag == "span":
            self._in_name = False
        elif tag == "th":
            self._in_row_th = False
        elif tag == "tr" and self._row is not None:
            if self.sections:
                self.sections[-1][1].append(self._row)
            self._row = None

    def handle_data(self, data):
        if self._in_style:
            self.css += data
        elif self._in_script:
            self.scripts[-1] += data
        elif self._in_name and self._row is not None:
            self._row["name"] += data


def parse(text):
    p = PageModel()
    p.feed(text)
    p.close()
    return p


def expected_rows(data):
    by_cat = {}
    for e in data["entries"]:
        by_cat.setdefault(e["category"], []).append(
            {"id": e["id"], "type": e["trust_source"], "name": e["name"]})
    return [(s["category"], by_cat[s["category"]]) for s in data["sections"] if s["category"] in by_cat]


def row_mismatches(data, page):
    """Differences between JSON entries and HTML rows, per section."""
    want, got = expected_rows(data), page.sections
    probs = []
    if [c for c, _ in want] != [c for c, _ in got]:
        probs.append("section order/categories differ")
    for (wc, wrows), (gc, grows) in zip(want, got):
        if len(wrows) != len(grows):
            probs.append("%s: %d JSON rows vs %d HTML rows" % (wc, len(wrows), len(grows)))
        for w, g in zip(wrows, grows):
            if w != g:
                probs.append("%s: %r != %r" % (wc, w, g))
    return probs


# ---- contrast ----------------------------------------------------------------

def _lin(c):
    c = c / 255.0
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def luminance(hex_color):
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _lin(r) + 0.7152 * _lin(g) + 0.0722 * _lin(b)


def contrast(fg, bg):
    a, b = sorted((luminance(fg), luminance(bg)), reverse=True)
    return (a + 0.05) / (b + 0.05)


TOKEN_RE = re.compile(r"--([a-z0-9-]+):\s*([^;]+);")
BLOCKS = {
    "light": re.compile(r"^:root \{(.*?)\}", re.S | re.M),
    "dark-media": re.compile(
        r'@media \(prefers-color-scheme: dark\) \{\s*:root:not\(\[data-theme="light"\]\) \{(.*?)\}', re.S),
    "dark-explicit": re.compile(r':root\[data-theme="dark"\] \{(.*?)\}', re.S),
}


def theme_tokens(css):
    out = {}
    for name, rx in BLOCKS.items():
        m = rx.search(css)
        out[name] = dict(TOKEN_RE.findall(m.group(1))) if m else None
    return out


def contrast_failures(css, pairs=build_site.CONTRAST_PAIRS, minimum=4.5):
    blocks = theme_tokens(css)
    fails = [("structure", n) for n, b in blocks.items() if not b]
    if fails:
        return fails
    if blocks["dark-media"] != blocks["dark-explicit"]:
        fails.append(("structure", "dark token blocks differ"))
    themes = {"light": blocks["light"], "dark": dict(blocks["light"], **blocks["dark-media"])}
    for theme, toks in themes.items():
        for fg, bg in pairs:
            f, b = toks.get(fg, ""), toks.get(bg, "")
            if not (re.fullmatch(r"#[0-9a-fA-F]{6}", f) and re.fullmatch(r"#[0-9a-fA-F]{6}", b)):
                fails.append((theme, fg, bg, "missing or non-hex token"))
                continue
            ratio = contrast(f, b)
            if ratio < minimum:
                fails.append((theme, fg, bg, round(ratio, 2)))
    return fails


class Freshness(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data, cls.schema = validate_data.load()
        cls.template = build_site.TEMPLATE_PATH.read_text(encoding="utf-8")
        cls.generated = build_site.render(cls.data, cls.template)

    def test_tp_committed_page_matches_json(self):
        self.assertFalse(build_site.is_stale(self.generated), "run python3 tools/build_site.py")

    def test_tp_generation_is_deterministic(self):
        self.assertEqual(self.generated, build_site.render(copy.deepcopy(self.data), self.template))

    def test_fp_stale_page_detected(self):
        changed = copy.deepcopy(self.data)
        changed["entries"][0]["remediation"] += " Changed."
        self.assertTrue(build_site.is_stale(build_site.render(changed, self.template)))

    def test_fp_stale_file_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            stale = Path(tmp) / "index.html"
            stale.write_text(self.generated.replace("CA Bundle Tracker", "CA Bundle Tracker (old)", 1), encoding="utf-8")
            self.assertTrue(build_site.is_stale(self.generated, stale))
            self.assertTrue(build_site.is_stale(self.generated, Path(tmp) / "missing.html"))

    def test_tp_check_cli_passes(self):
        self.assertEqual(build_site.main(["--check"]), 0)


class RowParity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data, _ = validate_data.load()
        cls.page = parse(build_site.OUTPUT_PATH.read_text(encoding="utf-8"))

    def test_tp_rows_equal_json(self):
        self.assertEqual(row_mismatches(self.data, self.page), [])
        n_html = sum(len(r) for _, r in self.page.sections)
        self.assertEqual(n_html, len(self.data["entries"]))

    def test_fp_json_entry_missing_from_html_detected(self):
        extra = copy.deepcopy(self.data)
        clone = copy.deepcopy(extra["entries"][0])
        clone["id"], clone["name"] = "not-on-page", "Not on page"
        extra["entries"].append(clone)
        self.assertTrue(row_mismatches(extra, self.page))

    def test_fp_html_row_dropped_detected(self):
        html_text = build_site.OUTPUT_PATH.read_text(encoding="utf-8")
        first = re.search(r'<tr data-type="[^"]+" data-entry="[^"]+">.*?</tr>\n', html_text).group(0)
        self.assertTrue(row_mismatches(self.data, parse(html_text.replace(first, "", 1))))

    def test_fp_legacy_page_diverges(self):
        self.assertTrue(row_mismatches(self.data, parse(LEGACY_HTML.read_text(encoding="utf-8"))))


class Contrast(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.css = parse(build_site.OUTPUT_PATH.read_text(encoding="utf-8")).css

    def test_tp_all_pairs_pass_both_themes(self):
        self.assertEqual(contrast_failures(self.css), [])

    def test_tp_reference_ratios(self):
        self.assertAlmostEqual(contrast("#000000", "#ffffff"), 21.0, places=2)
        self.assertAlmostEqual(contrast("#ffffff", "#ffffff"), 1.0, places=2)

    def test_fp_failing_dark_badge_detected(self):
        bad = self.css.replace("--bundled-fg: #2b0703;", "--bundled-fg: #ffffff;")
        fails = contrast_failures(bad)
        self.assertIn(("dark", "bundled-fg", "bundled-bg"), [f[:3] for f in fails])

    def test_fp_failing_light_muted_detected(self):
        bad = self.css.replace("--muted: #525a66;", "--muted: #6c757d;", 1)
        self.assertIn(("light", "muted", "bg"), [f[:3] for f in contrast_failures(bad)])

    def test_fp_missing_dark_guard_detected(self):
        bad = self.css.replace(':root:not([data-theme="light"])', ":root")
        self.assertIn(("structure", "dark-media"), contrast_failures(bad))

    def test_fp_legacy_css_fails(self):
        legacy_css = parse(LEGACY_HTML.read_text(encoding="utf-8")).css
        self.assertTrue(contrast_failures(legacy_css))


def a11y_problems(page):
    probs = []
    if "main" not in page.tags:
        probs.append("no <main>")
    if page.tables == 0 or page.captions != page.tables:
        probs.append("tables %d vs captions %d" % (page.tables, page.captions))
    if page.th_without_scope:
        probs.append("%d th without scope" % page.th_without_scope)
    if not page.meta_description:
        probs.append("no meta description")
    if not (page.icon_href or "").startswith("data:image/svg+xml"):
        probs.append("no inline SVG favicon")
    if page.style_attrs or page.event_attrs:
        probs.append("inline style/event attributes")
    if not page.buttons or any(b.get("aria-pressed") not in ("true", "false") for b in page.buttons
                               if "data-filter" in b):
        probs.append("filter buttons lack aria-pressed")
    if not page.live_region or page.live_region.get("aria-live") != "polite":
        probs.append("no polite live region")
    for cat, rows in page.sections:
        if any(r["type"] not in build_site.TRUST_LABELS for r in rows):
            probs.append("%s: row without a valid data-type" % cat)
    return probs


class Accessibility(unittest.TestCase):
    def test_tp_generated_page(self):
        page = parse(build_site.OUTPUT_PATH.read_text(encoding="utf-8"))
        self.assertEqual(a11y_problems(page), [])
        self.assertTrue(any(c == "operating_system" for c, _ in page.sections))

    def test_fp_legacy_page(self):
        probs = a11y_problems(parse(LEGACY_HTML.read_text(encoding="utf-8")))
        for p in ("no <main>", "no meta description", "no inline SVG favicon", "inline style/event attributes"):
            self.assertIn(p, probs)

    def test_fp_missing_caption_detected(self):
        html_text = build_site.OUTPUT_PATH.read_text(encoding="utf-8")
        broken = re.sub(r"<caption[^>]*>.*?</caption>", "", html_text, count=1)
        self.assertTrue(any(p.startswith("tables") for p in a11y_problems(parse(broken))))

    def test_tp_scanner_box_command(self):
        html_text = build_site.OUTPUT_PATH.read_text(encoding="utf-8")
        self.assertIn("ca-bundle-scanner --profile emudhra", html_text)
        self.assertIn("cargo install --path scanner", html_text)
        self.assertNotIn("emudhra-scanner", html_text)
        self.assertIn("emudhra-scanner", LEGACY_HTML.read_text(encoding="utf-8"))


class Wording(unittest.TestCase):
    """D15: the commenter's 'as small as 4' must not appear as a bug-body claim."""

    def test_tp_generated_page(self):
        self.assertNotIn("as small as 4", build_site.OUTPUT_PATH.read_text(encoding="utf-8"))

    def test_fp_legacy_page(self):
        self.assertIn("as small as 4", LEGACY_HTML.read_text(encoding="utf-8"))


CI_PATH = HERE.parent / ".github" / "workflows" / "ci.yml"
CI_REQUIRED = (
    "cargo fmt --all --check", "cargo clippy --release --workspace --all-targets -- -D warnings",
    "cargo test --release --workspace",
    "working-directory: scanner", "tools/validate_data.py", "tools/build_site.py --check",
    "python3 -m unittest discover -s tools", "lycheeverse/lychee-action",
)


def ci_missing(text):
    return [s for s in CI_REQUIRED if s not in text]


class ContinuousIntegration(unittest.TestCase):
    """D23: the workflow runs the scanner checks, data/site tests and link check."""

    def test_tp_workflow_has_all_jobs(self):
        self.assertEqual(ci_missing(CI_PATH.read_text(encoding="utf-8")), [])

    def test_fp_stripped_workflow_detected(self):
        text = CI_PATH.read_text(encoding="utf-8").replace("cargo test --release --workspace", "")
        self.assertEqual(ci_missing(text), ["cargo test --release --workspace"])


def layout_problems(css):
    probs = []
    if "position: sticky" in css or "position:sticky" in css:
        probs.append("sticky inside an overflow wrapper never sticks")
    m = re.search(r"\.scanner-cta pre \{(.*?)\}", css, re.S)
    if not m or "overflow-wrap: anywhere" not in m.group(1) or "max-width: 100%" not in m.group(1):
        probs.append("command box can overflow phone width")
    return probs


class Layout(unittest.TestCase):
    def test_tp_generated_css(self):
        self.assertEqual(layout_problems(parse(build_site.OUTPUT_PATH.read_text(encoding="utf-8")).css), [])

    def test_fp_legacy_css(self):
        self.assertEqual(len(layout_problems(parse(LEGACY_HTML.read_text(encoding="utf-8")).css)), 2)


@unittest.skipUnless(shutil.which("node"), "node not installed")
class FilterLogic(unittest.TestCase):
    """Runs the page's own visibility() in Node with the page's row types."""

    @classmethod
    def setUpClass(cls):
        page = parse(build_site.OUTPUT_PATH.read_text(encoding="utf-8"))
        cls.script = page.scripts[-1]
        cls.types = [[r["type"] for r in rows] for _, rows in page.sections]

    def run_filter(self, flt, types):
        harness = "%s\nconsole.log(JSON.stringify(globalThis.caBundleVisibility(%s, %s)));" % (
            self.script, json.dumps(flt), json.dumps(types))
        out = subprocess.run(["node", "-e", harness], capture_output=True, text=True, check=True, timeout=30)
        return json.loads(out.stdout)

    def test_tp_filter_hides_empty_sections(self):
        for flt in build_site.TRUST_LABELS:
            v = self.run_filter(flt, self.types)
            for i, types in enumerate(self.types):
                self.assertEqual(v["sections"][i], flt in types)
            self.assertEqual(v["count"], sum(t.count(flt) for t in self.types))

    def test_fp_all_shows_everything(self):
        v = self.run_filter("all", self.types)
        self.assertTrue(all(v["sections"]))
        self.assertEqual(v["count"], sum(len(t) for t in self.types))

    def test_fp_section_with_match_stays_visible(self):
        v = self.run_filter("os", [["bundled", "os"], ["bundled"]])
        self.assertEqual(v["sections"], [True, False])
        self.assertEqual(v["rows"], [[False, True], [False]])


if __name__ == "__main__":
    unittest.main()
