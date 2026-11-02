#!/usr/bin/env python3
"""Generate docs/index.html from data/ca-bundle-sources.json (stdlib only).

Usage: build_site.py          write docs/index.html
       build_site.py --check  exit 1 if docs/index.html is stale or data invalid
"""
import html
import json
import string
import sys
from pathlib import Path

import validate_data

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_PATH = Path(__file__).resolve().parent / "site_template.html"
OUTPUT_PATH = ROOT / "docs" / "index.html"

TRUST_LABELS = {
    "bundled": ("Bundled", "ships its own CA store, independent of the OS"),
    "os": ("OS store", "uses the operating system trust store (or is the OS store)"),
    "fallback": ("Fallback", "OS store first; own roots only when the OS has none"),
    "hybrid": ("Hybrid", "own store plus roots added to the OS by users or enterprises"),
    "configured": ("Configured", "no default roots; trusts only the CA file the operator configures"),
}
PLATFORM_LABELS = {
    "windows": "Windows", "macos": "macOS", "linux": "Linux", "android": "Android",
    "ios": "iOS", "chromeos": "ChromeOS", "freebsd": "FreeBSD", "embedded": "Embedded",
}
COLUMNS = (
    "Software", "Trust source", "Bundle origin", "Where the roots live",
    "Updates and revocation", "Override", "Remediation", "Notes and sources",
)

# Colour tokens. Every pair in CONTRAST_PAIRS must reach WCAG AA 4.5:1 in both themes.
LIGHT = {
    "bg": "#f5f6f8", "surface": "#ffffff", "row-alt": "#f0f2f5", "text": "#1b1e26",
    "muted": "#525a66", "border": "#c9ced6", "link": "#0b57d0", "accent": "#0b57d0",
    "header-bg": "#1b1e26", "header-fg": "#f5f6f8", "th-bg": "#e4e8ee", "th-fg": "#1b1e26",
    "code-bg": "#eceff3", "code-fg": "#1b1e26",
    "bundled-bg": "#b42318", "bundled-fg": "#ffffff", "os-bg": "#146c43", "os-fg": "#ffffff",
    "fallback-bg": "#8a4b00", "fallback-fg": "#ffffff", "hybrid-bg": "#0b57d0", "hybrid-fg": "#ffffff",
    "configured-bg": "#5b3e96", "configured-fg": "#ffffff",
    "unverified-bg": "#fff1c2", "unverified-fg": "#5c4300",
    "btn-bg": "#ffffff", "btn-fg": "#1b1e26", "btn-active-bg": "#0b57d0", "btn-active-fg": "#ffffff",
    "cta-bg": "#1b1e26", "cta-fg": "#f5f6f8", "cta-code-bg": "#2d323e", "cta-code-fg": "#f5f6f8",
    "focus": "#0b57d0",
}
DARK = {
    "bg": "#121418", "surface": "#1b1e25", "row-alt": "#22262e", "text": "#e6e8eb",
    "muted": "#a9b0bb", "border": "#3b414d", "link": "#8ab4f8", "accent": "#8ab4f8",
    "header-bg": "#0b0d10", "header-fg": "#e6e8eb", "th-bg": "#2a2f39", "th-fg": "#e6e8eb",
    "code-bg": "#2a2f39", "code-fg": "#e6e8eb",
    "bundled-bg": "#ffb4ab", "bundled-fg": "#2b0703", "os-bg": "#8fdcb0", "os-fg": "#062915",
    "fallback-bg": "#ffcf8a", "fallback-fg": "#2e1a00", "hybrid-bg": "#a8c7fa", "hybrid-fg": "#071d42",
    "configured-bg": "#d3bbff", "configured-fg": "#1f0a4a",
    "unverified-bg": "#4a3a00", "unverified-fg": "#ffe08a",
    "btn-bg": "#1b1e25", "btn-fg": "#e6e8eb", "btn-active-bg": "#a8c7fa", "btn-active-fg": "#071d42",
    "cta-bg": "#0b0d10", "cta-fg": "#e6e8eb", "cta-code-bg": "#2a2f39", "cta-code-fg": "#e6e8eb",
    "focus": "#8ab4f8",
}
CONTRAST_PAIRS = (
    ("text", "bg"), ("text", "surface"), ("text", "row-alt"),
    ("muted", "bg"), ("muted", "surface"), ("muted", "row-alt"),
    ("link", "bg"), ("link", "surface"), ("link", "row-alt"),
    ("header-fg", "header-bg"), ("th-fg", "th-bg"), ("code-fg", "code-bg"),
    ("bundled-fg", "bundled-bg"), ("os-fg", "os-bg"), ("fallback-fg", "fallback-bg"),
    ("hybrid-fg", "hybrid-bg"), ("configured-fg", "configured-bg"), ("unverified-fg", "unverified-bg"),
    ("btn-fg", "btn-bg"), ("btn-active-fg", "btn-active-bg"),
    ("cta-fg", "cta-bg"), ("cta-code-fg", "cta-code-bg"),
)


def esc(text):
    return html.escape(text, quote=True)


def inline(text):
    """Escape text; `backtick spans` become <code>."""
    parts = text.split("`")
    return "".join("<code>%s</code>" % esc(p) if i % 2 else esc(p) for i, p in enumerate(parts))


def opt(text):
    return inline(text) if text is not None else '<span class="na">Not applicable</span>'


def tokens_css(tokens, indent="  "):
    return "\n".join("%s--%s: %s;" % (indent, k, v) for k, v in tokens.items())


def source_list(sources, cls="sources"):
    items = "".join(
        '<li><a href="%s">%s</a> <span class="retrieved">retrieved %s</span></li>'
        % (esc(s["url"]), inline(s["title"]), esc(s["retrieved"]))
        for s in sources
    )
    return '<ul class="%s">%s</ul>' % (cls, items)


def render_row(e):
    label = TRUST_LABELS[e["trust_source"]][0]
    flag = ' <span class="tag-unverified">Unverified</span>' if not e["verified"] else ""
    plats = " · ".join(PLATFORM_LABELS[p] for p in e["platforms"])
    updates = inline(e["update_mechanism"])
    updates += '<br><span class="sub">Revocation channel: %s</span>' % esc(", ".join(e["revocation_channel"]))
    notes = []
    if not e["verified"]:
        notes.append('<p class="unverified-note"><strong>Unverified:</strong> %s</p>' % inline(e["unverified_note"]))
    if e["notes"] is not None:
        notes.append("<p>%s</p>" % inline(e["notes"]))
    if e["version_notes"] is not None:
        notes.append('<p><strong>Versions:</strong> %s</p>' % inline(e["version_notes"]))
    notes.append(source_list(e["sources"]))
    notes.append('<p class="sub">Last verified %s</p>' % esc(e["last_verified"]))
    cells = [
        '<th scope="row" id="%s"><span class="name">%s</span>%s<span class="platforms">%s</span></th>'
        % (esc(e["id"]), esc(e["name"]), flag, esc(plats)),
        '<td><span class="badge badge-%s">%s</span></td>' % (e["trust_source"], esc(label)),
        "<td>%s</td>" % opt(e["bundle_origin"]),
        "<td>%s</td>" % opt(e["location"]),
        "<td>%s</td>" % updates,
        "<td>%s</td>" % opt(e["override"]),
        "<td>%s</td>" % inline(e["remediation"]),
        '<td class="notes">%s</td>' % "".join(notes),
    ]
    return '<tr data-type="%s" data-entry="%s">%s</tr>' % (e["trust_source"], esc(e["id"]), "".join(cells))


def render_section(section, entries):
    cat = section["category"]
    head = "".join('<th scope="col">%s</th>' % esc(c) for c in COLUMNS)
    rows = "\n".join(render_row(e) for e in entries)
    return (
        '<section class="catalog" id="sec-{cat}" data-section="{cat}" aria-labelledby="h-{cat}">\n'
        '<h2 id="h-{cat}">{title}</h2>\n'
        '<div class="table-wrap" role="region" aria-labelledby="cap-{cat}" tabindex="0">\n'
        '<table>\n<caption id="cap-{cat}">{caption}</caption>\n'
        "<thead><tr>{head}</tr></thead>\n<tbody>\n{rows}\n</tbody>\n</table>\n</div>\n</section>"
    ).format(cat=cat, title=esc(section["title"]), caption=inline(section["caption"]), head=head, rows=rows)


def render_notice(n):
    paras = "\n".join("<p>%s</p>" % inline(p) for p in n["paragraphs"])
    return (
        '<section class="notice" id="%s" aria-labelledby="h-%s">\n<h2 id="h-%s">%s</h2>\n%s\n%s\n</section>'
        % (esc(n["id"]), esc(n["id"]), esc(n["id"]), esc(n["heading"]), paras, source_list(n["sources"]))
    )


def status_text(total):
    return "Showing all %d entries." % total


def render(data, template_text):
    meta = data["metadata"]
    entries = data["entries"]
    by_cat = {}
    for e in entries:
        by_cat.setdefault(e["category"], []).append(e)
    sections = "\n\n".join(
        render_section(s, by_cat[s["category"]]) for s in data["sections"] if s["category"] in by_cat
    )
    legend = "\n".join(
        '<li><span class="badge badge-%s">%s</span> %s</li>' % (k, esc(v[0]), esc(v[1]))
        for k, v in TRUST_LABELS.items()
    )
    buttons = '<button type="button" class="filter-btn" data-filter="all" aria-pressed="true">All</button>\n'
    buttons += "\n".join(
        '<button type="button" class="filter-btn" data-filter="%s" aria-pressed="false">%s</button>' % (k, esc(v[0]))
        for k, v in TRUST_LABELS.items()
    )
    inc = meta["incident"]
    glossary = "\n".join(
        "<dt>%s</dt><dd>%s</dd>" % (esc(g["term"]), inline(g["definition"])) for g in meta["glossary"]
    )
    out = string.Template(template_text).substitute(
        title=esc(meta["title"]),
        description=esc(meta["description"]),
        updated=esc(meta["updated"]),
        light_tokens=tokens_css(LIGHT),
        dark_tokens=tokens_css(DARK, "    "),
        dark_tokens_explicit=tokens_css(DARK),
        incident_name=esc(inc["name"]),
        incident_summary=inline(inc["summary"]),
        incident_sources=source_list(inc["sources"]),
        keys=inc["compromised_keys"],
        tls_keys=inc["tls_keys"],
        cs_keys=inc["code_signing_keys"],
        certs=inc["ca_certificates"],
        legend=legend,
        filter_buttons=buttons,
        status=esc(status_text(len(entries))),
        sections=sections,
        notices="\n\n".join(render_notice(n) for n in meta["notices"]),
        glossary=glossary,
        total=len(entries),
    )
    return out


def build():
    data, schema = validate_data.load()
    errs = validate_data.validate(data, schema)
    if errs:
        raise SystemExit("data invalid:\n" + "\n".join(errs))
    return render(data, TEMPLATE_PATH.read_text(encoding="utf-8"))


def is_stale(generated, path=OUTPUT_PATH):
    return not path.exists() or path.read_text(encoding="utf-8") != generated


def main(argv):
    out = build()
    if "--check" in argv:
        if is_stale(out):
            print("docs/index.html is stale: run python3 tools/build_site.py", file=sys.stderr)
            return 1
        print("docs/index.html is up to date")
        return 0
    with open(OUTPUT_PATH, "w", encoding="utf-8", newline="\n") as f:
        f.write(out)
    print("wrote %s" % OUTPUT_PATH)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
