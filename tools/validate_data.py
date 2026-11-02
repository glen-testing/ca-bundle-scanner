#!/usr/bin/env python3
"""Validate data/ca-bundle-sources.json against its JSON Schema (stdlib only).

Implements the JSON Schema 2020-12 keywords the schema uses, plus semantic
checks a schema cannot express (unique names, section coverage, date order).
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT / "data" / "ca-bundle-sources.json"
SCHEMA_PATH = ROOT / "data" / "ca-bundle-sources.schema.json"

_TYPES = {
    "object": lambda v: isinstance(v, dict),
    "array": lambda v: isinstance(v, list),
    "string": lambda v: isinstance(v, str),
    "boolean": lambda v: isinstance(v, bool),
    "integer": lambda v: isinstance(v, int) and not isinstance(v, bool),
    "null": lambda v: v is None,
}
SUPPORTED = {
    "$schema", "$id", "$defs", "$ref", "title", "description", "type", "enum", "const",
    "required", "properties", "additionalProperties", "items", "minItems", "uniqueItems",
    "minLength", "minimum", "pattern", "if", "then", "else",
}


def _resolve(ref, root):
    if not ref.startswith("#/"):
        raise ValueError("only local $ref supported: " + ref)
    node = root
    for part in ref[2:].split("/"):
        node = node[part]
    return node


def schema_errors(value, schema, root=None, path="$"):
    """Return a list of 'path: message' strings; empty means valid."""
    root = schema if root is None else root
    unknown = set(schema) - SUPPORTED
    if unknown:
        raise ValueError("unsupported schema keywords at %s: %s" % (path, sorted(unknown)))
    if "$ref" in schema:
        return schema_errors(value, _resolve(schema["$ref"], root), root, path)
    errs = []
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_TYPES[t](value) for t in types):
            return ["%s: expected type %s, got %r" % (path, "/".join(types), value)]
    if "enum" in schema and value not in schema["enum"]:
        errs.append("%s: %r not in enum %s" % (path, value, schema["enum"]))
    if "const" in schema and value != schema["const"]:
        errs.append("%s: expected const %r" % (path, schema["const"]))
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            errs.append("%s: string shorter than %d" % (path, schema["minLength"]))
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errs.append("%s: %r does not match %s" % (path, value, schema["pattern"]))
    if _TYPES["integer"](value) and "minimum" in schema and value < schema["minimum"]:
        errs.append("%s: %d below minimum %d" % (path, value, schema["minimum"]))
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errs.append("%s: missing required property %r" % (path, key))
        props = schema.get("properties", {})
        for key, sub in value.items():
            if key in props:
                errs.extend(schema_errors(sub, props[key], root, "%s.%s" % (path, key)))
            elif schema.get("additionalProperties") is False:
                errs.append("%s: unexpected property %r" % (path, key))
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            errs.append("%s: fewer than %d items" % (path, schema["minItems"]))
        if schema.get("uniqueItems"):
            seen = [json.dumps(v, sort_keys=True) for v in value]
            if len(seen) != len(set(seen)):
                errs.append("%s: items are not unique" % path)
        if "items" in schema:
            for i, item in enumerate(value):
                errs.extend(schema_errors(item, schema["items"], root, "%s[%d]" % (path, i)))
    if "if" in schema:
        branch = "then" if not schema_errors(value, schema["if"], root, path) else "else"
        if branch in schema:
            errs.extend(schema_errors(value, schema[branch], root, path))
    return errs


def _strings(node, path="$"):
    if isinstance(node, str):
        yield path, node
    elif isinstance(node, dict):
        for k, v in node.items():
            yield from _strings(v, "%s.%s" % (path, k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _strings(v, "%s[%d]" % (path, i))


def semantic_errors(data):
    """Checks outside JSON Schema: uniqueness, coverage, dates, markup."""
    errs = []
    entries = data.get("entries", [])
    for field in ("id", "name"):
        seen = {}
        for i, e in enumerate(entries):
            key = str(e.get(field, "")).casefold()
            if key in seen:
                errs.append("$.entries[%d]: duplicate %s %r (first at [%d])" % (i, field, e.get(field), seen[key]))
            seen.setdefault(key, i)
    cats = [s.get("category") for s in data.get("sections", [])]
    if len(cats) != len(set(cats)):
        errs.append("$.sections: duplicate category")
    for i, e in enumerate(entries):
        if e.get("category") not in cats:
            errs.append("$.entries[%d]: category %r has no section" % (i, e.get("category")))
        lv = e.get("last_verified", "")
        for j, s in enumerate(e.get("sources", [])):
            if isinstance(s, dict) and str(s.get("retrieved", "")) > str(lv):
                errs.append("$.entries[%d].sources[%d]: retrieved after last_verified" % (i, j))
        chans = e.get("revocation_channel", [])
        if "none" in chans and len(chans) > 1:
            errs.append("$.entries[%d]: revocation_channel mixes 'none' with channels" % i)
    updated = data.get("metadata", {}).get("updated", "")
    for i, e in enumerate(entries):
        if str(e.get("last_verified", "")) > str(updated):
            errs.append("$.entries[%d]: last_verified after metadata.updated" % i)
    inc = data.get("metadata", {}).get("incident", {})
    if inc and inc.get("tls_keys", 0) + inc.get("code_signing_keys", 0) != inc.get("compromised_keys"):
        errs.append("$.metadata.incident: tls_keys + code_signing_keys != compromised_keys")
    for path, s in _strings(data):
        if s.strip().upper() in ("N/A", "NA", "-", "—"):
            errs.append("%s: use null instead of placeholder %r" % (path, s))
        if s.count("`") % 2:
            errs.append("%s: unbalanced backtick" % path)
    return errs


def validate(data, schema):
    return schema_errors(data, schema) + semantic_errors(data)


def load():
    with open(DATA_PATH, encoding="utf-8") as f:
        data = json.load(f)
    with open(SCHEMA_PATH, encoding="utf-8") as f:
        schema = json.load(f)
    return data, schema


def main():
    data, schema = load()
    errs = validate(data, schema)
    for e in errs:
        print(e, file=sys.stderr)
    print("%s: %d entries, %d errors" % (DATA_PATH.name, len(data.get("entries", [])), len(errs)))
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
