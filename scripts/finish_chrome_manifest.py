#!/usr/bin/env python3
"""Finishes an assembled Chrome bundle: declares its rulesets and stamps the
version, then checks it against Chrome's documented limits.

Split out of build_chrome.sh so the validation is testable and so the shell
script stays free of nested heredocs.

    python3 scripts/finish_chrome_manifest.py dist/chrome 1.0
"""

import json
import pathlib
import re
import sys

# Chrome guarantees an extension 30,000 static rules; more only from a shared
# pool it may not get. Each rule must stay under 2 KB compiled, and regex rules
# are capped at 1,000 — we use none, because `requestDomains` does host
# matching natively and far more cheaply.
MAX_STATIC_RULES = 30_000
MAX_RULE_BYTES = 2048
MAX_REGEX_RULES = 1_000


def finish(out: pathlib.Path, version: str) -> list[str]:
    manifest_path = out / "manifest.json"
    manifest = json.loads(manifest_path.read_text())

    rulesets = sorted((out / "rules").glob("*.json"))
    manifest["version"] = version
    manifest["declarative_net_request"]["rule_resources"] = [
        {"id": p.stem, "enabled": True, "path": f"rules/{p.name}"} for p in rulesets
    ]
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    return validate(out, manifest)


def validate(out: pathlib.Path, manifest: dict) -> list[str]:
    """Everything the Web Store or Chrome itself would reject us for."""
    errors: list[str] = []

    def require(path: str, why: str) -> None:
        if not (out / path).exists():
            errors.append(f"{why} references a missing file: {path}")

    require(manifest["background"]["service_worker"], "background")
    for script in manifest["content_scripts"]:
        for js in script["js"]:
            require(js, "content script")
    for path in manifest["icons"].values():
        require(path, "icons")
    require(manifest["action"]["default_popup"], "action popup")
    for entry in manifest["web_accessible_resources"]:
        for resource in entry["resources"]:
            require(resource, "web accessible resources")

    # ES module imports and classic <script src> both have to resolve, or the
    # extension loads and then silently does nothing.
    for js in out.glob("*.js"):
        text = js.read_text()
        for target in re.findall(r'(?:from|import)\s+"(\./[^"]+)"', text):
            require(target[2:], js.name)
    for html in (out / "pages").glob("*.html"):
        for src in re.findall(r'<script src="([^"]+)"', html.read_text()):
            if not (out / "pages" / src).resolve().exists():
                errors.append(f"{html.name} references a missing script: {src}")

    ids: set[int] = set()
    sizes: list[int] = []
    regex_rules = 0
    for entry in manifest["declarative_net_request"]["rule_resources"]:
        for rule in json.loads((out / entry["path"]).read_text()):
            if rule["id"] in ids:
                errors.append(f"duplicate rule id {rule['id']}")
            ids.add(rule["id"])
            sizes.append(len(json.dumps(rule)))
            if "regexFilter" in rule.get("condition", {}):
                regex_rules += 1

    if len(sizes) > MAX_STATIC_RULES:
        errors.append(f"{len(sizes):,} static rules exceeds Chrome's {MAX_STATIC_RULES:,} guarantee")
    oversized = [s for s in sizes if s > MAX_RULE_BYTES]
    if oversized:
        errors.append(f"{len(oversized)} rules exceed the {MAX_RULE_BYTES} byte ceiling")
    if regex_rules > MAX_REGEX_RULES:
        errors.append(f"{regex_rules} regex rules exceeds the {MAX_REGEX_RULES} cap")

    hosts = sum(len(v) for v in json.loads((out / "lists/hosts.json").read_text()).values())
    print(f"  {len(manifest['declarative_net_request']['rule_resources'])} rulesets, "
          f"{len(sizes):,} rules (largest {max(sizes) if sizes else 0} B), {hosts:,} hosts")
    return errors


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    out = pathlib.Path(sys.argv[1])
    errors = finish(out, sys.argv[2])
    for error in errors:
        print(f"  ✗ {error}", file=sys.stderr)
    if errors:
        return 1
    print("  ✓ manifest complete, every reference resolves, limits respected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
