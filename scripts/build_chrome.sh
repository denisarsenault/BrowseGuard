#!/bin/zsh
# Assembles the Chrome extension from WebExtension/Shared + WebExtension/Chrome.
#
# Safari's copy is assembled by Xcode from the same Shared/ directory (see the
# BrowseGuardExtension-* targets in project.yml), so the two browsers ship the
# same orchestration, block page, popup, content script and heuristics — only
# manifest.json and engine.js differ.
#
#   ./scripts/build_chrome.sh [output-dir]      default: dist/chrome
set -e
cd "$(dirname "$0")/.."
OUT="${1:-dist/chrome}"

rm -rf "$OUT"
mkdir -p "$OUT"

# Shared, browser-agnostic.
cp WebExtension/Shared/background.js "$OUT/"
cp WebExtension/Shared/content.js    "$OUT/"
cp WebExtension/Shared/compat.js     "$OUT/"
cp WebExtension/Shared/heuristics.js "$OUT/"
cp -R WebExtension/Shared/pages      "$OUT/"
cp -R WebExtension/Shared/images     "$OUT/"

# Chrome-specific.
cp WebExtension/Chrome/engine.js     "$OUT/"
cp WebExtension/Chrome/manifest.json "$OUT/"

# Lists and declarativeNetRequest rulesets, from the same feed pipeline that
# produces the Swift app's blocklists.
python3 scripts/build_feeds.py --chrome "$OUT" --base-url "" >/dev/null

# Splice the generated rulesets into the manifest.
python3 - "$OUT" <<'PY'
import json, pathlib, sys
out = pathlib.Path(sys.argv[1])
manifest = json.loads((out / "manifest.json").read_text())
resources = [
    {"id": p.stem, "enabled": True, "path": f"rules/{p.name}"}
    for p in sorted((out / "rules").glob("*.json"))
]
manifest["declarative_net_request"]["rule_resources"] = resources
(out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
rules = sum(len(json.loads(p.read_text())) for p in (out / "rules").glob("*.json"))
hosts = sum(len(v) for v in json.loads((out / "lists/hosts.json").read_text()).values())
print(f"  {len(resources)} rulesets, {rules:,} rules, {hosts:,} hosts")
PY

echo "Chrome extension assembled at $OUT"
