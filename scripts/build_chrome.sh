#!/bin/zsh
# Assembles the Chrome extension from WebExtension/Shared + WebExtension/Chrome.
#
# Safari's copy is assembled by Xcode from the same Shared/ directory (see the
# BrowseGuardExtension-* targets in project.yml), so the two browsers ship the
# same orchestration, block page, popup and content script — only manifest.json
# and engine.js differ.
#
# There is no local installer for this, and that is Chrome's doing rather than
# an omission here: Chrome 44 removed external installs from a local .crx on
# macOS, and an external-extension entry's update URL must point at the Chrome
# Web Store. A sandboxed App Store app could not write into Chrome's support
# directory to place one anyway. So the Web Store listing *is* the installer,
# and `--package` produces the zip you upload to it.
#
#   ./scripts/build_chrome.sh              assemble into dist/chrome
#   ./scripts/build_chrome.sh --package    also produce a Web Store zip
#   ./scripts/build_chrome.sh some/dir     assemble elsewhere
set -e
cd "$(dirname "$0")/.."

PACKAGE=0
OUT="dist/chrome"
for arg in "$@"; do
  case "$arg" in
    --package) PACKAGE=1 ;;
    *) OUT="$arg" ;;
  esac
done

# Keep the extension's version in step with the apps, so someone comparing the
# two is not left guessing which is newer.
VERSION=$(awk -F'"' '/^    MARKETING_VERSION:/ {print $2}' project.yml)
[ -n "$VERSION" ] || VERSION="1.0"

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

# Splice the generated rulesets into the manifest and stamp the version.
python3 scripts/finish_chrome_manifest.py "$OUT" "$VERSION"

echo "Chrome extension assembled at $OUT (version $VERSION)"

if [ "$PACKAGE" = "1" ]; then
  ZIP="dist/browseguard-chrome-$VERSION.zip"
  rm -f "$ZIP"
  # Zipped from inside the directory: the Web Store expects manifest.json at
  # the archive root, not nested under a folder.
  (cd "$OUT" && zip -qr "../../$ZIP" . -x '.*' -x '__MACOSX/*')
  echo "Web Store package: $ZIP ($(du -h "$ZIP" | cut -f1 | tr -d ' '))"
  echo "Upload at https://chrome.google.com/webstore/devconsole"
fi
