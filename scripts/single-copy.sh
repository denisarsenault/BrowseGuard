#!/bin/zsh
#
# Checks that exactly one BrowseGuard is installed, running, and registered with
# Safari on this Mac: the copy in /Applications.
#
# Xcode registers every build product with LaunchServices and PlugInKit, so each
# build leaves another copy that Safari can pick up. That is why two copies once
# showed up in Safari's extension list at the same time.
#
#   ./scripts/single-copy.sh          report only, changes nothing
#   ./scripts/single-copy.sh --fix    quit, unregister and move extra copies to the Trash
#
set -u

FIX=0
for arg in "$@"; do
  case "$arg" in
    --fix) FIX=1 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) print -u2 "unknown option: $arg"; exit 2 ;;
  esac
done

CANONICAL="/Applications/BrowseGuard.app"
BUNDLE_ID="com.mybrightzone.BrowseGuard"
LSREGISTER="/System/Library/Frameworks/CoreServices.framework/Versions/Current/Frameworks/LaunchServices.framework/Versions/Current/Support/lsregister"

# Where a build or a download is likely to leave a copy, each with a depth limit.
# A full home-directory walk takes minutes; these depths reach every place Xcode
# and the Finder actually put one (DerivedData/<project>/Build/Products/<config>/,
# and <repo>/build/<dir>/Build/Products/<config>/ two levels under ~/Developer).
SEARCH_SPECS=(
  "/Applications:2"
  "$HOME/Applications:2"
  "$HOME/Library/Developer/Xcode/DerivedData:6"
  "$HOME/Developer:7"
  "$HOME/Desktop:3"
  "$HOME/Downloads:3"
  "$HOME/Documents:3"
)

# --- Find every BrowseGuard app bundle --------------------------------------
# Matched by bundle identifier, not by name, so a renamed copy is still found.
# Dependency and VCS folders are pruned: they are large and never hold an app.
copies=()
for spec in $SEARCH_SPECS; do
  root="${spec%:*}"
  depth="${spec##*:}"
  [[ -d "$root" ]] || continue
  while IFS= read -r app; do
    id=$(plutil -extract CFBundleIdentifier raw "$app/Contents/Info.plist" 2>/dev/null)
    [[ "$id" == "$BUNDLE_ID" ]] && copies+=("$app")
  done < <(find "$root" -maxdepth "$depth" \( -name node_modules -o -name .git -o -name Pods \) -prune -o -name "*.app" -prune -print 2>/dev/null)
done

extras=()
for app in $copies; do
  [[ "$app" == "$CANONICAL" ]] || extras+=("$app")
done

# --- Running processes -------------------------------------------------------
# The Safari extensions run as separate processes and are expected. Only the
# app's own executable counts as a copy.
running=()
while IFS= read -r line; do
  pid="${line%% *}"
  exe="${line#* }"
  running+=("$pid|$exe")
done < <(ps -axo pid=,command= | awk '/\/BrowseGuard\.app\/Contents\/MacOS\/BrowseGuard( |$)/ {print $1" "substr($0, index($0,$2))}')

# --- Safari registrations ---------------------------------------------------
# Only the Safari extension points matter here, and only the paths they name.
registered=()
for point in com.apple.Safari.content-blocker com.apple.Safari.web-extension; do
  while IFS= read -r p; do
    [[ -n "$p" ]] && registered+=("$p")
  done < <(pluginkit -mAvvv -p "$point" 2>/dev/null | sed -n 's/^[[:space:]]*Path = //p' | grep "BrowseGuard" )
done

# --- Report -------------------------------------------------------------------
print "Installed copies:"
for app in $copies; do print "  ${app/#$HOME/~}"; done
(( ${#copies} == 0 )) && print "  none"

print "\nRunning processes:"
for entry in $running; do print "  pid ${entry%%|*}  ${${entry#*|}/#$HOME/~}"; done
(( ${#running} == 0 )) && print "  none"

print "\nSafari registrations:"
for p in $registered; do print "  ${p/#$HOME/~}"; done
(( ${#registered} == 0 )) && print "  none"

bad=0
(( ${#extras} > 0 )) && bad=1
for p in $registered; do [[ "$p" == "$CANONICAL"* ]] || bad=1; done
(( ${#running} > 1 )) && bad=1

print
if (( bad == 0 )); then
  print "OK: one copy, in /Applications, registered with Safari."
  exit 0
fi
print "Not single-copy."
(( ${#extras} > 0 )) && print "  extra installed copies: ${#extras}"
(( ${#running} > 1 )) && print "  running processes: ${#running}"
for p in $registered; do [[ "$p" == "$CANONICAL"* ]] || print "  registered outside /Applications: ${p/#$HOME/~}"; done

if (( ! FIX )); then
  print "\nNothing was changed. Re-run with --fix to correct this."
  exit 1
fi

# --- Fix ---------------------------------------------------------------------
# Quit first, or a running copy rewrites its App Group state on exit.
for entry in $running; do
  pid="${entry%%|*}"
  exe="${entry#*|}"
  [[ "$exe" == "$CANONICAL"* ]] && continue
  kill -TERM "$pid" 2>/dev/null && print "quit     pid $pid"
done
sleep 2

# Unregister before moving, or LaunchServices keeps a record of a path that no
# longer exists.
for p in $registered; do
  [[ "$p" == "$CANONICAL"* ]] && continue
  pluginkit -r "$p" 2>/dev/null
done
failed=0
for app in $extras; do
  "$LSREGISTER" -u "$app" >/dev/null 2>&1
  if osascript -e "tell application \"Finder\" to delete POSIX file \"$app\"" >/dev/null 2>&1; then
    print "trashed  ${app/#$HOME/~}"
  else
    # Finder automation is denied until the terminal is allowed to control Finder
    # (System Settings > Privacy & Security > Automation). Say so, rather than
    # reporting a clean result over a copy that is still on disk.
    print -u2 "could not move to Trash: ${app/#$HOME/~}"
    print -u2 "  allow your terminal to control Finder, or move it to the Trash by hand"
    failed=1
  fi
done

if (( failed )); then
  print -u2 "\nNot finished: some copies were left in place. Their registrations were removed."
  exit 1
fi

print "\nRe-check after Safari has reloaded its extension list (quit and reopen Safari):"
print "  ./scripts/single-copy.sh"
exit 0
