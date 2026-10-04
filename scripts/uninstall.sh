#!/bin/zsh
#
# Removes BrowseGuard and its Safari extensions from this Mac.
#
# Safety, in order of importance:
#
#   1. It does nothing by default. Run it to see a report; pass --yes to act.
#   2. It moves things to the Trash, not to /dev/null, so a mistake is
#      recoverable. --delete forces permanent removal instead.
#   3. It never touches Safari's own preferences. Safari's record of which
#      extensions exist goes away with the app bundle; editing Safari's
#      settings to force that would risk the user's other extensions.
#
# It also cannot remove anything from iCloud. If iCloud sync was on, settings,
# the allowlist and the block list are mirrored to the key-value store and will
# come back on reinstall — see the note the report prints.
#
#   ./scripts/uninstall.sh                  report only, changes nothing
#   ./scripts/uninstall.sh --yes            move everything to the Trash
#   ./scripts/uninstall.sh --yes --delete   permanent removal
#
set -u

APPLY=0
PERMANENT=0
for arg in "$@"; do
  case "$arg" in
    --yes) APPLY=1 ;;
    --delete) PERMANENT=1 ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    *) print -u2 "unknown option: $arg"; exit 2 ;;
  esac
done

# Matched explicitly rather than by a loose com.mybrightzone.* glob, so a
# different app from the same developer is never caught up in it. The four
# extension identifiers each get their own sandbox container.
BUNDLE_IDS=(
  com.mybrightzone.BrowseGuard
  com.mybrightzone.BrowseGuard.ContentBlocker
  com.mybrightzone.BrowseGuard.Extension
  com.mybrightzone.BrowseGuard.macContentBlocker
  com.mybrightzone.BrowseGuard.macExtension
)
APP_GROUP_SUFFIX="group.com.mybrightzone.BrowseGuard"

targets=()
add() { [[ -n "$1" && -e "$1" ]] && targets+=("$1") }

# --- Application ------------------------------------------------------------
# The extensions live inside the app bundle, so this takes them with it.
add "/Applications/BrowseGuard.app"
add "$HOME/Applications/BrowseGuard.app"

# --- Per-identifier user data ----------------------------------------------
for id in $BUNDLE_IDS; do
  add "$HOME/Library/Containers/$id"
  add "$HOME/Library/Preferences/$id.plist"
  add "$HOME/Library/Caches/$id"
  add "$HOME/Library/HTTPStorages/$id"
  add "$HOME/Library/HTTPStorages/$id.binarycookies"
  add "$HOME/Library/WebKit/$id"
  add "$HOME/Library/Saved Application State/$id.savedState"
done

# --- Shared containers ------------------------------------------------------
# Two forms exist in practice: the Team-ID prefixed one a signed build uses,
# and a bare one left behind by unsigned local builds. Both are ours.
group_containers=()
for dir in "$HOME/Library/Group Containers/"*"$APP_GROUP_SUFFIX"(N); do
  add "$dir"
  group_containers+=("$dir")
done

# --- Report -----------------------------------------------------------------
print
if (( ${#targets} == 0 )); then
  print "Nothing found. BrowseGuard does not appear to be installed."
  exit 0
fi

print "Found:"
for t in $targets; do
  size=$(du -sh "$t" 2>/dev/null | cut -f1 | tr -d ' ')
  printf "  %-8s %s\n" "${size:-?}" "${t/#$HOME/~}"
done

# Say what configuration is about to be lost. These are small files, but they
# are the only record of choices the user made by hand.
for dir in $group_containers; do
  for pair in "allowlist.json:allowed site" "userBlocklist.json:blocked site"; do
    file="${pair%%:*}"; label="${pair##*:}"
    entry="$dir/$file"
    [[ -e "$entry" ]] || continue
    # Counted by grepping the one key every entry has, rather than shelling
    # out to a JSON parser: multi-line Python inside a command substitution is
    # a quoting trap, and this needs no interpreter to be present.
    count=$(grep -o '"host"' "$entry" 2>/dev/null | wc -l | tr -d ' ')
    (( count > 0 )) && print "\n  $count $label(s) will be lost with ${dir:t}/$file"
  done
done

print
print "Not touched:"
print "  Safari's own settings. The extensions disappear with the app bundle;"
print "  editing Safari's preferences to force that would risk your others."
print "  iCloud. If sync was on, your settings and lists are mirrored to the"
print "  key-value store and will return if you reinstall. Turn sync off in the"
print "  app first if you want them gone for good."

# --- Act --------------------------------------------------------------------
print
if (( ! APPLY )); then
  print "Nothing was changed. Re-run with --yes to remove the items listed above."
  exit 0
fi

# Quit first, or the app rewrites its container on exit and leaves part of what
# we just removed behind.
pkill -x BrowseGuard 2>/dev/null
osascript -e 'tell application id "com.mybrightzone.BrowseGuard" to quit' >/dev/null 2>&1
sleep 1

remove() {
  # Deliberately not named `path`: in zsh that is tied to the PATH array, so
  # assigning to it wipes PATH and every command below becomes "not found" —
  # including the `rm` this function depends on.
  local item="$1"
  # A typo in a path variable should fail loudly, not delete something else.
  if [[ "$item" != "$HOME/"* && "$item" != /Applications/* ]]; then
    print -u2 "  refusing to remove outside HOME or /Applications: $item"
    return 1
  fi
  if (( PERMANENT )); then
    rm -rf "$item" && print "  removed  ${item/#$HOME/~}"
  else
    if osascript -e "tell application \"Finder\" to delete POSIX file \"$item\"" >/dev/null 2>&1; then
      print "  trashed  ${item/#$HOME/~}"
    else
      print -u2 "  could not move to Trash (grant Finder automation, or use --delete): $item"
      return 1
    fi
  fi
}

failed=0
for t in $targets; do
  remove "$t" || failed=1
done

print
if (( failed )); then
  print "Finished with errors. Some items were left in place; see above."
  exit 1
fi
print "BrowseGuard has been removed."
print "If Safari still lists the extensions, quit and reopen it."
