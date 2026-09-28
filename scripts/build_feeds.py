#!/usr/bin/env python3
"""Builds BrowseGuard blocklist feeds from upstream sources.

Fetches permissively-licensed hosts/domain lists, normalizes them the same way
`URLNormalizer.canonicalHost` does in the app, validates them, and emits both
the bundled baseline (`Shared/Resources/Blocklists/*.json`) and the hosted
update feed (`dist/`).

The validation is the point. A blocklist pipeline that publishes whatever it
downloaded is how a security app ends up blocking apple.com because an upstream
feed got poisoned, or silently shipping an empty list because a mirror returned
a 200 with an error page. Every feed must clear a floor, a shrink limit, and a
guard list before anything is written.

Usage:
    python3 scripts/build_feeds.py --base-url https://example.github.io/BrowseGuard
    python3 scripts/build_feeds.py --check-only      # validate, write nothing
    python3 scripts/build_feeds.py --update-bundled  # also refresh the baseline
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import sys
import urllib.error
import urllib.request

REPO = pathlib.Path(__file__).resolve().parent.parent
BUNDLED = REPO / "Shared" / "Resources" / "Blocklists"
DIST = REPO / "dist"

USER_AGENT = "BrowseGuard-feed-builder/1.0 (+https://gitlab.com/malware-filter)"
TIMEOUT = 60


# --------------------------------------------------------------------------
# Never block these, whatever an upstream feed says.
#
# A compromised or careless feed that lists apple.com would break software
# updates, iCloud, and the App Store on every device running BrowseGuard. The
# blast radius of that is far worse than missing one real threat, so a guard
# hit is treated as evidence the feed is bad and rejects the whole build.
#
# Kept deliberately short. Over-guarding quietly defeats the blocklist; the
# user's own allowlist is the right tool for everything else.
# --------------------------------------------------------------------------
GUARDED_DOMAINS = frozenset({
    "apple.com", "icloud.com", "mzstatic.com", "cdn-apple.com",
    "google.com", "gstatic.com", "googleapis.com",
    "microsoft.com", "windowsupdate.com", "live.com",
    "cloudflare.com", "mozilla.org", "mozilla.com",
    "github.com", "githubusercontent.com",
    "digicert.com", "letsencrypt.org", "ocsp.apple.com",
})

# Guard hits below these thresholds are dropped as ordinary upstream false
# positives; above them the feed is treated as poisoned and rejected whole.
GUARD_HIT_LIMIT = 5
GUARD_HIT_FRACTION = 0.001


class FeedSpec:
    """One upstream source and the rules it has to satisfy."""

    def __init__(
        self,
        identifier: str,
        name: str,
        category: str,
        mirrors: list[str],
        fmt: str,
        min_entries: int,
        attribution: str,
        licence: str,
        max_age_days: int | None = 7,
        max_shrink: float = 0.5,
        snapshot: bool = False,
    ):
        self.identifier = identifier
        self.name = name
        self.category = category
        self.mirrors = mirrors
        self.fmt = fmt
        self.min_entries = min_entries
        self.attribution = attribution
        self.licence = licence
        # None disables the freshness check.
        self.max_age_days = max_age_days
        # Reject a build where the feed lost more than this fraction of its
        # entries. A sudden collapse means a broken upstream, not good news.
        self.max_shrink = max_shrink
        # A feed whose upstream has stopped updating. Still shipped, but its
        # staleness is reported rather than treated as a build failure.
        self.snapshot = snapshot


FEEDS = [
    FeedSpec(
        identifier="malware",
        name="Online Malicious Domains (urlhaus-filter)",
        category="malware",
        mirrors=[
            "https://malware-filter.gitlab.io/urlhaus-filter/urlhaus-filter-domains-online.txt",
            "https://malware-filter.pages.dev/urlhaus-filter-domains-online.txt",
            "https://curbengh.github.io/urlhaus-filter/urlhaus-filter-domains-online.txt",
        ],
        fmt="domains",
        min_entries=300,
        attribution="malware-filter / abuse.ch URLhaus",
        licence="MIT",
    ),
    FeedSpec(
        identifier="scam",
        name="Phishing Domains (phishing-filter)",
        category="scam",
        mirrors=[
            "https://malware-filter.gitlab.io/phishing-filter/phishing-filter-domains.txt",
            "https://malware-filter.pages.dev/phishing-filter-domains.txt",
            "https://curbengh.github.io/phishing-filter/phishing-filter-domains.txt",
        ],
        fmt="domains",
        min_entries=5000,
        attribution="malware-filter (OpenPhish, IPThreat, PhishTank)",
        licence="MIT",
    ),
    FeedSpec(
        identifier="cryptojacking",
        name="NoCoin Cryptominer List",
        category="cryptojacking",
        mirrors=[
            "https://raw.githubusercontent.com/hoshsadiq/adblock-nocoin-list/master/hosts.txt",
        ],
        fmt="hosts",
        min_entries=100,
        attribution="hoshsadiq/adblock-nocoin-list",
        licence="MIT",
        # Last touched March 2025. Cryptominer kits do turn over more slowly
        # than phishing domains, so the data has not rotted the way a stale
        # phishing feed would — but 18 months without a change is a snapshot,
        # not a live feed, and calling it one would be dishonest. Labelled as
        # such rather than raising the age limit until the check passes.
        snapshot=True,
        max_age_days=None,
    ),
    FeedSpec(
        identifier="pup",
        name="PUP Domains (static snapshot)",
        category="pup",
        mirrors=[
            "https://malware-filter.gitlab.io/pup-filter/pup-filter-domains.txt",
            "https://malware-filter.pages.dev/pup-filter-domains.txt",
        ],
        fmt="domains",
        min_entries=100,
        attribution="malware-filter / malware-discoverer",
        licence="MIT",
        # Upstream paused daily updates in May 2023 and has not resumed. The
        # data is still valid as far as it goes, but it is a frozen snapshot,
        # not a live feed, and is labelled as one everywhere it surfaces.
        snapshot=True,
        max_age_days=None,
    ),
]


# --------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------

def fetch(spec: FeedSpec) -> tuple[str, str]:
    """Returns (body, mirror_used). Tries each mirror before giving up."""
    errors = []
    for url in spec.mirrors:
        try:
            request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
                body = response.read().decode("utf-8", errors="replace")
            # A mirror serving an error page still returns 200 sometimes.
            if len(body) < 200:
                raise ValueError(f"suspiciously short body ({len(body)} bytes)")
            return body, url
        except (urllib.error.URLError, ValueError, TimeoutError, OSError) as error:
            errors.append(f"  {url}: {error}")
    raise RuntimeError(f"all mirrors failed for {spec.identifier}:\n" + "\n".join(errors))


UPDATED_PATTERNS = [
    (re.compile(r"^#\s*Updated:\s*(\S+)", re.M), "%Y-%m-%dT%H:%M:%SZ"),
    (re.compile(r"^#\s*Last modified:\s*(.+)$", re.M), "%d %B %Y"),
]


def upstream_updated_at(body: str) -> dt.datetime | None:
    """Reads the feed's own 'Updated:' header. Formats differ per publisher."""
    for pattern, fmt in UPDATED_PATTERNS:
        match = pattern.search(body)
        if not match:
            continue
        try:
            return dt.datetime.strptime(match.group(1).strip(), fmt).replace(
                tzinfo=dt.timezone.utc
            )
        except ValueError:
            continue
    return None


# --------------------------------------------------------------------------
# Parsing and normalization
#
# Must agree with URLNormalizer.canonicalHost in the app. If these two drift,
# a rule compiles that the engine will never match.
# --------------------------------------------------------------------------

HOST_RE = re.compile(r"^[a-z0-9._-]+$")
NON_HOSTS = frozenset({
    "localhost", "localhost.localdomain", "local",
    "broadcasthost", "ip6-localhost", "ip6-loopback", "0.0.0.0",
})


def canonical_host(raw: str) -> str | None:
    host = raw.strip().lower().rstrip(".")
    if not host or host in NON_HOSTS:
        return None
    if host.startswith("www."):
        host = host[4:]
    if not host or "." not in host:
        return None
    if not HOST_RE.match(host):
        return None
    return host


def parse(body: str, fmt: str) -> set[str]:
    hosts: set[str] = set()
    for line in body.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        if fmt == "hosts":
            parts = line.split()
            if len(parts) < 2:
                continue
            candidates = parts[1:]
        else:
            candidates = [line]
        for candidate in candidates:
            host = canonical_host(candidate)
            if host:
                hosts.add(host)
    return hosts


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

class ValidationError(Exception):
    pass


def guard_hits(hosts: set[str]) -> list[str]:
    hits = []
    for host in hosts:
        for guarded in GUARDED_DOMAINS:
            if host == guarded or host.endswith("." + guarded):
                hits.append(host)
                break
    return sorted(hits)


def validate(spec: FeedSpec, hosts: set[str], previous: dict | None, body: str) -> list[str]:
    """Raises on anything disqualifying. Returns non-fatal warnings.

    Mutates `hosts` to drop guarded domains — see below.
    """
    warnings: list[str] = []

    if len(hosts) < spec.min_entries:
        raise ValidationError(
            f"{spec.identifier}: {len(hosts)} entries is below the floor of {spec.min_entries}"
        )

    # A handful of guard hits is an ordinary false positive — big phishing
    # feeds aggregate from sources that occasionally scoop up a CDN or metrics
    # subdomain. Dropping those entries and keeping the other 40,000 is the
    # right trade; throwing the feed away would leave the user with no phishing
    # protection at all because of one bad row.
    #
    # A *lot* of guard hits is a different animal: that is what a poisoned or
    # mis-generated feed looks like, and it is not safe to publish any of it.
    hits = guard_hits(hosts)
    if hits:
        poisoned = len(hits) > max(GUARD_HIT_LIMIT, len(hosts) * GUARD_HIT_FRACTION)
        if poisoned:
            raise ValidationError(
                f"{spec.identifier}: {len(hits)} protected domains listed "
                f"(e.g. {', '.join(hits[:5])}) — feed looks poisoned, refusing to publish"
            )
        hosts.difference_update(hits)
        warnings.append(
            f"{spec.identifier}: dropped {len(hits)} protected domain(s) upstream listed: "
            + ", ".join(hits[:5])
            + ("…" if len(hits) > 5 else "")
        )

    if previous:
        before = len(previous.get("entries", []))
        if before and len(hosts) < before * (1 - spec.max_shrink):
            raise ValidationError(
                f"{spec.identifier}: shrank from {before} to {len(hosts)} entries "
                f"(>{spec.max_shrink:.0%} loss); refusing to publish"
            )

    updated = upstream_updated_at(body)
    if updated is None:
        warnings.append(f"{spec.identifier}: upstream states no update date")
    elif spec.max_age_days is not None:
        age = (dt.datetime.now(dt.timezone.utc) - updated).days
        if age > spec.max_age_days:
            raise ValidationError(
                f"{spec.identifier}: upstream is {age} days old "
                f"(limit {spec.max_age_days}); refusing to publish stale data"
            )
    if spec.snapshot:
        age = (dt.datetime.now(dt.timezone.utc) - updated).days if updated else None
        warnings.append(
            f"{spec.identifier}: SNAPSHOT — upstream is no longer updated"
            + (f" (last change {age} days ago)" if age is not None else "")
        )

    return warnings


# --------------------------------------------------------------------------
# Emitting
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# Chrome
# --------------------------------------------------------------------------

# Chrome guarantees an extension 30,000 static declarativeNetRequest rules
# (more from a shared 300,000 pool, but only if no other content blocker is
# installed — so 30,000 is the number to design against).
CHROME_STATIC_RULE_BUDGET = 30_000

# Each rule must stay under 2 KB once compiled. `requestDomains` takes a list,
# so one rule can carry many hosts — but how many depends on how long those
# hosts are, which is why rules are packed by byte budget rather than by a
# fixed count. A fixed count of 50 put 123 rules over the ceiling.
#
# The budget leaves headroom below 2,048 because the compiled size is not
# exactly the JSON length.
CHROME_RULE_BYTE_BUDGET = 1_700

# Chrome caps `regexFilter` rules at 1,000 across the extension. We use none:
# `requestDomains` does host matching natively and far more cheaply, which is
# why the Safari regex rules are not simply translated across.
CHROME_RESOURCE_TYPES = [
    "sub_frame", "stylesheet", "script", "image", "font", "object",
    "xmlhttprequest", "ping", "csp_report", "media", "websocket", "other",
]


def chrome_rules(hosts: list[str], start_id: int) -> list[dict]:
    """Blocks sub-resource requests to `hosts`, batched to stay under 2 KB.

    `main_frame` is deliberately excluded. Letting declarativeNetRequest kill a
    top-level navigation would drop the user on Chrome's generic error page;
    the service worker handles navigations instead so the block page can say
    what was blocked and why. Same division of labour as Safari's content
    blocker versus its web extension.
    """
    def rule(batch: list[str], rule_id: int) -> dict:
        return {
            "id": rule_id,
            "priority": 1,
            "action": {"type": "block"},
            "condition": {
                "requestDomains": batch,
                "resourceTypes": CHROME_RESOURCE_TYPES,
            },
        }

    # Fixed overhead of everything in the rule except the domains themselves.
    overhead = len(json.dumps(rule([], 0)))

    rules: list[dict] = []
    batch: list[str] = []
    batch_bytes = overhead
    for host in hosts:
        entry_bytes = len(host) + 4          # quotes, comma, slack
        if batch and batch_bytes + entry_bytes > CHROME_RULE_BYTE_BUDGET:
            rules.append(rule(batch, start_id + len(rules)))
            batch, batch_bytes = [], overhead
        batch.append(host)
        batch_bytes += entry_bytes
    if batch:
        rules.append(rule(batch, start_id + len(rules)))
    return rules


def write_chrome(out_dir: pathlib.Path, feeds: dict[str, list[str]]) -> dict:
    """Emits Chrome's static rulesets, the navigation host list, and the
    manifest fragment that declares them."""
    lists_dir = out_dir / "lists"
    rules_dir = out_dir / "rules"
    for directory in (lists_dir, rules_dir):
        directory.mkdir(parents=True, exist_ok=True)

    # The service worker needs hosts, not rules: it answers navigation checks.
    write_json(lists_dir / "hosts.json", {k: sorted(v) for k, v in feeds.items()})

    rule_resources = []
    next_id = 1
    total_rules = 0
    for identifier, hosts in sorted(feeds.items()):
        rules = chrome_rules(sorted(hosts), next_id)
        next_id += len(rules)
        total_rules += len(rules)
        path = rules_dir / f"{identifier}.json"
        write_json(path, rules)
        rule_resources.append({
            "id": identifier,
            "enabled": True,
            "path": f"rules/{identifier}.json",
        })

    if total_rules > CHROME_STATIC_RULE_BUDGET:
        raise ValidationError(
            f"chrome: {total_rules} static rules exceeds the {CHROME_STATIC_RULE_BUDGET} "
            "guaranteed to an extension; increase CHROME_DOMAINS_PER_RULE or drop a feed"
        )

    return {"rule_resources": rule_resources, "rule_count": total_rules}


def load_existing(identifier: str) -> dict | None:
    path = BUNDLED / f"{identifier}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return None


def build_payload(spec: FeedSpec, hosts: set[str], previous: dict | None) -> dict:
    entries = [{"host": h, "category": spec.category} for h in sorted(hosts)]

    # Only bump the version when the content actually changed, so devices do
    # not re-download an identical feed every cycle.
    version = 1
    if previous:
        previous_hosts = {e["host"] for e in previous.get("entries", [])}
        version = previous.get("version", 1)
        if previous_hosts != hosts:
            version += 1

    return {
        "identifier": spec.identifier,
        "name": spec.name,
        "version": version,
        "updatedAt": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "entries": entries,
    }


def write_json(path: pathlib.Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default="", help="Public URL that dist/ is served from.")
    parser.add_argument("--check-only", action="store_true", help="Validate but write nothing.")
    parser.add_argument("--update-bundled", action="store_true",
                        help="Also refresh Shared/Resources/Blocklists (a release-time action).")
    parser.add_argument("--chrome", metavar="DIR",
                        help="Also emit Chrome rulesets and host lists into DIR.")
    args = parser.parse_args()

    index_feeds = []
    chrome_feeds: dict[str, list[str]] = {}
    all_warnings: list[str] = []
    failures: list[str] = []
    total = 0

    for spec in FEEDS:
        try:
            body, mirror = fetch(spec)
        except RuntimeError as error:
            failures.append(str(error))
            continue

        hosts = parse(body, spec.fmt)
        previous = load_existing(spec.identifier)

        try:
            warnings = validate(spec, hosts, previous, body)
        except ValidationError as error:
            failures.append(str(error))
            continue

        all_warnings.extend(warnings)
        payload = build_payload(spec, hosts, previous)
        chrome_feeds[spec.identifier] = sorted(hosts)
        total += len(hosts)

        status = "snapshot" if spec.snapshot else "live"
        print(f"  {spec.identifier:<14} {len(hosts):>7,} entries  v{payload['version']}  "
              f"[{status}]  {spec.licence}  <- {mirror.split('/')[2]}")

        if args.check_only:
            continue

        write_json(DIST / f"{spec.identifier}-v{payload['version']}.json", payload)
        if args.update_bundled:
            write_json(BUNDLED / f"{spec.identifier}.json", payload)

        index_feeds.append({
            "identifier": spec.identifier,
            "version": payload["version"],
            "url": f"{args.base_url.rstrip('/')}/{spec.identifier}-v{payload['version']}.json",
            "name": spec.name,
            "attribution": spec.attribution,
            "license": spec.licence,
            "snapshot": spec.snapshot,
        })

    if all_warnings:
        print("\nWarnings:")
        for warning in all_warnings:
            print(f"  ! {warning}")

    if failures:
        print("\nFailures:", file=sys.stderr)
        for failure in failures:
            print(f"  x {failure}", file=sys.stderr)
        # A partial publish is worse than none: the app would take a truncated
        # index as authoritative and could lose categories it already had.
        return 1

    if args.chrome and not args.check_only:
        # The hand-curated ad/tracker/clickbait baselines are not fetched, but
        # Chrome should still block them — pull them from the bundled feeds.
        for extra in ("advertising", "tracking", "clickbait"):
            bundled = load_existing(extra)
            if bundled:
                chrome_feeds.setdefault(
                    extra, sorted({e["host"] for e in bundled.get("entries", [])})
                )
        chrome_out = pathlib.Path(args.chrome)
        result = write_chrome(chrome_out, chrome_feeds)
        print(f"\nChrome: {result['rule_count']:,} static rules "
              f"({sum(len(v) for v in chrome_feeds.values()):,} hosts) -> {chrome_out}")

    if not args.check_only:
        write_json(DIST / "feeds.json", {"feeds": index_feeds})
        print(f"\nWrote {len(index_feeds)} feeds ({total:,} hosts) to {DIST}")
        if args.update_bundled:
            print(f"Refreshed the bundled baseline in {BUNDLED}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
