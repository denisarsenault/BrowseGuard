#!/usr/bin/env python3
"""Tests for the feed builder.

No network. These cover the two things that would hurt if they broke quietly:
normalization drifting away from `URLNormalizer.canonicalHost` in the app, and
the validation gates that stop a bad upstream reaching users.

    python3 scripts/test_build_feeds.py
"""

import unittest

from build_feeds import (
    FeedSpec,
    ValidationError,
    build_payload,
    canonical_host,
    guard_hits,
    parse,
    upstream_updated_at,
    validate,
)


def spec(**overrides) -> FeedSpec:
    defaults = dict(
        identifier="test",
        name="Test",
        category="malware",
        mirrors=["https://example.invalid/list.txt"],
        fmt="domains",
        min_entries=3,
        attribution="test",
        licence="MIT",
        max_age_days=None,
    )
    defaults.update(overrides)
    return FeedSpec(**defaults)


class CanonicalHost(unittest.TestCase):
    """Must agree with URLNormalizer.canonicalHost, or rules never match."""

    def test_normalizes(self):
        self.assertEqual(canonical_host("WWW.Example.COM"), "example.com")
        self.assertEqual(canonical_host("example.com."), "example.com")
        self.assertEqual(canonical_host("  sub.example.com  "), "sub.example.com")

    def test_rejects_non_hosts(self):
        for bad in ["", "localhost", "broadcasthost", "0.0.0.0", "com", "no-dot"]:
            self.assertIsNone(canonical_host(bad), bad)

    def test_rejects_junk_characters(self):
        for bad in ["exa mple.com", "http://example.com", "exa|mple.com", "*.example.com"]:
            self.assertIsNone(canonical_host(bad), bad)

    def test_keeps_ip_literals(self):
        # urlhaus lists bare IPs for C2 hosts; they are legitimate entries.
        self.assertEqual(canonical_host("192.0.2.14"), "192.0.2.14")


class Parsing(unittest.TestCase):
    def test_domains_format_skips_comments(self):
        body = "# Title: x\n# Updated: 2026-01-01T00:00:00Z\n\nevil.example\nbad.example\n"
        self.assertEqual(parse(body, "domains"), {"evil.example", "bad.example"})

    def test_hosts_format_strips_the_ip(self):
        body = "# comment\n0.0.0.0 evil.example\n127.0.0.1 bad.example\n0.0.0.0 localhost\n"
        self.assertEqual(parse(body, "hosts"), {"evil.example", "bad.example"})

    def test_trailing_comment_is_stripped(self):
        self.assertEqual(parse("evil.example # why\n", "domains"), {"evil.example"})


class Guards(unittest.TestCase):
    def test_matches_exact_and_subdomains(self):
        hits = guard_hits({"apple.com", "ocsp.apple.com", "evil.example"})
        self.assertEqual(hits, ["apple.com", "ocsp.apple.com"])

    def test_does_not_match_lookalikes(self):
        # The distinction that matters: `notapple.com` and a domain that merely
        # *contains* apple.com as a subdomain label are both real threats.
        hits = guard_hits({"notapple.com", "apple.com.phish.tk", "myapple.com"})
        self.assertEqual(hits, [])


class Validation(unittest.TestCase):
    def test_below_floor_is_rejected(self):
        with self.assertRaises(ValidationError):
            validate(spec(min_entries=100), {"a.example", "b.example"}, None, "")

    def test_a_few_guard_hits_are_dropped_not_fatal(self):
        hosts = {f"evil{i}.example" for i in range(50)} | {"apple.com"}
        warnings = validate(spec(), hosts, None, "")
        self.assertNotIn("apple.com", hosts)
        self.assertEqual(len(hosts), 50)
        self.assertTrue(any("dropped 1 protected" in w for w in warnings))

    def test_many_guard_hits_reject_the_feed(self):
        hosts = {"apple.com", "google.com", "microsoft.com", "github.com",
                 "cloudflare.com", "mozilla.org", "live.com", "evil.example"}
        with self.assertRaises(ValidationError) as caught:
            validate(spec(), hosts, None, "")
        self.assertIn("poisoned", str(caught.exception))

    def test_sudden_shrink_is_rejected(self):
        previous = {"entries": [{"host": f"h{i}.example"} for i in range(1000)]}
        with self.assertRaises(ValidationError) as caught:
            validate(spec(), {"a.example", "b.example", "c.example"}, previous, "")
        self.assertIn("shrank", str(caught.exception))

    def test_growth_is_fine(self):
        previous = {"entries": [{"host": "a.example"}]}
        hosts = {f"h{i}.example" for i in range(500)}
        validate(spec(), hosts, previous, "")

    def test_stale_upstream_is_rejected_when_age_is_enforced(self):
        body = "# Updated: 2020-01-01T00:00:00Z\n"
        with self.assertRaises(ValidationError) as caught:
            validate(spec(max_age_days=7), {"a.e", "b.e", "c.e"}, None, body)
        self.assertIn("stale", str(caught.exception))

    def test_snapshot_warns_instead_of_failing(self):
        body = "# Updated: 2020-01-01T00:00:00Z\n"
        warnings = validate(
            spec(snapshot=True, max_age_days=None), {"a.e", "b.e", "c.e"}, None, body
        )
        self.assertTrue(any("SNAPSHOT" in w for w in warnings))


class UpdatedAtHeader(unittest.TestCase):
    def test_iso_form(self):
        parsed = upstream_updated_at("# Updated: 2026-09-21T12:07:05Z\n")
        self.assertEqual((parsed.year, parsed.month, parsed.day), (2026, 9, 21))

    def test_long_date_form(self):
        parsed = upstream_updated_at("# Last modified: 05 March 2025\n")
        self.assertEqual((parsed.year, parsed.month, parsed.day), (2025, 3, 5))

    def test_absent(self):
        self.assertIsNone(upstream_updated_at("# no date here\n"))


class Versioning(unittest.TestCase):
    def test_identical_content_keeps_the_version(self):
        previous = {"version": 7, "entries": [{"host": "a.example", "category": "malware"}]}
        payload = build_payload(spec(), {"a.example"}, previous)
        self.assertEqual(payload["version"], 7)

    def test_changed_content_bumps_the_version(self):
        previous = {"version": 7, "entries": [{"host": "a.example", "category": "malware"}]}
        payload = build_payload(spec(), {"a.example", "b.example"}, previous)
        self.assertEqual(payload["version"], 8)

    def test_entries_are_sorted_for_stable_diffs(self):
        payload = build_payload(spec(), {"c.example", "a.example", "b.example"}, None)
        self.assertEqual([e["host"] for e in payload["entries"]],
                         ["a.example", "b.example", "c.example"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
