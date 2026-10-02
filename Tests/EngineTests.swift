import Foundation
import Testing

// The engine sources are compiled directly into this bundle, so these tests
// exercise the real matching and heuristic code with no host app and no Safari.

// MARK: - Host normalization

@Suite("URL normalization")
struct URLNormalizerTests {

    @Test("Strips scheme, www, port, path, and trailing dot", arguments: [
        ("https://www.Example.COM/path?q=1", "example.com"),
        ("http://example.com.", "example.com"),
        ("EXAMPLE.com:8443", "example.com"),
        ("https://user:pw@sub.example.com/", "sub.example.com"),
        ("example.com/some/path", "example.com"),
    ])
    func canonicalizes(input: String, expected: String) {
        #expect(URLNormalizer.canonicalHost(of: input) == expected)
    }

    @Test("Rejects non-web URLs")
    func rejectsNonWeb() {
        #expect(URLNormalizer.canonicalHost(of: URL(string: "file:///etc/hosts")!) == nil)
        #expect(URLNormalizer.canonicalHost(of: URL(string: "data:text/html,hi")!) == nil)
        #expect(URLNormalizer.canonicalHost(of: URL(string: "about:blank")!) == nil)
    }

    @Test("Suffix chain runs most specific to least")
    func suffixChain() {
        #expect(URLNormalizer.suffixChain(for: "a.b.example.com")
                == ["a.b.example.com", "b.example.com", "example.com", "com"])
    }

    @Test("Detects IP literals")
    func ipLiterals() {
        #expect(URLNormalizer.isIPLiteral("192.168.1.1"))
        #expect(URLNormalizer.isIPLiteral("[2001:db8::1]"))
        #expect(!URLNormalizer.isIPLiteral("example.com"))
        #expect(!URLNormalizer.isIPLiteral("999.1.1.1"))
    }
}

// MARK: - Blocklist matching

@Suite("Blocklist matching")
struct BlocklistCatalogTests {

    private func catalog() -> BlocklistCatalog {
        BlocklistCatalog(lists: [
            Blocklist(
                identifier: "test",
                name: "Test Feed",
                version: 1,
                updatedAt: .now,
                entries: [
                    BlocklistEntry(host: "doubleclick.net", category: .advertising),
                    BlocklistEntry(host: "evil.example", category: .malware),
                    BlocklistEntry(host: "ads.partner.example", category: .advertising),
                ]
            )
        ])
    }

    @Test("Matches subdomains by suffix")
    func matchesSubdomains() {
        let entry = catalog().match(host: "stats.g.doubleclick.net")
        #expect(entry?.category == .advertising)
    }

    @Test("Does not match a host that merely ends in the same letters")
    func noSubstringMatch() {
        #expect(catalog().match(host: "notdoubleclick.net") == nil)
    }

    @Test("Prefers the most specific rule")
    func prefersLongestSuffix() {
        let catalog = BlocklistCatalog(lists: [
            Blocklist(identifier: "a", name: "A", version: 1, updatedAt: .now, entries: [
                BlocklistEntry(host: "partner.example", category: .tracking),
                BlocklistEntry(host: "ads.partner.example", category: .malware),
            ])
        ])
        #expect(catalog.match(host: "ads.partner.example")?.category == .malware)
        #expect(catalog.match(host: "other.partner.example")?.category == .tracking)
    }

    @Test("The more severe listing wins when feeds disagree")
    func severityWins() {
        let catalog = BlocklistCatalog(lists: [
            Blocklist(identifier: "a", name: "A", version: 1, updatedAt: .now, entries: [
                BlocklistEntry(host: "conflict.example", category: .tracking),
            ]),
            Blocklist(identifier: "b", name: "B", version: 1, updatedAt: .now, entries: [
                BlocklistEntry(host: "conflict.example", category: .malware),
            ]),
        ])
        #expect(catalog.match(host: "conflict.example")?.category == .malware)
    }
}

// MARK: - Heuristics

@Suite("Heuristic scanner")
struct HeuristicScannerTests {

    let scanner = HeuristicScanner()

    @Test("Ordinary sites score clean", arguments: [
        "apple.com", "google.com", "github.com", "nytimes.com",
        "en.wikipedia.org", "developer.apple.com", "stackoverflow.com",
    ])
    func noFalsePositives(host: String) {
        let risk = scanner.risk(for: host)
        #expect(risk < ProtectionSettings.Sensitivity.balanced.warnThreshold,
                "\(host) scored \(risk)")
    }

    @Test("Brand in the subdomain of an unrelated domain is caught")
    func brandInSubdomain() {
        let signals = scanner.signals(for: "apple.com.secure-login.example")
        #expect(signals.contains { $0.rule == "brand-in-subdomain" })
    }

    @Test("Typosquats are caught", arguments: [
        "gogle.com", "paypa1.com", "micosoft.com", "netflx.com",
    ])
    func typosquats(host: String) {
        let signals = scanner.signals(for: host)
        #expect(signals.contains { $0.rule == "typosquat" }, "no typosquat signal for \(host)")
    }

    @Test("Transpositions count as one edit, not two")
    func transposition() {
        #expect(HeuristicScanner.damerauLevenshtein("gogole", "google") == 1)
        #expect(HeuristicScanner.damerauLevenshtein("apple", "apple") == 0)
    }

    @Test("A high-risk TLD plus a scam token clears the balanced warn bar")
    func compoundSignals() {
        let risk = scanner.risk(for: "verify-account.tk")
        #expect(risk >= ProtectionSettings.Sensitivity.balanced.warnThreshold)
    }

    @Test("Raw IP addresses are flagged")
    func ipLiteral() {
        let signals = scanner.signals(for: "192.0.2.14")
        #expect(signals.contains { $0.rule == "ip-literal" })
    }

    @Test("Entropy separates words from gibberish")
    func entropy() {
        #expect(HeuristicScanner.shannonEntropy("aaaaaaaa") < 1.0)
        #expect(HeuristicScanner.shannonEntropy("x7q2mzbv9kdf") > 3.0)
    }
}

// MARK: - Decisions

@Suite("Protection engine")
struct ProtectionEngineTests {

    private func engine(
        settings: ProtectionSettings = .default,
        allowlist: Allowlist = .empty
    ) -> ProtectionEngine {
        ProtectionEngine(
            settings: settings,
            catalog: BlocklistCatalog(lists: [
                Blocklist(identifier: "t", name: "Test", version: 1, updatedAt: .now, entries: [
                    BlocklistEntry(host: "malware.example", category: .malware),
                    BlocklistEntry(host: "ads.example", category: .advertising),
                ])
            ]),
            allowlist: allowlist
        )
    }

    @Test("A listed host is blocked with full confidence")
    func blocksListedHost() {
        let verdict = engine().evaluate(host: "malware.example")
        #expect(verdict.decision == .block)
        #expect(verdict.category == .malware)
        #expect(verdict.confidence == 1.0)
    }

    @Test("Disabling a category stops its blocks")
    func categoryToggle() {
        var settings = ProtectionSettings.default
        settings.enabledCategories.remove(.advertising)
        #expect(engine(settings: settings).evaluate(host: "ads.example").decision == .allow)
        // Other categories are unaffected.
        #expect(engine(settings: settings).evaluate(host: "malware.example").decision == .block)
    }

    @Test("The master switch overrides everything")
    func masterSwitch() {
        var settings = ProtectionSettings.default
        settings.isProtectionEnabled = false
        #expect(engine(settings: settings).evaluate(host: "malware.example").decision == .allow)
    }

    @Test("The allowlist beats a malware listing, and covers subdomains")
    func allowlistWins() {
        let allowlist = Allowlist(items: [AllowlistItem(host: "malware.example")])
        let engine = engine(allowlist: allowlist)
        #expect(engine.evaluate(host: "malware.example").decision == .allowlisted)
        #expect(engine.evaluate(host: "deep.sub.malware.example").decision == .allowlisted)
    }

    @Test("A lapsed temporary bypass stops applying")
    func expiredBypass() {
        let allowlist = Allowlist(items: [
            AllowlistItem(host: "malware.example", expiresAt: .now.addingTimeInterval(-1))
        ])
        #expect(engine(allowlist: allowlist).evaluate(host: "malware.example").decision == .block)
    }

    @Test("Critical blocks always show the interstitial, even when it is off")
    func interstitialForCritical() {
        var settings = ProtectionSettings.default
        settings.showsInterstitial = false
        let engine = engine(settings: settings)

        let malware = engine.evaluate(host: "malware.example")
        #expect(engine.shouldPresentInterstitial(for: malware))

        let ad = engine.evaluate(host: "ads.example")
        #expect(!engine.shouldPresentInterstitial(for: ad))
    }

    @Test("Sensitivity moves the line between warn and block")
    func sensitivity() {
        let host = "verify-account.tk"
        var relaxed = ProtectionSettings.default
        relaxed.heuristicSensitivity = .relaxed
        var strict = ProtectionSettings.default
        strict.heuristicSensitivity = .strict

        #expect(engine(settings: strict).evaluate(host: host).decision == .block)
        #expect(engine(settings: relaxed).evaluate(host: host).decision != .block)
    }
}

// MARK: - Rule compilation

@Suite("Content rule compiler")
struct ContentRuleCompilerTests {

    private let catalog = BlocklistCatalog(lists: [
        Blocklist(identifier: "t", name: "Test", version: 1, updatedAt: .now, entries: [
            BlocklistEntry(host: "malware.example", category: .malware),
            BlocklistEntry(host: "ads.example", category: .advertising),
        ])
    ])

    @Test("Produces JSON WebKit will accept")
    func encodes() throws {
        let rules = ContentRuleCompiler.compile(
            catalog: catalog,
            settings: .default,
            allowlist: .empty
        )
        let data = try JSONEncoder().encode(rules)
        let decoded = try JSONSerialization.jsonObject(with: data) as? [[String: Any]]
        let first = try #require(decoded?.first)
        let trigger = try #require(first["trigger"] as? [String: Any])
        #expect(trigger["url-filter"] is String)
        #expect((first["action"] as? [String: Any])?["type"] as? String != nil)
    }

    @Test("The url-filter anchors at the host, not anywhere in the URL")
    func anchorsAtHost() throws {
        let rules = ContentRuleCompiler.compile(
            catalog: catalog, settings: .default, allowlist: .empty
        )
        let pattern = try #require(rules.first { $0.trigger.urlFilter.contains("malware") }).trigger.urlFilter
        let regex = try NSRegularExpression(pattern: pattern)

        func matches(_ url: String) -> Bool {
            regex.firstMatch(in: url, range: NSRange(url.startIndex..., in: url)) != nil
        }

        #expect(matches("https://malware.example/"))
        #expect(matches("https://sub.malware.example/x"))
        #expect(!matches("https://safe.example/?ref=malware.example"))
        #expect(!matches("https://notmalware.example/"))
    }

    @Test("Allowlist exemption is emitted last so it can undo earlier rules")
    func allowlistIsLast() {
        let rules = ContentRuleCompiler.compile(
            catalog: catalog,
            settings: .default,
            allowlist: Allowlist(items: [AllowlistItem(host: "ads.example")])
        )
        #expect(rules.last?.action.type == "ignore-previous-rules")
    }

    @Test("Phishing is left to the engine, not compiled into WebKit")
    func excludesPhishing() {
        // 40,000 phishing hosts made Safari refuse the whole rule set with
        // SFErrorLoadingInterrupted, which left the blocker with nothing.
        // They are handled at navigation time by ProtectionEngine instead.
        let catalog = BlocklistCatalog(lists: [
            Blocklist(identifier: "t", name: "T", version: 1, updatedAt: .now, entries: [
                BlocklistEntry(host: "phish.example", category: .scam),
                BlocklistEntry(host: "ads.example", category: .advertising),
            ])
        ])
        let rules = ContentRuleCompiler.compile(
            catalog: catalog, settings: .default, allowlist: .empty
        )
        let filters = rules.map(\.trigger.urlFilter).joined()
        #expect(!filters.contains("phish"), "phishing should not reach WebKit")
        #expect(filters.contains("ads"), "ad domains should reach WebKit")

        // …but the engine still blocks it, so coverage is not lost.
        let engine = ProtectionEngine(
            settings: .default, catalog: catalog, allowlist: .empty
        )
        #expect(engine.evaluate(host: "phish.example").decision == .block)
    }

    @Test("Turning protection off yields no rules")
    func disabledProducesNothing() {
        var settings = ProtectionSettings.default
        settings.isProtectionEnabled = false
        let rules = ContentRuleCompiler.compile(
            catalog: catalog, settings: settings, allowlist: .empty
        )
        #expect(rules.isEmpty)
    }

    @Test("Stays under WebKit's rule ceiling")
    func respectsRuleLimit() {
        let many = (0..<200_000).map {
            BlocklistEntry(host: "host\($0).example", category: .advertising)
        }
        let big = BlocklistCatalog(lists: [
            Blocklist(identifier: "big", name: "Big", version: 1, updatedAt: .now, entries: many)
        ])
        let rules = ContentRuleCompiler.compile(
            catalog: big, settings: .default, allowlist: .empty
        )
        #expect(rules.count <= ContentRuleCompiler.ruleLimit)
    }
}

// MARK: - Settings and allowlist

@Suite("Settings and allowlist")
struct StorageModelTests {

    @Test("Settings written by an older build still decode")
    func forwardCompatibleDecoding() throws {
        let partial = Data(#"{"isProtectionEnabled": false}"#.utf8)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let settings = try decoder.decode(ProtectionSettings.self, from: partial)

        #expect(settings.isProtectionEnabled == false)
        // Everything absent falls back to the default rather than throwing.
        #expect(settings.heuristicsEnabled == ProtectionSettings.default.heuristicsEnabled)
        #expect(settings.enabledCategories == ProtectionSettings.default.enabledCategories)
    }

    @Test("Pruning drops lapsed entries and keeps permanent ones")
    func pruning() {
        var allowlist = Allowlist(items: [
            AllowlistItem(host: "permanent.example"),
            AllowlistItem(host: "lapsed.example", expiresAt: .now.addingTimeInterval(-60)),
            AllowlistItem(host: "live.example", expiresAt: .now.addingTimeInterval(600)),
        ])
        #expect(allowlist.pruneExpired() == 1)
        #expect(allowlist.items.map(\.host).sorted() == ["live.example", "permanent.example"])
    }

    @Test("Adding a host twice replaces rather than duplicates")
    func addReplaces() {
        var allowlist = Allowlist()
        allowlist.add(AllowlistItem(host: "example.com", note: "first"))
        allowlist.add(AllowlistItem(host: "example.com", note: "second"))
        #expect(allowlist.items.count == 1)
        #expect(allowlist.items.first?.note == "second")
    }

    @Test("Summary rolls up per category")
    func summary() {
        let events = [
            BlockEvent(host: "a.example", category: .malware, decision: .block, severity: .critical),
            BlockEvent(host: "b.example", category: .advertising, decision: .block, severity: .low),
            BlockEvent(host: "c.example", category: .advertising, decision: .block, severity: .low),
        ]
        let summary = ActivitySummary.summarize(events)
        #expect(summary.totalBlocked == 3)
        #expect(summary.byCategory[.advertising] == 2)
        #expect(summary.criticalBlockedToday == 1)
    }
}

// MARK: - Bundled feeds

@Suite("Bundled blocklists")
struct BundledFeedTests {

    @Test("Every bundled feed parses and is non-empty")
    func feedsLoad() {
        let updater = BlocklistUpdater(bundle: Bundle(for: BundleToken.self))
        let lists = updater.loadBundledLists()
        #expect(lists.count == BlocklistUpdater.bundledFeedNames.count)
        for list in lists {
            #expect(!list.entries.isEmpty, "\(list.identifier) is empty")
        }
    }

    @Test("Feed entries carry the category their file claims")
    func categoriesMatchFilenames() {
        let updater = BlocklistUpdater(bundle: Bundle(for: BundleToken.self))
        for list in updater.loadBundledLists() {
            let expected = ThreatCategory(rawValue: list.identifier)
            #expect(expected != nil, "\(list.identifier) is not a known category")
            #expect(list.entries.allSatisfy { $0.category == expected })
        }
    }
}

// MARK: - User block list

@Suite("User block list")
struct UserBlocklistTests {

    private func engine(
        blocked: [String] = [],
        allowed: [String] = [],
        settings: ProtectionSettings = .default
    ) -> ProtectionEngine {
        ProtectionEngine(
            settings: settings,
            catalog: BlocklistCatalog(lists: [
                Blocklist(identifier: "t", name: "Test", version: 1, updatedAt: .now, entries: [
                    BlocklistEntry(host: "malware.example", category: .malware),
                ])
            ]),
            allowlist: Allowlist(items: allowed.map { AllowlistItem(host: $0) }),
            userBlocklist: UserBlocklist(items: blocked.map { BlockedSite(host: $0) })
        )
    }

    @Test("A user-blocked host is blocked even though no feed lists it")
    func blocksUnlistedHost() {
        let verdict = engine(blocked: ["webbrowsertools.com"]).evaluate(host: "webbrowsertools.com")
        #expect(verdict.decision == .block)
        #expect(verdict.category == .userBlocked)
    }

    @Test("Blocking covers subdomains")
    func coversSubdomains() {
        let verdict = engine(blocked: ["example.com"]).evaluate(host: "deep.sub.example.com")
        #expect(verdict.decision == .block)
    }

    @Test("A user block beats the allowlist")
    func beatsAllowlist() {
        // Both are the user's instructions; the explicit block is the newer,
        // more specific intent and must not lose to a stale allowlist entry.
        let verdict = engine(blocked: ["example.com"], allowed: ["example.com"])
            .evaluate(host: "example.com")
        #expect(verdict.decision == .block)
        #expect(verdict.category == .userBlocked)
    }

    @Test("The master switch still turns it off")
    func respectsMasterSwitch() {
        var settings = ProtectionSettings.default
        settings.isProtectionEnabled = false
        #expect(engine(blocked: ["example.com"], settings: settings)
            .evaluate(host: "example.com").decision == .allow)
    }

    @Test("A user block never claims the site is dangerous")
    func honestCopy() {
        let verdict = engine(blocked: ["example.com"]).evaluate(host: "example.com")
        #expect(verdict.headline == "You blocked this site")
        #expect(verdict.explanation.contains("you chose to block it"))
        #expect(verdict.severity == .low)
    }

    @Test("Not shown as a toggle, since removing the entry is how you undo it")
    func notToggleable() {
        #expect(!ThreatCategory.toggleable.contains(.userBlocked))
        #expect(ThreatCategory.allCases.contains(.userBlocked))
    }

    @Test("Compiles a rule that survives the allowlist exemption")
    func compilesAfterAllowlistExemption() throws {
        let rules = ContentRuleCompiler.compile(
            catalog: .empty,
            settings: .default,
            allowlist: Allowlist(items: [AllowlistItem(host: "example.com")]),
            userBlocklist: UserBlocklist(items: [BlockedSite(host: "example.com")])
        )
        // `ignore-previous-rules` only undoes what precedes it, so the user's
        // block must come after — otherwise WebKit and the engine would
        // disagree about the same host.
        let ignoreIndex = try #require(rules.firstIndex { $0.action.type == "ignore-previous-rules" })
        let blockIndex = try #require(rules.lastIndex { $0.action.type == "block" })
        #expect(blockIndex > ignoreIndex)
    }

    @Test("An ordinary site with a clean verdict can still be blocked")
    func blocksAnOrdinarySite() {
        // The reported case: cnn.com is on no threat feed and trips no
        // heuristic, so it comes back clean. Adding it must still block it —
        // the user block list is not conditional on the site being suspicious.
        let clean = engine()
        #expect(clean.evaluate(host: "cnn.com").decision == .allow)

        let blocked = engine(blocked: ["cnn.com"])
        let verdict = blocked.evaluate(host: "cnn.com")
        #expect(verdict.decision == .block)
        #expect(verdict.category == .userBlocked)
        // Subdomains too, since that is what people expect from "block cnn.com".
        #expect(blocked.evaluate(host: "edition.cnn.com").decision == .block)
        #expect(blocked.evaluate(host: "www.cnn.com").decision == .block)
    }

    @Test("Blocking a site reaches the compiled Safari rules")
    func blockedSiteReachesWebKit() throws {
        let rules = ContentRuleCompiler.compile(
            catalog: .empty,
            settings: .default,
            allowlist: .empty,
            userBlocklist: UserBlocklist(items: [BlockedSite(host: "cnn.com")])
        )
        let pattern = try #require(rules.last { $0.action.type == "block" }).trigger.urlFilter
        let regex = try NSRegularExpression(pattern: pattern)
        func matches(_ url: String) -> Bool {
            regex.firstMatch(in: url, range: NSRange(url.startIndex..., in: url)) != nil
        }
        #expect(matches("https://cnn.com/"))
        #expect(matches("https://edition.cnn.com/world"))
        #expect(!matches("https://cnnvideo.ru/"))
    }

    @Test("Add replaces rather than duplicates, and remove works")
    func mutation() {
        var list = UserBlocklist()
        list.add(BlockedSite(host: "example.com", note: "first"))
        list.add(BlockedSite(host: "example.com", note: "second"))
        #expect(list.items.count == 1)
        #expect(list.items.first?.note == "second")
        list.remove(host: "example.com")
        #expect(list.items.isEmpty)
    }
}

// MARK: - Coalescing

/// A counter the runner's operations mutate. `@MainActor` matches the runner,
/// so no locking is needed and interleaving would be visible.
@MainActor
final class RunRecorder {
    var starts = 0
    var finishes = 0
    var order: [Int] = []
    var maxConcurrent = 0
    private var active = 0

    func begin() {
        starts += 1
        active += 1
        maxConcurrent = max(maxConcurrent, active)
    }

    func end(_ tag: Int) {
        active -= 1
        finishes += 1
        order.append(tag)
    }
}

@Suite("Coalescing runner")
@MainActor
struct CoalescingRunnerTests {

    @Test("A burst of requests collapses into one run")
    func coalesces() async throws {
        let runner = CoalescingRunner(delay: .milliseconds(60))
        let recorder = RunRecorder()

        // Four toggles in quick succession, as a user flipping categories.
        for tag in 1...4 {
            runner.schedule {
                recorder.begin()
                recorder.end(tag)
            }
        }

        try await Task.sleep(for: .milliseconds(400))
        #expect(recorder.starts == 1, "expected one run, got \(recorder.starts)")
        // The last request is the one that survives — it carries the newest state.
        #expect(recorder.order == [4])
    }

    @Test("Requests spaced beyond the delay each run")
    func doesNotCoalesceSlowRequests() async throws {
        let runner = CoalescingRunner(delay: .milliseconds(30))
        let recorder = RunRecorder()

        for tag in 1...3 {
            runner.schedule {
                recorder.begin()
                recorder.end(tag)
            }
            try await Task.sleep(for: .milliseconds(120))
        }

        try await Task.sleep(for: .milliseconds(200))
        #expect(recorder.starts == 3)
        #expect(recorder.order == [1, 2, 3])
    }

    @Test("Runs never overlap, so an older compile cannot overwrite a newer one")
    func serializes() async throws {
        let runner = CoalescingRunner(delay: .milliseconds(10))
        let recorder = RunRecorder()

        // The first operation is slow; the second is requested while it runs.
        runner.schedule {
            recorder.begin()
            try? await Task.sleep(for: .milliseconds(150))
            recorder.end(1)
        }
        try await Task.sleep(for: .milliseconds(60))   // let run 1 start
        runner.schedule {
            recorder.begin()
            recorder.end(2)
        }

        try await Task.sleep(for: .milliseconds(500))
        #expect(recorder.starts == 2)
        #expect(recorder.maxConcurrent == 1, "runs overlapped")
        // Ordering preserved: the newer rules are written last.
        #expect(recorder.order == [1, 2])
    }

    @Test("runNow skips the delay and supersedes anything waiting")
    func runNowIsImmediate() async throws {
        let runner = CoalescingRunner(delay: .seconds(30))
        let recorder = RunRecorder()

        runner.schedule {
            recorder.begin()
            recorder.end(99)
        }
        await runner.runNow {
            recorder.begin()
            recorder.end(1)
        }

        // Did not wait out the 30s delay, and the queued request was dropped.
        #expect(recorder.order == [1])
    }
}

// MARK: - Update endpoint

@Suite("Feed endpoint configuration")
struct FeedEndpointTests {

    @Test("Accepts a configured HTTPS endpoint")
    func acceptsHTTPS() {
        let url = ConfiguredURL.https(from: "https://example.com/feeds.json")
        #expect(url?.absoluteString == "https://example.com/feeds.json")
        // Surrounding whitespace from a build setting should not defeat it.
        #expect(ConfiguredURL.https(from: "  https://example.com/f.json \n") != nil)
    }

    @Test("Refuses plaintext HTTP")
    func refusesHTTP() {
        // A blocklist fetched over HTTP is an instruction set anyone on the
        // path can rewrite — unblocking their domain on every device.
        #expect(ConfiguredURL.https(from: "http://example.com/feeds.json") == nil)
        #expect(ConfiguredURL.https(from: "ftp://example.com/feeds.json") == nil)
        #expect(ConfiguredURL.https(from: "file:///etc/feeds.json") == nil)
    }

    @Test("Treats absent, empty, and unexpanded settings as no feed")
    func treatsUnsetAsNoFeed() {
        #expect(ConfiguredURL.https(from: nil) == nil)
        #expect(ConfiguredURL.https(from: "") == nil)
        #expect(ConfiguredURL.https(from: "   ") == nil)
        // An Xcode build setting that never got substituted.
        #expect(ConfiguredURL.https(from: "$(BROWSEGUARD_FEED_URL)") == nil)
    }
}

/// Anchors `Bundle(for:)` to the test bundle, which is where the feeds land.
private final class BundleToken {}

// MARK: - Chrome listing

@Suite("Chrome Web Store link")
struct ChromeListingTests {

    @Test("Accepts a configured HTTPS listing")
    func acceptsHTTPS() {
        // Same rule as the update feed: a link the app opens on the user's
        // behalf should not be downgradeable by anyone on the path.
        #expect(ConfiguredURL.https(from: "https://chrome.google.com/webstore/detail/abc") != nil)
    }

    @Test("Hides the offer when unset, empty, or unexpanded")
    func hidesWhenUnconfigured() {
        #expect(ConfiguredURL.https(from: nil) == nil)
        #expect(ConfiguredURL.https(from: "") == nil)
        #expect(ConfiguredURL.https(from: "   ") == nil)
        #expect(ConfiguredURL.https(from: "$(BROWSEGUARD_CHROME_URL)") == nil)
    }

    @Test("Refuses plaintext and non-web schemes")
    func refusesUnsafeSchemes() {
        #expect(ConfiguredURL.https(from: "http://example.com/x") == nil)
        #expect(ConfiguredURL.https(from: "file:///tmp/x") == nil)
        #expect(ConfiguredURL.https(from: "javascript:alert(1)") == nil)
    }
}
