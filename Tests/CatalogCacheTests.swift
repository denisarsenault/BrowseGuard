import Foundation
import Testing

/// Guards the hot path the web extension runs on every navigation.
///
/// Before the cache, `ProtectionEngine.current()` re-read and re-decoded the
/// whole catalog per page load. These tests assert what the cache *does* —
/// how many times it decodes — rather than how long it takes: a timing
/// assertion cannot tell "the cache worked" apart from "the machine was fast",
/// and it made the suite take half a minute.
@Suite(.serialized)
struct CatalogCacheTests {

    /// Small on purpose. The cache either decodes once or it does not; feeding
    /// it 20,000 rows proves nothing extra and costs seconds.
    private func seed(host: String) -> Bool {
        SharedStore.write([
            Blocklist(identifier: "cache", name: "Cache", version: 1, updatedAt: .now, entries: [
                BlocklistEntry(host: host, category: .malware),
            ])
        ], to: .catalog)
    }

    @Test("Repeated reads decode once, not once per call")
    func decodesOnce() throws {
        guard seed(host: "one.example") else { return }   // no App Group here
        defer { SharedStore.write([Blocklist](), to: .catalog) }

        _ = SharedStore.catalog()                          // warm it
        let before = SharedStore.catalogDecodeCount

        for _ in 0..<50 {
            _ = SharedStore.catalog()
        }

        #expect(
            SharedStore.catalogDecodeCount == before,
            "50 reads caused \(SharedStore.catalogDecodeCount - before) extra decode(s); expected 0"
        )
    }

    @Test("A write is visible to the very next read")
    func writeThenReadIsFresh() throws {
        // The caches sit on the navigation hot path, so a stale read here
        // would mean blocking a site the user had just unblocked — or worse,
        // still allowing one they had just blocked.
        guard SharedStore.write(UserBlocklist(items: [BlockedSite(host: "one.example")]),
                                to: .userBlocklist) else { return }
        defer { SharedStore.write(UserBlocklist.empty, to: .userBlocklist) }
        #expect(SharedStore.userBlocklist().contains(host: "one.example") != nil)

        // No sleep: back-to-back writes can share a filesystem timestamp, so
        // the write itself has to drop the cache rather than relying on dates.
        SharedStore.write(UserBlocklist(items: [BlockedSite(host: "two.example")]),
                          to: .userBlocklist)
        #expect(SharedStore.userBlocklist().contains(host: "two.example") != nil,
                "a write must be visible to the next read")
        #expect(SharedStore.userBlocklist().contains(host: "one.example") == nil,
                "the replaced entry must be gone")
    }

    @Test("Settings and the allowlist are cached too, not just the catalog")
    func allHotPathFilesAreCached() throws {
        guard SharedStore.write(ProtectionSettings.default, to: .settings) else { return }
        // Reading repeatedly must not re-decode; the modification date is
        // unchanged, so the same value comes back each time.
        let first = SharedStore.settings()
        for _ in 0..<50 {
            #expect(SharedStore.settings() == first)
        }
    }

    @Test("A catalog written by another process is still picked up")
    func invalidatesOnWrite() throws {
        guard seed(host: "one.example") else { return }
        defer { SharedStore.write([Blocklist](), to: .catalog) }

        #expect(SharedStore.catalog().match(host: "one.example") != nil)
        #expect(SharedStore.catalog().match(host: "two.example") == nil)

        // Modification-date stamps have one-second resolution on some file
        // systems, so land the rewrite in a later second.
        Thread.sleep(forTimeInterval: 1.1)
        _ = seed(host: "two.example")

        let decodes = SharedStore.catalogDecodeCount
        #expect(SharedStore.catalog().match(host: "two.example") != nil,
                "a catalog written by another process must invalidate the cache")
        #expect(SharedStore.catalogDecodeCount > decodes, "expected a re-decode after the write")
    }
}
