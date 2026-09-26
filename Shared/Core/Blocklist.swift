import Foundation

/// One entry in a blocklist: a host pattern plus the reason it is listed.
public struct BlocklistEntry: Codable, Sendable, Hashable {
    /// Canonical host. Matching is suffix-based, so `doubleclick.net` also
    /// covers `stats.g.doubleclick.net`.
    public let host: String
    public let category: ThreatCategory
    /// Optional human-readable source, shown on the block page.
    public let source: String?

    public init(host: String, category: ThreatCategory, source: String? = nil) {
        self.host = host
        self.category = category
        self.source = source
    }
}

/// A named, versioned collection of entries — one feed.
public struct Blocklist: Codable, Sendable {
    public let identifier: String
    public let name: String
    /// Monotonic version from the publisher. Used to decide whether a
    /// downloaded copy is newer than the bundled baseline.
    public let version: Int
    public let updatedAt: Date
    public let entries: [BlocklistEntry]

    public init(
        identifier: String,
        name: String,
        version: Int,
        updatedAt: Date,
        entries: [BlocklistEntry]
    ) {
        self.identifier = identifier
        self.name = name
        self.version = version
        self.updatedAt = updatedAt
        self.entries = entries
    }
}

/// Every blocklist currently loaded, flattened into a single lookup structure.
///
/// Immutable by construction, which is what lets it cross actor boundaries and
/// be used from the content blocker and web extension handlers without locking.
public struct BlocklistCatalog: Sendable {
    public let lists: [Blocklist]
    private let index: [String: BlocklistEntry]

    public init(lists: [Blocklist]) {
        self.lists = lists
        var index: [String: BlocklistEntry] = [:]
        index.reserveCapacity(lists.reduce(0) { $0 + $1.entries.count })
        for list in lists {
            for entry in list.entries {
                guard let host = URLNormalizer.canonicalHost(of: entry.host) else { continue }
                let normalized = BlocklistEntry(
                    host: host,
                    category: entry.category,
                    source: entry.source ?? list.name
                )
                // A more severe listing wins when two feeds disagree.
                if let existing = index[host],
                   existing.category.severity >= normalized.category.severity {
                    continue
                }
                index[host] = normalized
            }
        }
        self.index = index
    }

    public static let empty = BlocklistCatalog(lists: [])

    public var entryCount: Int { index.count }

    /// Longest-suffix match: `ads.tracker.example.com` prefers a rule on
    /// `tracker.example.com` over one on `example.com`.
    public func match(host: String) -> BlocklistEntry? {
        for candidate in URLNormalizer.suffixChain(for: host) {
            if let entry = index[candidate] { return entry }
        }
        return nil
    }

    public func entries(in category: ThreatCategory) -> [BlocklistEntry] {
        index.values.filter { $0.category == category }
    }

    public var allEntries: [BlocklistEntry] { Array(index.values) }

    public func counts() -> [ThreatCategory: Int] {
        index.values.reduce(into: [:]) { totals, entry in
            totals[entry.category, default: 0] += 1
        }
    }
}
