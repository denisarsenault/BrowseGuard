import Foundation

/// A host the user chose to permit, permanently or for a while.
public struct AllowlistItem: Codable, Sendable, Hashable, Identifiable {
    public let host: String
    public let addedAt: Date
    /// `nil` means permanent. Otherwise the entry lapses at this date — this is
    /// how "Continue anyway" works without becoming a forever hole.
    public let expiresAt: Date?
    /// What the user was told when they allowed it, kept so the UI can show
    /// "you allowed this even though it was flagged as phishing".
    public let bypassedCategory: ThreatCategory?
    public var note: String?

    public var id: String { host }

    public init(
        host: String,
        addedAt: Date = .now,
        expiresAt: Date? = nil,
        bypassedCategory: ThreatCategory? = nil,
        note: String? = nil
    ) {
        self.host = host
        self.addedAt = addedAt
        self.expiresAt = expiresAt
        self.bypassedCategory = bypassedCategory
        self.note = note
    }

    public func isActive(at date: Date = .now) -> Bool {
        guard let expiresAt else { return true }
        return expiresAt > date
    }

    public var isTemporary: Bool { expiresAt != nil }
}

/// The user's allowlist. Suffix-matching, like the blocklist, so allowing
/// `example.com` also allows its subdomains.
public struct Allowlist: Codable, Sendable, Equatable {
    public private(set) var items: [AllowlistItem]

    public init(items: [AllowlistItem] = []) {
        self.items = items
    }

    public static let empty = Allowlist()

    public var activeItems: [AllowlistItem] {
        items.filter { $0.isActive() }
    }

    public func contains(host: String, at date: Date = .now) -> AllowlistItem? {
        let chain = URLNormalizer.suffixChain(for: host)
        for candidate in chain {
            if let item = items.first(where: { $0.host == candidate && $0.isActive(at: date) }) {
                return item
            }
        }
        return nil
    }

    public mutating func add(_ item: AllowlistItem) {
        items.removeAll { $0.host == item.host }
        items.append(item)
        items.sort { $0.host < $1.host }
    }

    public mutating func remove(host: String) {
        items.removeAll { $0.host == host }
    }

    /// Drops lapsed temporary entries. Called on launch and before each write
    /// so the file does not accumulate dead bypasses.
    @discardableResult
    public mutating func pruneExpired(at date: Date = .now) -> Int {
        let before = items.count
        items.removeAll { !$0.isActive(at: date) }
        return before - items.count
    }
}
