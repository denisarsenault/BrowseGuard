import Foundation

/// A site the user chose to block, independently of any threat feed.
///
/// The counterpart to `AllowlistItem`. Feeds cover threats; this covers
/// everything else a person might not want loading — a time sink, a site they
/// have decided they are done with, or a domain they are testing a blocker
/// against.
public struct BlockedSite: Codable, Sendable, Hashable, Identifiable {
    public let host: String
    public let addedAt: Date
    public var note: String?

    public var id: String { host }

    public init(host: String, addedAt: Date = .now, note: String? = nil) {
        self.host = host
        self.addedAt = addedAt
        self.note = note
    }
}

/// The user's own block list. Suffix-matching like the other lists, so
/// blocking `example.com` also blocks its subdomains.
public struct UserBlocklist: Codable, Sendable, Equatable {
    public private(set) var items: [BlockedSite]

    public init(items: [BlockedSite] = []) {
        self.items = items
    }

    public static let empty = UserBlocklist()

    public var hosts: [String] { items.map(\.host) }

    public func contains(host: String) -> BlockedSite? {
        for candidate in URLNormalizer.suffixChain(for: host) {
            if let item = items.first(where: { $0.host == candidate }) {
                return item
            }
        }
        return nil
    }

    public mutating func add(_ item: BlockedSite) {
        items.removeAll { $0.host == item.host }
        items.append(item)
        items.sort { $0.host < $1.host }
    }

    public mutating func remove(host: String) {
        items.removeAll { $0.host == host }
    }
}
