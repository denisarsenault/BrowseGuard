import Foundation
import os

/// Loads the bundled baseline feeds and refreshes them from the network.
public struct BlocklistUpdater: Sendable {

    public enum UpdateError: LocalizedError {
        case noFeedConfigured
        case server(Int)
        case malformed(String)

        public var errorDescription: String? {
            switch self {
            case .noFeedConfigured:
                "No update server is configured for this build."
            case .server(let code):
                "The update server returned HTTP \(code)."
            case .malformed(let name):
                "The downloaded feed \"\(name)\" could not be read."
            }
        }
    }

    /// Where the feed index lives.
    ///
    /// Defaults to the `BGBlocklistFeedURL` Info.plist key, which the
    /// `BROWSEGUARD_FEED_URL` build setting fills in — so a debug build can
    /// point at a staging feed without touching source. Unset means "no feed",
    /// and the app runs entirely on its bundled baseline rather than silently
    /// reaching for a host that does not exist.
    public var feedIndexURL: URL?

    private let bundle: Bundle
    private let session: URLSession
    private let log = Logger(subsystem: "com.mybrightzone.BrowseGuard", category: "Updater")

    public init(
        feedIndexURL: URL? = nil,
        bundle: Bundle = .main,
        session: URLSession = .shared
    ) {
        self.feedIndexURL = feedIndexURL ?? Self.configuredFeedURL(in: bundle)
        self.bundle = bundle
        self.session = session
    }

    /// HTTPS is required, not preferred. A blocklist fetched over plaintext is
    /// an instruction set an attacker on the path can rewrite — they could
    /// unblock their own domain, or block a competitor's, on every device that
    /// takes the update.
    static func configuredFeedURL(in bundle: Bundle) -> URL? {
        configuredFeedURL(rawValue: bundle.object(forInfoDictionaryKey: "BGBlocklistFeedURL") as? String)
    }

    /// Split out from the `Bundle` lookup so the rule can be tested directly.
    static func configuredFeedURL(rawValue: String?) -> URL? {
        guard let value = rawValue else { return nil }

        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              !trimmed.hasPrefix("$("),          // unexpanded build setting
              let url = URL(string: trimmed),
              url.scheme?.lowercased() == "https"
        else { return nil }
        return url
    }

    /// The feeds compiled into the app. These ship so the app protects the
    /// user on first launch, offline, before any network call.
    public static let bundledFeedNames = [
        "malware", "scam", "advertising", "tracking", "clickbait", "cryptojacking", "pup",
    ]

    public func loadBundledLists() -> [Blocklist] {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return Self.bundledFeedNames.compactMap { name in
            guard let url = bundle.url(forResource: name, withExtension: "json", subdirectory: "Blocklists")
                    ?? bundle.url(forResource: name, withExtension: "json")
            else {
                log.error("Bundled feed missing: \(name, privacy: .public).json")
                return nil
            }
            guard let data = try? Data(contentsOf: url),
                  let list = try? decoder.decode(Blocklist.self, from: data)
            else {
                log.error("Bundled feed unreadable: \(name, privacy: .public).json")
                return nil
            }
            return list
        }
    }

    /// Returns the catalog to use: the newer of what is on disk and what is
    /// bundled, per feed. A bundled feed shipped in an app update can be newer
    /// than a downloaded copy from months ago.
    public func resolvedCatalog() -> BlocklistCatalog {
        let bundled = loadBundledLists()
        let stored = SharedStore.read([Blocklist].self, from: .catalog) ?? []

        var best: [String: Blocklist] = [:]
        for list in bundled + stored {
            if let existing = best[list.identifier], existing.version >= list.version { continue }
            best[list.identifier] = list
        }
        return BlocklistCatalog(lists: Array(best.values))
    }

    /// Downloads any feed whose published version is newer than what we hold.
    /// Returns the feeds that actually changed.
    public func fetchUpdates(current: BlocklistCatalog) async throws -> [Blocklist] {
        guard let feedIndexURL else { throw UpdateError.noFeedConfigured }

        let (indexData, indexResponse) = try await session.data(from: feedIndexURL)
        try Self.validate(indexResponse)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let index = try decoder.decode(FeedIndex.self, from: indexData)

        let currentVersions = Dictionary(
            current.lists.map { ($0.identifier, $0.version) },
            uniquingKeysWith: max
        )

        var updated: [Blocklist] = []
        for descriptor in index.feeds {
            guard descriptor.version > (currentVersions[descriptor.identifier] ?? -1) else { continue }
            let (data, response) = try await session.data(from: descriptor.url)
            try Self.validate(response)
            guard let list = try? decoder.decode(Blocklist.self, from: data) else {
                throw UpdateError.malformed(descriptor.identifier)
            }
            updated.append(list)
        }
        return updated
    }

    private static func validate(_ response: URLResponse) throws {
        guard let http = response as? HTTPURLResponse else { return }
        guard (200..<300).contains(http.statusCode) else {
            throw UpdateError.server(http.statusCode)
        }
    }

    private struct FeedIndex: Decodable {
        struct Descriptor: Decodable {
            let identifier: String
            let version: Int
            let url: URL
        }
        let feeds: [Descriptor]
    }
}
