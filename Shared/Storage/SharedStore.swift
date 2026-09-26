import Foundation
import os

/// Atomic JSON read/write against the App Group container.
///
/// Deliberately synchronous and free-function shaped: the content blocker and
/// the web extension handler are short-lived, non-UI processes that need a
/// value immediately and have no run loop worth suspending on.
public enum SharedStore {

    static let log = Logger(subsystem: "com.mybrightzone.BrowseGuard", category: "SharedStore")

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        encoder.outputFormatting = [.withoutEscapingSlashes]
        return encoder
    }()

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()

    public static func read<T: Decodable>(_ type: T.Type, from file: AppGroup.File) -> T? {
        guard let url = file.url else {
            log.error("App Group container unavailable; cannot read \(file.rawValue, privacy: .public)")
            return nil
        }
        guard let data = try? Data(contentsOf: url) else { return nil }
        do {
            return try decoder.decode(type, from: data)
        } catch {
            log.error("Failed to decode \(file.rawValue, privacy: .public): \(error.localizedDescription, privacy: .public)")
            return nil
        }
    }

    @discardableResult
    public static func write(_ value: some Encodable, to file: AppGroup.File) -> Bool {
        AppGroup.prepareContainer()
        guard let url = file.url else {
            log.error("App Group container unavailable; cannot write \(file.rawValue, privacy: .public)")
            return false
        }
        do {
            let data = try encoder.encode(value)
            // `.atomic` so a content blocker reading mid-write never sees a
            // truncated rule file and disables itself.
            try data.write(to: url, options: .atomic)
            return true
        } catch {
            log.error("Failed to write \(file.rawValue, privacy: .public): \(error.localizedDescription, privacy: .public)")
            return false
        }
    }

    public static func settings() -> ProtectionSettings {
        read(ProtectionSettings.self, from: .settings) ?? .default
    }

    public static func allowlist() -> Allowlist {
        read(Allowlist.self, from: .allowlist) ?? .empty
    }

    public static func userBlocklist() -> UserBlocklist {
        read(UserBlocklist.self, from: .userBlocklist) ?? .empty
    }

    /// The decoded catalog, cached for the lifetime of the process.
    ///
    /// This is on the hot path: the web extension builds a `ProtectionEngine`
    /// for **every navigation**, and before this cache each page load re-read
    /// the 2.4 MB catalog file and rebuilt a 42,000-entry index — roughly 20 MB
    /// of allocation per page, in an extension process with a far smaller
    /// memory allowance than the app.
    ///
    /// Invalidated by the file's modification date rather than a notification,
    /// because the writer is a different process and the extension may not be
    /// alive when the write happens.
    public static func catalog() -> BlocklistCatalog {
        catalogCache.value()
    }

    private static let catalogCache = CatalogCache()

    private final class CatalogCache: @unchecked Sendable {
        private let lock = NSLock()
        private var cached: BlocklistCatalog?
        private var stamp: Date?

        func value() -> BlocklistCatalog {
            let modified = modificationDate()

            lock.lock()
            if let cached, stamp == modified {
                lock.unlock()
                return cached
            }
            lock.unlock()

            // Decoded outside the lock: it is the slow part, and two threads
            // racing to decode the same file is wasteful but harmless, whereas
            // holding the lock across it would serialize every navigation.
            let fresh = SharedStore.decodeCatalog()

            lock.lock()
            cached = fresh
            stamp = modified
            lock.unlock()
            return fresh
        }

        private func modificationDate() -> Date? {
            guard let url = AppGroup.File.catalog.url else { return nil }
            return try? url.resourceValues(forKeys: [.contentModificationDateKey])
                .contentModificationDate
        }
    }

    /// Counts full catalog decodes. Exists so the cache can be tested by
    /// observing what it does rather than by timing it — a timing assertion on
    /// a shared machine is both slow and flaky, and it cannot distinguish "the
    /// cache worked" from "the machine was fast today".
    public private(set) nonisolated(unsafe) static var catalogDecodeCount = 0
    private static let decodeCountLock = NSLock()

    private static func decodeCatalog() -> BlocklistCatalog {
        decodeCountLock.lock()
        catalogDecodeCount += 1
        decodeCountLock.unlock()

        guard let lists = read([Blocklist].self, from: .catalog) else { return .empty }
        return BlocklistCatalog(lists: lists)
    }
}
