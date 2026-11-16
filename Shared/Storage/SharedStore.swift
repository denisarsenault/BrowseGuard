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
            invalidateCache(for: file)
            return true
        } catch {
            log.error("Failed to write \(file.rawValue, privacy: .public): \(error.localizedDescription, privacy: .public)")
            return false
        }
    }

    // Everything below is on the hot path. The web extension builds a
    // `ProtectionEngine` for **every navigation**, and each one used to re-read
    // and re-decode four files from disk. In Safari that cost is paid inside
    // the window between the page starting to load and our verdict arriving —
    // the window in which a blocked site can still run its own scripts — so
    // shortening it is not merely a performance question.
    //
    // Each cache is invalidated by its file's modification date rather than by
    // a notification, because the writer is usually a different process and
    // the extension may not even be alive when the write happens.

    public static func settings() -> ProtectionSettings {
        settingsCache.value()
    }

    public static func allowlist() -> Allowlist {
        allowlistCache.value()
    }

    public static func userBlocklist() -> UserBlocklist {
        userBlocklistCache.value()
    }

    public static func catalog() -> BlocklistCatalog {
        catalogCache.value()
    }

    public static func entitlement() -> EntitlementRecord {
        entitlementCache.value()
    }

    private static let settingsCache = FileCache(.settings) {
        read(ProtectionSettings.self, from: .settings) ?? .default
    }
    private static let entitlementCache = FileCache(.entitlement) {
        read(EntitlementRecord.self, from: .entitlement) ?? .unsubscribed
    }
    private static let allowlistCache = FileCache(.allowlist) {
        read(Allowlist.self, from: .allowlist) ?? .empty
    }
    private static let userBlocklistCache = FileCache(.userBlocklist) {
        read(UserBlocklist.self, from: .userBlocklist) ?? .empty
    }
    private static let catalogCache = FileCache(.catalog) {
        decodeCatalog()
    }

    /// A decoded file, held for as long as the file on disk is unchanged.
    private final class FileCache<Value: Sendable>: @unchecked Sendable {
        private let file: AppGroup.File
        private let load: @Sendable () -> Value
        private let lock = NSLock()
        private var cached: Value?
        private var stamp: Date?

        init(_ file: AppGroup.File, load: @escaping @Sendable () -> Value) {
            self.file = file
            self.load = load
        }

        func value() -> Value {
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
            let fresh = load()

            lock.lock()
            cached = fresh
            stamp = modified
            lock.unlock()
            return fresh
        }

        /// Drops the cached copy. Called right after this process writes the
        /// file, so a read that follows a write never sees the old value even
        /// if the two land within the same filesystem timestamp.
        func invalidate() {
            lock.lock()
            cached = nil
            stamp = nil
            lock.unlock()
        }

        private func modificationDate() -> Date? {
            guard let url = file.url else { return nil }
            return try? url.resourceValues(forKeys: [.contentModificationDateKey])
                .contentModificationDate
        }
    }

    /// Drops whichever cache covers `file`. Writes go through here so a caller
    /// that writes and then immediately reads cannot observe stale data.
    static func invalidateCache(for file: AppGroup.File) {
        switch file {
        case .settings: settingsCache.invalidate()
        case .allowlist: allowlistCache.invalidate()
        case .userBlocklist: userBlocklistCache.invalidate()
        case .catalog: catalogCache.invalidate()
        case .entitlement: entitlementCache.invalidate()
        case .events, .compiledRules: break   // not cached
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
