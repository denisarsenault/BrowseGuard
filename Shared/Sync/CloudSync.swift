import Foundation
import os

/// Mirrors settings, the allowlist, and the activity summary across the user's
/// devices via `NSUbiquitousKeyValueStore`.
///
/// Chosen over CloudKit on purpose: the payload is a few kilobytes, the store
/// works identically on iOS, macOS, and tvOS, it needs no schema or container
/// setup, and it costs nothing in quota. It is the only iCloud API available on
/// tvOS without a CloudKit container, and tvOS is where the synced data matters
/// most — the TV target has no browser of its own to learn from.
///
/// The 1 MB / 1024-key limit is why the full event log stays local and only
/// `ActivitySummary` is mirrored.
@MainActor
public final class CloudSync {

    public static let shared = CloudSync()

    private let store = NSUbiquitousKeyValueStore.default
    private let log = Logger(subsystem: "com.mybrightzone.BrowseGuard", category: "CloudSync")
    private var observer: (any NSObjectProtocol)?

    /// Fires when iCloud hands us newer values from another device.
    public var onRemoteChange: (@MainActor () -> Void)?

    private enum Key {
        static let settings = AppGroup.cloudPrefix + "settings"
        static let allowlist = AppGroup.cloudPrefix + "allowlist"
        static let userBlocklist = AppGroup.cloudPrefix + "userBlocklist"
        static let summary = AppGroup.cloudPrefix + "summary"
        static let revision = AppGroup.cloudPrefix + "revision"
    }

    private init() {}

    public func start() {
        guard observer == nil else { return }
        observer = NotificationCenter.default.addObserver(
            forName: NSUbiquitousKeyValueStore.didChangeExternallyNotification,
            object: store,
            queue: .main
        ) { [weak self] notification in
            // Pull the one value we need out here: `Notification` is not
            // Sendable, so it cannot cross into the MainActor closure.
            let reason = notification.userInfo?[NSUbiquitousKeyValueStoreChangeReasonKey] as? Int
            MainActor.assumeIsolated {
                self?.handleRemoteChange(reason: reason)
            }
        }
        store.synchronize()
    }

    public func stop() {
        if let observer { NotificationCenter.default.removeObserver(observer) }
        observer = nil
    }

    private func handleRemoteChange(reason: Int?) {
        if reason == NSUbiquitousKeyValueStoreQuotaViolationChange {
            log.error("iCloud key-value quota exceeded; sync paused")
            return
        }
        onRemoteChange?()
    }

    // MARK: - Push

    public func push(
        settings: ProtectionSettings,
        allowlist: Allowlist,
        userBlocklist: UserBlocklist,
        summary: ActivitySummary
    ) {
        write(settings, forKey: Key.settings)
        write(allowlist, forKey: Key.allowlist)
        write(userBlocklist, forKey: Key.userBlocklist)
        write(summary, forKey: Key.summary)
        store.set(Date.now.timeIntervalSince1970, forKey: Key.revision)
        store.synchronize()
    }

    // MARK: - Pull

    public func remoteSettings() -> ProtectionSettings? { read(ProtectionSettings.self, forKey: Key.settings) }
    public func remoteAllowlist() -> Allowlist? { read(Allowlist.self, forKey: Key.allowlist) }
    public func remoteUserBlocklist() -> UserBlocklist? { read(UserBlocklist.self, forKey: Key.userBlocklist) }
    public func remoteSummary() -> ActivitySummary? { read(ActivitySummary.self, forKey: Key.summary) }

    /// When the remote copy was written. Used for last-writer-wins: the local
    /// side only yields when iCloud is strictly newer than our last push.
    public var remoteRevision: Date? {
        let value = store.double(forKey: Key.revision)
        return value > 0 ? Date(timeIntervalSince1970: value) : nil
    }

    // MARK: - Coding

    private func write(_ value: some Encodable, forKey key: String) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        guard let data = try? encoder.encode(value) else { return }
        store.set(data, forKey: key)
    }

    private func read<T: Decodable>(_ type: T.Type, forKey key: String) -> T? {
        guard let data = store.data(forKey: key) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(type, from: data)
    }
}
