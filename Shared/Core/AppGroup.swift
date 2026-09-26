import Foundation
import Security
import os

/// Identifiers shared by the app, the content blockers, and the web extension.
///
/// The App Group is what makes the whole thing work under the App Sandbox: it
/// is the only writable location all five targets can see, so it holds the
/// compiled rule file, the settings, the allowlist, and the event log.
///
/// Resolving the identifier is fiddlier than it looks. On iOS and tvOS the
/// group is `group.com.mybrightzone.BrowseGuard`. On macOS the App Store
/// requires the Team ID prefix — `ABCDE12345.group.com.mybrightzone.BrowseGuard`
/// — and the Team ID is not known at compile time. So each target declares its
/// own value in `Info.plist` (fed by the `BROWSEGUARD_APP_GROUP` build setting)
/// and we verify at runtime that the container actually exists, falling back
/// through the alternatives rather than silently writing nowhere.
public enum AppGroup {

    private static let log = Logger(subsystem: "com.mybrightzone.BrowseGuard", category: "AppGroup")

    /// The unprefixed form. Correct as-is on iOS and tvOS.
    public static let baseIdentifier = "group.com.mybrightzone.BrowseGuard"

    // All three apps share one bundle identifier so the App Store treats them
    // as a Universal Purchase. Extensions still need distinct identifiers,
    // because those are registered globally.
    public static let appBundleID = "com.mybrightzone.BrowseGuard"

    public static let iOSContentBlockerBundleID = "com.mybrightzone.BrowseGuard.ContentBlocker"
    public static let macContentBlockerBundleID = "com.mybrightzone.BrowseGuard.macContentBlocker"
    public static let iOSWebExtensionBundleID = "com.mybrightzone.BrowseGuard.Extension"
    public static let macWebExtensionBundleID = "com.mybrightzone.BrowseGuard.macExtension"

    /// iCloud key-value store key namespace for cross-device sync.
    public static let cloudPrefix = "bg."

    /// The resolved group identifier for this process. Computed once.
    public static let identifier: String = resolveIdentifier()

    private static func resolveIdentifier() -> String {
        let manager = FileManager.default
        for candidate in candidateIdentifiers() {
            if manager.containerURL(forSecurityApplicationGroupIdentifier: candidate) != nil {
                return candidate
            }
        }
        log.error("""
            No App Group container is reachable. Check that every target carries the \
            com.apple.security.application-groups entitlement and that \
            BROWSEGUARD_APP_GROUP matches it (macOS needs the Team ID prefix).
            """)
        return baseIdentifier
    }

    private static func candidateIdentifiers() -> [String] {
        var candidates: [String] = []

        // What this target was built with.
        if let declared = Bundle.main.object(forInfoDictionaryKey: "BGAppGroupIdentifier") as? String,
           !declared.isEmpty,
           !declared.hasPrefix("$(") {
            candidates.append(declared)
        }

        // The entitlement itself is the ground truth when we can read it.
        candidates.append(contentsOf: entitledGroups())

        candidates.append(baseIdentifier)
        // De-duplicate while preserving order.
        var seen = Set<String>()
        return candidates.filter { seen.insert($0).inserted }
    }

    /// Reads `com.apple.security.application-groups` out of the running code's
    /// own signature. This is what makes the macOS Team ID prefix a non-issue:
    /// whatever Xcode actually signed with is what we use.
    ///
    /// The `SecCode` family is macOS-only, which is fine — macOS is the only
    /// platform where the prefix is in question.
    private static func entitledGroups() -> [String] {
        #if os(macOS)
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return [] }

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
              let staticCode
        else { return [] }

        var information: CFDictionary?
        guard SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &information
        ) == errSecSuccess,
            let dictionary = information as? [String: Any],
            let entitlements = dictionary["entitlements-dict"] as? [String: Any],
            let groups = entitlements["com.apple.security.application-groups"] as? [String]
        else { return [] }

        return groups
        #else
        return []
        #endif
    }

    /// Shared container root. `nil` means the App Group entitlement is missing
    /// or the provisioning profile does not carry it — callers fall back to
    /// their own container and log loudly rather than crashing.
    /// Resolved once per process, not per access.
    ///
    /// `containerURL(forSecurityApplicationGroupIdentifier:)` is an XPC round
    /// trip to `containermanagerd`, and this was a computed property — so every
    /// file read, every write, and every stat paid for one. The web extension
    /// touches it five or more times per navigation, which made page loads far
    /// more expensive than the actual work. Measured here: 50 cached catalog
    /// reads took 107s as a computed property, versus well under a second as a
    /// stored one.
    ///
    /// Safe to cache: a process's container assignment cannot change while it
    /// is running.
    public static let containerURL: URL? =
        FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier)

    public static var defaults: UserDefaults {
        UserDefaults(suiteName: identifier) ?? .standard
    }

    /// Where each shared artifact lives inside the container.
    public enum File: String {
        case settings = "settings.json"
        case allowlist = "allowlist.json"
        case userBlocklist = "userBlocklist.json"
        case events = "events.json"
        case catalog = "catalog.json"
        /// The compiled Safari content-blocker rules the extensions serve.
        case compiledRules = "blockerList.json"

        public var url: URL? {
            AppGroup.containerURL?.appending(path: rawValue, directoryHint: .notDirectory)
        }
    }

    /// Creates the container directory if it does not exist yet.
    @discardableResult
    public static func prepareContainer() -> Bool {
        guard let containerURL else { return false }
        try? FileManager.default.createDirectory(
            at: containerURL,
            withIntermediateDirectories: true
        )
        return true
    }
}
