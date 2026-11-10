import Foundation

/// Detecting that more than one copy of BrowseGuard is installed.
///
/// A Safari App/Web Extension ships *inside* its containing app bundle, and
/// Safari registers an extension for every copy of that app Launch Services knows
/// about. So a second copy — an old build left in `~/Downloads`, a duplicate in
/// `~/Applications`, a drag-installed update sitting next to the original — makes
/// Safari show two "BrowseGuard" extensions, and the stale one can keep serving
/// old rules. The only clean fix is for the user to keep one copy and trash the
/// rest, so the app's job is to notice the situation and say so.
///
/// This file is the **pure** half: the model and the de-duplication / "which one
/// am I" logic, with no AppKit. It lives in the engine sources so it compiles on
/// every platform and is unit-testable without a real Launch Services database.
/// The macOS-only query that feeds it lives in `DuplicateInstallScanner`.

/// One installed copy of the app bundle.
public struct InstalledCopy: Equatable, Sendable {
    public let url: URL
    /// `CFBundleShortVersionString`, e.g. "2.1".
    public let shortVersion: String
    /// `CFBundleVersion`, e.g. "214".
    public let buildVersion: String
    /// True for the copy this process is running from.
    public let isRunningCopy: Bool

    public init(url: URL, shortVersion: String, buildVersion: String, isRunningCopy: Bool) {
        self.url = url
        self.shortVersion = shortVersion
        self.buildVersion = buildVersion
        self.isRunningCopy = isRunningCopy
    }
}

public struct DuplicateInstallReport: Equatable, Sendable {
    public let copies: [InstalledCopy]

    public init(copies: [InstalledCopy]) { self.copies = copies }

    /// More than one copy is installed — the condition worth warning about.
    public var hasDuplicates: Bool { copies.count > 1 }

    /// The copy we are running from, if it was among those found.
    public var runningCopy: InstalledCopy? { copies.first(where: \.isRunningCopy) }

    /// Every copy that is NOT the one running — the ones to trash.
    public var otherCopies: [InstalledCopy] { copies.filter { !$0.isRunningCopy } }

    /// Count of distinct version/build pairs, so the UI can say "two versions".
    public var distinctVersionCount: Int {
        Set(copies.map { "\($0.shortVersion) (\($0.buildVersion))" }).count
    }

    /// Build a report from raw bundle URLs (e.g. everything Launch Services
    /// returns for the app's bundle identifier), collapsing paths that point at
    /// the same bundle and marking the running copy.
    ///
    /// Kept free of I/O so it is deterministic in tests: the caller supplies the
    /// running location and a closure that reads a bundle's version.
    public static func build(
        from urls: [URL],
        runningURL: URL,
        versionReader: (URL) -> (short: String, build: String)
    ) -> DuplicateInstallReport {
        let runningPath = runningURL.standardizedFileURL.path
        var seenPaths = Set<String>()
        let copies = urls
            .map(\.standardizedFileURL)
            .filter { seenPaths.insert($0.path).inserted }   // collapse duplicate paths
            .map { url -> InstalledCopy in
                let version = versionReader(url)
                return InstalledCopy(
                    url: url,
                    shortVersion: version.short,
                    buildVersion: version.build,
                    isRunningCopy: url.path == runningPath
                )
            }
        return DuplicateInstallReport(copies: copies)
    }
}
