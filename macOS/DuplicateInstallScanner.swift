import AppKit
import Foundation
import os

/// The macOS-only query that feeds `DuplicateInstallReport`.
///
/// `urlsForApplications(withBundleIdentifier:)` asks Launch Services for every
/// registered copy of a bundle identifier, wherever it lives on disk — which is
/// exactly the set that makes Safari show duplicate extensions. We read each
/// copy's version straight from its `Info.plist` and drop any whose bundle no
/// longer exists (a stale registration pointing at a deleted app is not a copy
/// the user needs to act on).
enum DuplicateInstallScanner {

    private static let log = Logger(subsystem: "com.mybrightzone.BrowseGuard", category: "DuplicateInstall")

    static func scan(bundleID: String = AppGroup.appBundleID,
                     runningURL: URL = Bundle.main.bundleURL) -> DuplicateInstallReport {
        let registered = NSWorkspace.shared.urlsForApplications(withBundleIdentifier: bundleID)
        let onDisk = registered.filter { FileManager.default.fileExists(atPath: $0.path) }

        let report = DuplicateInstallReport.build(
            from: onDisk,
            runningURL: runningURL,
            versionReader: readVersion
        )
        if report.hasDuplicates {
            log.notice("Found \(report.copies.count) installed copies of \(bundleID, privacy: .public).")
        }
        return report
    }

    private static func readVersion(_ url: URL) -> (short: String, build: String) {
        let info = Bundle(url: url)?.infoDictionary
        let short = (info?["CFBundleShortVersionString"] as? String) ?? "—"
        let build = (info?["CFBundleVersion"] as? String) ?? "—"
        return (short, build)
    }
}
