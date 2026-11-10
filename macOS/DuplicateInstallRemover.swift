import AppKit
import Foundation
import UniformTypeIdentifiers
import os

/// Moves a stray copy of BrowseGuard to the Trash — the App-Store-safe way.
///
/// A sandboxed app cannot delete a bundle it merely *found*; it can only touch a
/// file the user hands it. So removal always goes through an open panel pointed
/// at the copy: the user confirms by selecting it, which grants the sandbox scope
/// that `files.user-selected.read-write` needs, and only then do we trash it. The
/// panel is pre-pointed at the copy's folder so the confirmation is one click, but
/// the user is always the one who authorizes the delete.
enum DuplicateInstallRemover {

    private static let log = Logger(subsystem: "com.mybrightzone.BrowseGuard", category: "DuplicateInstall")

    enum Outcome: Equatable {
        case trashed
        case cancelled
        /// The user picked a different item than the copy we meant to remove.
        case mismatch
        case failed(String)
    }

    @MainActor
    static func moveToTrash(_ copy: InstalledCopy) -> Outcome {
        let panel = NSOpenPanel()
        panel.title = "Remove Old BrowseGuard"
        panel.message = "Confirm the old copy to move to the Trash:\n\(copy.url.path)"
        panel.prompt = "Move to Trash"
        panel.directoryURL = copy.url.deletingLastPathComponent()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.treatsFilePackagesAsDirectories = false   // pick the .app itself, not inside it
        panel.allowedContentTypes = [.application]

        guard panel.runModal() == .OK, let chosen = panel.url else { return .cancelled }

        // Only trash the copy we were asked about — never whatever else was picked.
        guard chosen.standardizedFileURL.path == copy.url.standardizedFileURL.path else {
            return .mismatch
        }

        do {
            try FileManager.default.trashItem(at: chosen, resultingItemURL: nil)
            log.notice("Moved a duplicate BrowseGuard copy to the Trash.")
            return .trashed
        } catch {
            log.error("Failed to trash duplicate copy: \(error.localizedDescription, privacy: .public)")
            return .failed(error.localizedDescription)
        }
    }
}
