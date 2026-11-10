import Foundation
import Testing

struct DuplicateInstallTests {

    /// A version reader backed by a path → (short, build) table.
    private func reader(_ table: [String: (String, String)]) -> (URL) -> (short: String, build: String) {
        { url in
            let v = table[url.path] ?? ("?", "?")
            return (v.0, v.1)
        }
    }

    @Test func singleCopyIsNotADuplicate() {
        let running = URL(fileURLWithPath: "/Applications/BrowseGuard.app")
        let report = DuplicateInstallReport.build(
            from: [running],
            runningURL: running,
            versionReader: reader(["/Applications/BrowseGuard.app": ("2.0", "200")])
        )
        #expect(report.hasDuplicates == false)
        #expect(report.copies.count == 1)
        #expect(report.runningCopy?.url.path == running.path)
        #expect(report.otherCopies.isEmpty)
    }

    @Test func multipleCopiesAreFlaggedAndRunningMarked() {
        let running = URL(fileURLWithPath: "/Applications/BrowseGuard.app")
        let stale = URL(fileURLWithPath: "/Users/me/Downloads/BrowseGuard.app")
        let report = DuplicateInstallReport.build(
            from: [stale, running],                 // order shouldn't matter
            runningURL: running,
            versionReader: reader([
                "/Applications/BrowseGuard.app": ("2.0", "200"),
                "/Users/me/Downloads/BrowseGuard.app": ("1.3", "130"),
            ])
        )
        #expect(report.hasDuplicates)
        #expect(report.copies.count == 2)
        #expect(report.runningCopy?.url.path == running.path)
        #expect(report.otherCopies.map(\.url.path) == [stale.path])
        #expect(report.distinctVersionCount == 2)
    }

    @Test func identicalPathsAreCollapsed() {
        let running = URL(fileURLWithPath: "/Applications/BrowseGuard.app")
        let sameWithSlash = URL(fileURLWithPath: "/Applications/BrowseGuard.app/")
        let report = DuplicateInstallReport.build(
            from: [running, sameWithSlash, running], // dupes from Launch Services
            runningURL: running,
            versionReader: reader(["/Applications/BrowseGuard.app": ("2.0", "200")])
        )
        #expect(report.copies.count == 1)
        #expect(report.hasDuplicates == false)
    }

    // MARK: - First-launch prompt gate

    @Test func noPromptWhenNoDuplicates() {
        #expect(DuplicateInstallPrompt.shouldPrompt(
            hasDuplicates: false, currentVersion: "2.0 (200)", lastPromptedVersion: nil) == false)
    }

    @Test func promptsOnceForANewVersionWithDuplicates() {
        // First time this version is seen → prompt.
        #expect(DuplicateInstallPrompt.shouldPrompt(
            hasDuplicates: true, currentVersion: "2.0 (200)", lastPromptedVersion: nil))
        // Already prompted for this version → stay quiet.
        #expect(DuplicateInstallPrompt.shouldPrompt(
            hasDuplicates: true, currentVersion: "2.0 (200)", lastPromptedVersion: "2.0 (200)") == false)
    }

    @Test func promptsAgainAfterAnUpdate() {
        #expect(DuplicateInstallPrompt.shouldPrompt(
            hasDuplicates: true, currentVersion: "2.1 (210)", lastPromptedVersion: "2.0 (200)"))
    }

    @Test func sameVersionInstalledTwiceStillCountsAsDuplicateCopies() {
        let a = URL(fileURLWithPath: "/Applications/BrowseGuard.app")
        let b = URL(fileURLWithPath: "/Applications/BrowseGuard 2.app")
        let report = DuplicateInstallReport.build(
            from: [a, b],
            runningURL: a,
            versionReader: reader([
                "/Applications/BrowseGuard.app": ("2.0", "200"),
                "/Applications/BrowseGuard 2.app": ("2.0", "200"),
            ])
        )
        #expect(report.hasDuplicates)                 // two copies…
        #expect(report.distinctVersionCount == 1)     // …even though same version
        #expect(report.otherCopies.map(\.url.path) == [b.path])
    }
}
