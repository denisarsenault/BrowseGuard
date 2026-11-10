import SwiftUI
import AppKit

/// Warns that more than one copy of BrowseGuard is installed, lists them, and
/// offers to move each stray copy to the Trash (user-confirmed) or reveal it in
/// Finder. Shown at the top of the Overview only when `report.hasDuplicates`.
struct DuplicateInstallBanner: View {
    let report: DuplicateInstallReport
    /// Called after a copy is removed so the parent can re-scan and refresh.
    var onRemoved: () -> Void = {}

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Multiple copies of BrowseGuard are installed", systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundStyle(.orange)

            Text("""
            Safari loads the extension from every copy it finds, so a stray or older \
            build can keep serving stale rules and show a duplicate extension. Keep one \
            copy — ideally in Applications — move the others to the Trash, then quit and \
            reopen Safari.
            """)
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)

            VStack(spacing: 8) {
                ForEach(report.copies, id: \.url) { copy in
                    HStack(spacing: 10) {
                        Image(systemName: copy.isRunningCopy ? "checkmark.circle.fill" : "trash.circle")
                            .foregroundStyle(copy.isRunningCopy ? .green : .orange)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(copy.url.path)
                                .font(.caption.monospaced())
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Text(subtitle(for: copy))
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                        }
                        Spacer(minLength: 8)
                        Button("Reveal") {
                            NSWorkspace.shared.activateFileViewerSelecting([copy.url])
                        }
                        .buttonStyle(.link)
                        if !copy.isRunningCopy {
                            Button("Move to Trash…") { remove(copy) }
                                .buttonStyle(.borderless)
                                .tint(.orange)
                        }
                    }
                }
            }

            if let failureMessage {
                Text(failureMessage)
                    .font(.caption)
                    .foregroundStyle(.red)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .cardBackground()
    }

    @State private var failureMessage: String?

    private func remove(_ copy: InstalledCopy) {
        failureMessage = nil
        switch DuplicateInstallRemover.moveToTrash(copy) {
        case .trashed:
            onRemoved()
        case .cancelled, .mismatch:
            break   // user backed out or picked the wrong item; leave the list as-is
        case .failed(let message):
            failureMessage = "Couldn’t move it to the Trash: \(message)"
        }
    }

    private func subtitle(for copy: InstalledCopy) -> String {
        let version = "Version \(copy.shortVersion) (\(copy.buildVersion))"
        return copy.isRunningCopy ? "\(version) · this copy" : version
    }
}
