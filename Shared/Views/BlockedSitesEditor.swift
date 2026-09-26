import SwiftUI

/// Add/remove rows for the user's own block list.
///
/// The counterpart to `AllowlistEditor`. Kept visually distinct from it on
/// purpose — confusing "never load this" with "always load this" is the one
/// mistake in this screen that would actually matter.
public struct BlockedSitesEditor: View {
    @Environment(ProtectionCoordinator.self) private var coordinator
    @State private var newHost = ""
    @State private var showsInvalidInput = false

    public init() {}

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                TextField("Block a site — example.com", text: $newHost)
                    #if !os(tvOS)
                    .textFieldStyle(.roundedBorder)
                    #endif
                    #if os(iOS)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    #endif
                    .onSubmit(add)

                Button("Block", action: add)
                    .disabled(newHost.trimmingCharacters(in: .whitespaces).isEmpty)
            }

            if showsInvalidInput {
                Label("That doesn't look like a website address.", systemImage: "exclamationmark.circle")
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            if coordinator.userBlocklist.items.isEmpty {
                Text("Nothing blocked by you. Sites you add here are blocked regardless of what the threat lists say — useful for a time sink, or for testing that blocking works.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(coordinator.userBlocklist.items) { item in
                    BlockedSiteRow(item: item) {
                        Task { await coordinator.unblock(host: item.host) }
                    }
                }
            }
        }
    }

    private func add() {
        let candidate = newHost
        guard URLNormalizer.canonicalHost(of: candidate) != nil else {
            showsInvalidInput = true
            return
        }
        showsInvalidInput = false
        newHost = ""
        Task { await coordinator.block(host: candidate) }
    }
}

public struct BlockedSiteRow: View {
    let item: BlockedSite
    let onRemove: () -> Void

    public init(item: BlockedSite, onRemove: @escaping () -> Void) {
        self.item = item
        self.onRemove = onRemove
    }

    public var body: some View {
        HStack {
            Image(systemName: "hand.raised.slash.fill")
                .foregroundStyle(.red)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.host)
                    .lineLimit(1)
                    .truncationMode(.middle)
                if let note = item.note, !note.isEmpty {
                    Text(note)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 8)
            Button(role: .destructive, action: onRemove) {
                Image(systemName: "trash")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("Unblock \(item.host)")
        }
        .padding(.vertical, 2)
    }
}
