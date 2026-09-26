import SwiftUI

/// Add/remove rows for the allowlist, shared by iOS and macOS.
///
/// tvOS gets a read-only variant: typing a domain on a remote is miserable, and
/// the list syncs from the phone or Mac anyway.
public struct AllowlistEditor: View {
    @Environment(ProtectionCoordinator.self) private var coordinator
    @State private var newHost = ""
    @State private var showsInvalidInput = false

    public init() {}

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                TextField("Add a site — example.com", text: $newHost)
                    #if !os(tvOS)
                    .textFieldStyle(.roundedBorder)
                    #endif
                    #if os(iOS)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    #endif
                    .onSubmit(add)

                Button("Add", action: add)
                    .disabled(newHost.trimmingCharacters(in: .whitespaces).isEmpty)
            }

            if showsInvalidInput {
                Label("That doesn't look like a website address.", systemImage: "exclamationmark.circle")
                    .font(.caption)
                    .foregroundStyle(.red)
            }

            if coordinator.allowlist.activeItems.isEmpty {
                Text("Nothing allowlisted. Sites you choose to permit — and sites you continue past on a block page — appear here.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                ForEach(coordinator.allowlist.activeItems) { item in
                    AllowlistRow(item: item) {
                        Task { await coordinator.removeFromAllowlist(host: item.host) }
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
        Task { await coordinator.allow(host: candidate) }
    }
}

public struct AllowlistRow: View {
    let item: AllowlistItem
    let onRemove: () -> Void

    public init(item: AllowlistItem, onRemove: @escaping () -> Void) {
        self.item = item
        self.onRemove = onRemove
    }

    public var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text(item.host)
                    .lineLimit(1)
                    .truncationMode(.middle)
                if let expiresAt = item.expiresAt {
                    Text("Temporary — lapses \(expiresAt, format: .relative(presentation: .numeric))")
                        .font(.caption)
                        .foregroundStyle(.orange)
                } else if let category = item.bypassedCategory {
                    Text("You allowed this past a \(category.title.lowercased()) block")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 8)
            Button(role: .destructive, action: onRemove) {
                Image(systemName: "trash")
            }
            .buttonStyle(.borderless)
            .accessibilityLabel("Remove \(item.host) from allowlist")
        }
        .padding(.vertical, 2)
    }
}
