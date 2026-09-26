import SwiftUI

/// Lets the user test any address against the engine without visiting it.
///
/// This is the feature that makes the heuristics legible: paste a link from an
/// email, see exactly which rules fire and why, and decide before clicking.
public struct SiteCheckerView: View {
    @Environment(ProtectionCoordinator.self) private var coordinator
    @State private var input = ""
    @State private var verdict: Verdict?

    public init() {}

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Paste a link you were sent and BrowseGuard will tell you what it thinks — without loading it.")
                .font(.subheadline)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            HStack {
                TextField("example.com", text: $input)
                    #if !os(tvOS)
                    .textFieldStyle(.roundedBorder)
                    #endif
                    #if os(iOS)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .keyboardType(.URL)
                    #endif
                    .onSubmit(check)

                Button("Check", action: check)
                    .disabled(input.trimmingCharacters(in: .whitespaces).isEmpty)
            }

            if let verdict {
                VerdictCard(verdict: verdict) {
                    Task { await coordinator.allow(host: verdict.host) }
                }
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .animation(.default, value: verdict)
    }

    private func check() {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        verdict = coordinator.engine.evaluate(host: trimmed)
    }
}

/// The verdict panel — also the in-app preview of what the block page shows.
public struct VerdictCard: View {
    let verdict: Verdict
    let onAllow: (() -> Void)?

    public init(verdict: Verdict, onAllow: (() -> Void)? = nil) {
        self.verdict = verdict
        self.onAllow = onAllow
    }

    private var tint: Color {
        switch verdict.decision {
        case .block: Theme.color(for: verdict.severity)
        case .warn: .orange
        case .allow: Theme.safe
        case .allowlisted: .blue
        }
    }

    private var symbol: String {
        switch verdict.decision {
        case .block: "xmark.octagon.fill"
        case .warn: "exclamationmark.triangle.fill"
        case .allow: "checkmark.shield.fill"
        case .allowlisted: "hand.raised.fill"
        }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 12) {
                Image(systemName: symbol)
                    .font(.title)
                    .foregroundStyle(tint)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text(verdict.headline).font(.headline)
                    Text(verdict.host)
                        .font(.subheadline.monospaced())
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }

            Text(verdict.explanation)
                .font(.subheadline)
                .fixedSize(horizontal: false, vertical: true)

            if !verdict.signals.isEmpty {
                Divider()
                VStack(alignment: .leading, spacing: 6) {
                    Text("What tripped")
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    ForEach(verdict.signals, id: \.rule) { signal in
                        HStack(alignment: .firstTextBaseline, spacing: 8) {
                            Text("•").foregroundStyle(tint)
                            Text(signal.explanation)
                                .font(.caption)
                                .fixedSize(horizontal: false, vertical: true)
                            Spacer(minLength: 0)
                            Text(signal.weight, format: .number.precision(.fractionLength(2)))
                                .font(.caption.monospacedDigit())
                                .foregroundStyle(.tertiary)
                        }
                    }
                    HStack {
                        Text("Confidence")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                        Spacer()
                        Text(verdict.confidence, format: .percent.precision(.fractionLength(0)))
                            .font(.caption.monospacedDigit())
                    }
                }
            }

            if verdict.isBlocking, let onAllow {
                Button("Add \(verdict.host) to allowlist", action: onAllow)
                    .buttonStyle(.bordered)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .cardBackground()
    }
}
