import SwiftUI

/// The per-category toggle list, shared by all three platforms.
public struct CategoryToggleList: View {
    let settings: ProtectionSettings
    let onChange: (ThreatCategory, Bool) -> Void

    public init(settings: ProtectionSettings, onChange: @escaping (ThreatCategory, Bool) -> Void) {
        self.settings = settings
        self.onChange = onChange
    }

    public var body: some View {
        ForEach(ThreatCategory.toggleable) { category in
            Toggle(isOn: Binding(
                get: { settings.enabledCategories.contains(category) },
                set: { onChange(category, $0) }
            )) {
                Label {
                    VStack(alignment: .leading, spacing: 2) {
                        HStack(spacing: 6) {
                            Text(category.title)
                            if category.isSecurityCritical {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .font(.caption2)
                                    .foregroundStyle(.orange)
                                    .accessibilityLabel("Security critical")
                            }
                        }
                        Text(category.detail)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                } icon: {
                    Image(systemName: category.symbolName)
                        .foregroundStyle(Theme.color(for: category))
                }
            }
            .disabled(!settings.isProtectionEnabled)
        }
    }
}

/// Sensitivity picker plus the explanation of what each level does.
public struct SensitivityPicker: View {
    let selection: ProtectionSettings.Sensitivity
    let onChange: (ProtectionSettings.Sensitivity) -> Void

    public init(
        selection: ProtectionSettings.Sensitivity,
        onChange: @escaping (ProtectionSettings.Sensitivity) -> Void
    ) {
        self.selection = selection
        self.onChange = onChange
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Picker("Sensitivity", selection: Binding(
                get: { selection },
                set: { onChange($0) }
            )) {
                ForEach(ProtectionSettings.Sensitivity.allCases) { level in
                    Text(level.title).tag(level)
                }
            }
            #if !os(tvOS)
            .pickerStyle(.segmented)
            #endif

            Text(selection.detail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

/// Shows what Safari itself reports, because our own switch is only half the
/// story — the user has to enable the extension on the Safari side too.
public struct ExtensionStatusRow: View {
    let title: String
    let isEnabled: Bool?
    let helpText: String
    let action: (() -> Void)?

    public init(title: String, isEnabled: Bool?, helpText: String, action: (() -> Void)? = nil) {
        self.title = title
        self.isEnabled = isEnabled
        self.helpText = helpText
        self.action = action
    }

    private var symbol: String {
        switch isEnabled {
        case true: "checkmark.circle.fill"
        case false: "xmark.circle.fill"
        case nil: "questionmark.circle.fill"
        }
    }

    private var tint: Color {
        switch isEnabled {
        case true: Theme.safe
        case false: .red
        case nil: Theme.disabled
        }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Label(title, systemImage: symbol)
                    .foregroundStyle(tint)
                Spacer()
                if isEnabled == false, let action {
                    Button("Open Safari Settings", action: action)
                        .buttonStyle(.borderless)
                }
            }
            if isEnabled != true {
                Text(helpText)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}
