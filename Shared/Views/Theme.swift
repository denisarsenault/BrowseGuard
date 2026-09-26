import SwiftUI

/// Cross-platform color and layout tokens.
///
/// Deliberately avoids `UIColor`/`NSColor` bridges so the same view code
/// compiles for iOS, macOS, and tvOS without `#if` noise at every call site.
public enum Theme {

    public static func color(for severity: ThreatSeverity) -> Color {
        switch severity {
        case .critical: .red
        case .high: .orange
        case .medium: .yellow
        case .low: .blue
        }
    }

    public static func color(for category: ThreatCategory) -> Color {
        color(for: category.severity)
    }

    public static let safe = Color.green
    public static let disabled = Color.secondary

    /// tvOS is viewed from across a room; everything needs more air.
    public static var cardPadding: CGFloat {
        #if os(tvOS)
        32
        #else
        16
        #endif
    }

    public static var cornerRadius: CGFloat {
        #if os(tvOS)
        20
        #else
        12
        #endif
    }

    public static var gridMinimum: CGFloat {
        #if os(tvOS)
        320
        #else
        160
        #endif
    }
}

/// A card background that reads correctly in light and dark on every platform.
public struct CardBackground: ViewModifier {
    public func body(content: Content) -> some View {
        content
            .padding(Theme.cardPadding)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: Theme.cornerRadius))
    }
}

public extension View {
    func cardBackground() -> some View { modifier(CardBackground()) }
}
