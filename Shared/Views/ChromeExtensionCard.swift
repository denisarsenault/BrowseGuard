import SwiftUI

/// Offers the Chrome extension, when a Web Store listing has been configured.
///
/// A link rather than a button that installs: Chrome removed external installs
/// from a local `.crx` on macOS in Chrome 44, an external-extension entry's
/// update URL must point at the Web Store, and a sandboxed App Store app
/// cannot write into Chrome's support directory in any case. The listing is
/// the installer; this just takes you there.
///
/// Hidden entirely until `BROWSEGUARD_CHROME_URL` is set, so a build without a
/// published listing does not advertise a link that goes nowhere.
public struct ChromeExtensionCard: View {

    public init() {}

    /// Reads the listing from Info.plist. See `ConfiguredURL` for why https
    /// is required and why "not configured" is a normal state.
    static var listingURL: URL? {
        ConfiguredURL.https(infoKey: "BGChromeExtensionURL")
    }

    public var body: some View {
        if let url = Self.listingURL {
            VStack(alignment: .leading, spacing: 8) {
                Label("Also protect Chrome", systemImage: "globe")
                    .font(.headline)
                Text("""
                    BrowseGuard has a Chrome extension with the same blocklists \
                    and the same heuristics. Its allowed and blocked sites are \
                    kept separately from this app — nothing syncs between \
                    browsers.
                    """)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

                Link("Get it from the Chrome Web Store", destination: url)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .cardBackground()
        }
    }
}
