import StoreKit
import SwiftUI

/// Wraps a platform's root view. With an active subscription the content shows;
/// without one the paywall takes its place, so nothing runs behind it.
struct SubscriptionGate<Content: View>: View {
    @Environment(ProtectionCoordinator.self) private var coordinator
    private let content: () -> Content

    init(@ViewBuilder content: @escaping () -> Content) {
        self.content = content
    }

    var body: some View {
        if coordinator.isEntitled {
            content()
        } else {
            PaywallView()
        }
    }
}

/// Shown whenever there is no active subscription. Apple's review asks for the
/// price, the billing period, the auto-renewal terms, a way to restore, and
/// working terms and privacy links. All of them are here.
struct PaywallView: View {
    @Environment(ProtectionCoordinator.self) private var coordinator

    private var store: SubscriptionStore { coordinator.subscription }

    /// Someone who subscribed and let it lapse gets different words from someone
    /// who has never subscribed.
    private var hadSubscription: Bool { store.record.productID != nil }

    var body: some View {
        ScrollView {
            VStack(spacing: 22) {
                Image(systemName: "shield.lefthalf.filled")
                    .font(.system(size: 56))
                    .foregroundStyle(.tint)

                Text(hadSubscription ? "Your subscription has ended" : "Start protecting this device")
                    .font(.title2.weight(.semibold))
                    .multilineTextAlignment(.center)

                Text(hadSubscription
                     ? "Filtering is paused until you renew. Your settings, allowed sites and blocked sites are all kept."
                     : "BrowseGuard blocks malware, scams and trackers in Safari. A subscription keeps it running.")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
                    .frame(maxWidth: 480)

                if store.isLoadingProducts {
                    ProgressView()
                }

                VStack(spacing: 12) {
                    ForEach(store.products, id: \.id) { product in
                        Button {
                            Task { await store.purchase(product) }
                        } label: {
                            VStack(spacing: 2) {
                                Text(product.displayName).font(.headline)
                                Text("\(product.displayPrice) \(periodPhrase(for: product))")
                                    .font(.subheadline)
                            }
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 6)
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(store.isPurchasing)
                    }
                }
                .frame(maxWidth: 360)

                Button("Restore Purchases") {
                    Task { await store.restore() }
                }
                .disabled(store.isPurchasing)

                if let message = store.message {
                    Text(message)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .multilineTextAlignment(.center)
                        .frame(maxWidth: 480)
                }

                legal
            }
            .padding(.horizontal, 24)
            .padding(.vertical, 40)
            .frame(maxWidth: .infinity)
        }
        .task {
            if store.products.isEmpty { await store.loadProducts() }
        }
    }

    private var legal: some View {
        VStack(spacing: 8) {
            Text("Payment is charged to your Apple Account when you confirm the purchase. The subscription renews automatically unless it is cancelled at least 24 hours before the end of the current period. Manage or cancel it in your App Store account settings.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 480)

            #if !os(tvOS)
            HStack(spacing: 16) {
                if let terms = ConfiguredURL.https(infoKey: "BGTermsURL") {
                    Link("Terms of Use", destination: terms)
                }
                if let privacy = ConfiguredURL.https(infoKey: "BGPrivacyURL") {
                    Link("Privacy Policy", destination: privacy)
                }
                Link("Manage Subscription", destination: URL(string: "https://apps.apple.com/account/subscriptions")!)
            }
            .font(.caption)
            #else
            Text("Manage your subscription on iPhone or Mac.")
                .font(.caption)
                .foregroundStyle(.secondary)
            #endif
        }
        .padding(.top, 8)
    }

    private func periodPhrase(for product: Product) -> String {
        guard let period = product.subscription?.subscriptionPeriod else { return "" }
        let unit: String
        switch period.unit {
        case .day: unit = "day"
        case .week: unit = "week"
        case .month: unit = "month"
        case .year: unit = "year"
        @unknown default: unit = "period"
        }
        return period.value == 1 ? "per \(unit)" : "per \(period.value) \(unit)s"
    }
}
