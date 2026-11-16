import Foundation
import Observation
import StoreKit
import os

/// Sells BrowseGuard through StoreKit and keeps the App Group's
/// `EntitlementRecord` current.
///
/// Why StoreKit and not a license key: the App Store does not let a Mac or iOS
/// app unlock paid digital functionality with keys of its own. Apple's signed
/// transactions are the only license this app honours, so purchase, renewal,
/// refund and restore all come from them.
@MainActor
@Observable
public final class SubscriptionStore {

    public private(set) var products: [Product] = []
    public private(set) var record: EntitlementRecord
    public private(set) var isLoadingProducts = false
    public private(set) var isPurchasing = false
    /// The last thing that went wrong or needs the user's attention, in words
    /// the paywall can show as they are.
    public private(set) var message: String?

    /// Fired when the record changes, so the coordinator can recompile the
    /// rules and tell Safari.
    public var onChange: ((EntitlementRecord) -> Void)?

    private var transactionUpdates: Task<Void, Never>?
    private var expiryCheck: Task<Void, Never>?
    private let log = Logger(subsystem: "com.mybrightzone.BrowseGuard", category: "Subscription")

    public init() {
        record = SharedStore.entitlement()
    }

    public var isActive: Bool { record.isActive() }

    /// Begins listening for transactions that arrive outside a purchase this
    /// session made: renewals, Family Sharing, refunds, and purchases made on
    /// another device. Safe to call more than once.
    public func start() {
        guard transactionUpdates == nil else { return }
        transactionUpdates = Task { [weak self] in
            for await result in Transaction.updates {
                guard let self else { return }
                if case .verified(let transaction) = result {
                    await transaction.finish()
                }
                await self.refresh()
            }
        }
        Task {
            await loadProducts()
            await refresh()
        }
    }

    public func loadProducts() async {
        isLoadingProducts = true
        defer { isLoadingProducts = false }
        do {
            let loaded = try await Product.products(for: BrowseGuardProduct.all)
            // Keep the order the identifiers are listed in, so monthly comes first.
            products = BrowseGuardProduct.all.compactMap { id in
                loaded.first { $0.id == id }
            }
            if products.isEmpty {
                log.error("StoreKit returned no products for the configured identifiers")
                message = "No subscriptions are available right now."
            }
        } catch {
            log.error("Product load failed: \(error.localizedDescription, privacy: .public)")
            message = "The App Store could not be reached. Try again in a moment."
        }
    }

    /// Rebuilds the record from the App Store's current entitlements.
    public func refresh() async {
        var newest: Transaction?
        for await result in Transaction.currentEntitlements {
            guard case .verified(let transaction) = result,
                  BrowseGuardProduct.all.contains(transaction.productID),
                  transaction.revocationDate == nil
            else { continue }

            // If the user somehow holds two (for example, a plan switch that has
            // not yet been reconciled), the one that runs longest is the one to honour.
            let current = newest?.expirationDate ?? .distantPast
            if newest == nil || (transaction.expirationDate ?? .distantFuture) > current {
                newest = transaction
            }
        }

        var graceEnd: Date?
        if let transaction = newest,
           let subscription = products.first(where: { $0.id == transaction.productID })?.subscription,
           let statuses = try? await Product.SubscriptionInfo.status(for: subscription.subscriptionGroupID) {
            for status in statuses where status.state == .inGracePeriod {
                if case .verified(let renewal) = status.renewalInfo {
                    graceEnd = renewal.gracePeriodExpirationDate
                }
            }
        }

        publish(EntitlementRecord(
            productID: newest?.productID,
            expiresAt: newest?.expirationDate,
            gracePeriodEndsAt: graceEnd
        ))
    }

    public func purchase(_ product: Product) async {
        isPurchasing = true
        defer { isPurchasing = false }
        message = nil
        do {
            switch try await product.purchase() {
            case .success(let verification):
                guard case .verified(let transaction) = verification else {
                    message = "The App Store could not verify that purchase, so nothing was unlocked."
                    return
                }
                await transaction.finish()
                await refresh()
            case .userCancelled:
                break
            case .pending:
                message = "The purchase is waiting for approval. BrowseGuard unlocks once it is approved."
            @unknown default:
                break
            }
        } catch {
            log.error("Purchase failed: \(error.localizedDescription, privacy: .public)")
            message = "The purchase did not complete. Nothing was charged."
        }
    }

    /// For a new device, or after reinstalling. Asks the App Store to re-sync
    /// purchases for this Apple ID, which may prompt for sign-in.
    public func restore() async {
        isPurchasing = true
        defer { isPurchasing = false }
        message = nil
        do {
            try await AppStore.sync()
            await refresh()
            if !isActive {
                message = "No active BrowseGuard subscription was found for this Apple ID."
            }
        } catch {
            log.error("Restore failed: \(error.localizedDescription, privacy: .public)")
            message = "Restore did not complete. Check your connection and try again."
        }
    }

    private func publish(_ new: EntitlementRecord) {
        scheduleExpiryCheck(for: new)
        guard new != record else { return }
        record = new
        SharedStore.write(new, to: .entitlement)
        log.info("Entitlement is now \(new.isActive() ? "active" : "lapsed", privacy: .public)")
        onChange?(new)
    }

    /// A running app should not wait for its next launch to notice a lapse.
    /// Wake at the end of the paid period or the grace window, whichever is
    /// later, and ask StoreKit again then.
    private func scheduleExpiryCheck(for record: EntitlementRecord) {
        expiryCheck?.cancel()
        let boundary = [record.expiresAt, record.gracePeriodEndsAt].compactMap { $0 }.max()
        guard let boundary else { return }
        let delay = max(0, boundary.timeIntervalSinceNow) + 1
        expiryCheck = Task { [weak self] in
            try? await Task.sleep(for: .seconds(delay))
            guard !Task.isCancelled else { return }
            await self?.refresh()
        }
    }
}
