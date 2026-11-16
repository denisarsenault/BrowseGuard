import Foundation

/// The products BrowseGuard sells. The same identifiers are registered in
/// App Store Connect and listed in `StoreKit/BrowseGuard.storekit` for local
/// testing; a mismatch between the two shows up as "no products" in the paywall.
public enum BrowseGuardProduct {
    public static let monthly = "com.mybrightzone.BrowseGuard.monthly"
    public static let annual = "com.mybrightzone.BrowseGuard.annual"

    /// Both live in one subscription group, so a subscriber can move between
    /// plans without being billed twice.
    public static let all = [monthly, annual]
}

/// What the App Store last said about this Apple ID's subscription, cached in
/// the App Group so the extensions can honour it. They cannot call StoreKit.
///
/// The App Store is the authority. The app rewrites this file whenever StoreKit
/// reports a change. Readers check the dates against the clock instead of
/// trusting a stored "active" flag, so a subscription that lapses while the app
/// is closed stops working without anything having to run to notice.
///
/// Anyone who can edit the App Group container can change this file. That is an
/// accepted limit for v1. Verifying the signed transaction inside the extension
/// is the stronger option if it ever matters.
public struct EntitlementRecord: Codable, Equatable, Sendable {
    /// The product the current subscription belongs to. `nil` means none.
    public var productID: String?
    /// End of the paid period, from the verified transaction.
    public var expiresAt: Date?
    /// End of Apple's billing-retry window. Use continues until then while a
    /// renewal payment is being retried.
    public var gracePeriodEndsAt: Date?

    public init(productID: String? = nil, expiresAt: Date? = nil, gracePeriodEndsAt: Date? = nil) {
        self.productID = productID
        self.expiresAt = expiresAt
        self.gracePeriodEndsAt = gracePeriodEndsAt
    }

    public static let unsubscribed = EntitlementRecord()

    public func isActive(at now: Date = .now) -> Bool {
        guard productID != nil else { return false }
        if let expiresAt, expiresAt > now { return true }
        if let gracePeriodEndsAt, gracePeriodEndsAt > now { return true }
        return false
    }

    /// Read by the content blocker, which does not compile in `SharedStore`.
    /// Uses the same ISO-8601 dates as `SharedStore`, so both sides agree.
    public static func load(from url: URL) -> EntitlementRecord? {
        guard let data = try? Data(contentsOf: url) else { return nil }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return try? decoder.decode(EntitlementRecord.self, from: data)
    }
}
