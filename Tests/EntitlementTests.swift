import Foundation
import Testing

/// The rules that decide whether BrowseGuard filters at all. A fixed clock is
/// used throughout, so the expiry and grace boundaries are exact rather than
/// something a test run can land on either side of.
@Suite(.serialized)
struct EntitlementTests {

    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    @Test("No record means no subscription")
    func unsubscribedIsInactive() {
        #expect(!EntitlementRecord.unsubscribed.isActive(at: now))
    }

    @Test("A paid period runs until its end and not a second longer")
    func activeUntilExpiry() {
        let record = EntitlementRecord(
            productID: BrowseGuardProduct.monthly,
            expiresAt: now.addingTimeInterval(60)
        )
        #expect(record.isActive(at: now))
        #expect(record.isActive(at: now.addingTimeInterval(59)))
        #expect(!record.isActive(at: now.addingTimeInterval(60)))
        #expect(!record.isActive(at: now.addingTimeInterval(3_600)))
    }

    @Test("Billing grace keeps use going after the period ends, then stops")
    func graceWindow() {
        let record = EntitlementRecord(
            productID: BrowseGuardProduct.annual,
            expiresAt: now.addingTimeInterval(-86_400),
            gracePeriodEndsAt: now.addingTimeInterval(86_400)
        )
        #expect(record.isActive(at: now), "a renewal being retried must not cut the user off")
        #expect(!record.isActive(at: now.addingTimeInterval(86_401)), "grace has a finite end")
    }

    @Test("A grace window without a product is not a subscription")
    func graceNeedsProduct() {
        let record = EntitlementRecord(
            productID: nil,
            expiresAt: nil,
            gracePeriodEndsAt: now.addingTimeInterval(86_400)
        )
        #expect(!record.isActive(at: now))
    }

    @Test("A lapsed subscription turns protection off without touching the saved choice")
    func lapseKeepsSavedChoice() {
        var settings = ProtectionSettings.default
        settings.isProtectionEnabled = true
        let lapsed = EntitlementRecord(
            productID: BrowseGuardProduct.monthly,
            expiresAt: now.addingTimeInterval(-1)
        )

        let effective = ProtectionEngine.effective(settings, entitlement: lapsed, at: now)

        #expect(!effective.isProtectionEnabled)
        #expect(settings.isProtectionEnabled, "renewing must restore exactly what the user chose")
    }

    @Test("An active subscription leaves the settings as the user saved them")
    func activeKeepsSettings() {
        var settings = ProtectionSettings.default
        settings.isProtectionEnabled = true
        let active = EntitlementRecord(
            productID: BrowseGuardProduct.monthly,
            expiresAt: now.addingTimeInterval(3_600)
        )

        let effective = ProtectionEngine.effective(settings, entitlement: active, at: now)

        #expect(effective.isProtectionEnabled)
    }

    @Test("The record survives the App Group round trip with its dates intact")
    func roundTripThroughAppGroup() throws {
        // Whole seconds: the ISO-8601 encoding used for the file does not keep fractions.
        let record = EntitlementRecord(
            productID: BrowseGuardProduct.annual,
            expiresAt: now.addingTimeInterval(3_600),
            gracePeriodEndsAt: nil
        )
        guard SharedStore.write(record, to: .entitlement) else { return }   // no App Group here
        defer { SharedStore.write(EntitlementRecord.unsubscribed, to: .entitlement) }

        #expect(SharedStore.entitlement() == record)
    }

    @Test("The content blocker reads the same file the app writes")
    func blockerReadsSameFile() throws {
        let record = EntitlementRecord(
            productID: BrowseGuardProduct.monthly,
            expiresAt: now.addingTimeInterval(3_600),
            gracePeriodEndsAt: nil
        )
        guard SharedStore.write(record, to: .entitlement),
              let url = AppGroup.File.entitlement.url
        else { return }
        defer { SharedStore.write(EntitlementRecord.unsubscribed, to: .entitlement) }

        #expect(EntitlementRecord.load(from: url) == record)
    }

    @Test("Both sold products are offered, monthly first")
    func productsAreOffered() {
        #expect(BrowseGuardProduct.all == [BrowseGuardProduct.monthly, BrowseGuardProduct.annual])
        #expect(Set(BrowseGuardProduct.all).count == 2)
    }
}
