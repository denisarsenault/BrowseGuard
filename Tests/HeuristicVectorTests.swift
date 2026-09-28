import Foundation
import Testing

/// The Swift half of the cross-implementation check.
///
/// `WebExtension/Shared/heuristics.js` reimplements `HeuristicScanner` because
/// Chrome has no native side to ask. Two copies of the same rules drift unless
/// something stops them, so both are run against `Tests/heuristic-vectors.json`
/// — this suite proves Swift still agrees with the file, and
/// `scripts/test_heuristics.mjs` proves JavaScript does.
@Suite("Heuristic vectors")
struct HeuristicVectorTests {

    struct Vector: Codable {
        let host: String
        let rules: [String]
        let risk: Double
    }

    /// Hosts chosen to exercise each rule, plus ordinary sites that must stay
    /// clean. Add to this list when adding a heuristic.
    static let hosts = [
        "apple.com", "google.com", "github.com", "nytimes.com",
        "en.wikipedia.org", "developer.apple.com", "stackoverflow.com",
        "gogle.com", "paypa1.com", "micosoft.com", "netflx.com", "gogole.com",
        "apple.com.secure-login.example", "icloud-verify.tk",
        "verify-account.tk", "secure-login-update-now.xyz",
        "192.0.2.14", "x7q2mzbv9kdf.com", "a1b2c3d4e5.example",
        "a.b.c.d.example.com", "xn--pple-43d.com",
        "xn--80ak6aa92e.com", "xn--nxasmm1c.com",
    ]

    static let vectorsURL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .appendingPathComponent("heuristic-vectors.json")

    @Test("Swift still matches the shared vectors")
    func matchesVectors() throws {
        let scanner = HeuristicScanner()
        let data = try Data(contentsOf: Self.vectorsURL)
        let expected = try JSONDecoder().decode([Vector].self, from: data)

        #expect(expected.count == Self.hosts.count,
                "vector file is stale; regenerate it with scripts/make_heuristic_vectors.swift")

        for vector in expected {
            let rules = scanner.signals(for: vector.host).map(\.rule).sorted()
            #expect(rules == vector.rules.sorted(),
                    "\(vector.host): Swift fired \(rules), vectors say \(vector.rules.sorted())")
            let risk = scanner.risk(for: vector.host)
            #expect(abs(risk - vector.risk) < 0.0001,
                    "\(vector.host): Swift risk \(risk), vectors say \(vector.risk)")
        }
    }
}
