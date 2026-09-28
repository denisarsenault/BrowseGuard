// Regenerates Tests/heuristic-vectors.json from the Swift scanner, which is the
// source of truth. The JavaScript port is checked against the result.
//
//   swift scripts/make_heuristic_vectors.swift
import Foundation

let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
let sources = [
    "Shared/Core/HeuristicScanner.swift",
    "Shared/Core/URLNormalizer.swift",
]
// Compiled on the fly so this stays a one-file script with no target to wire up.
let temp = FileManager.default.temporaryDirectory.appendingPathComponent("bgvec")
try? FileManager.default.removeItem(at: temp)
try FileManager.default.createDirectory(at: temp, withIntermediateDirectories: true)

let hosts = [
    "apple.com", "google.com", "github.com", "nytimes.com",
    "en.wikipedia.org", "developer.apple.com", "stackoverflow.com",
    "gogle.com", "paypa1.com", "micosoft.com", "netflx.com", "gogole.com",
    "apple.com.secure-login.example", "icloud-verify.tk",
    "verify-account.tk", "secure-login-update-now.xyz",
    "192.0.2.14", "x7q2mzbv9kdf.com", "a1b2c3d4e5.example",
    "a.b.c.d.example.com", "xn--pple-43d.com",
    "xn--80ak6aa92e.com", "xn--nxasmm1c.com",
]

var driver = "import Foundation\n"
for source in sources {
    driver += try String(contentsOf: root.appendingPathComponent(source), encoding: .utf8)
        .replacingOccurrences(of: "\nimport Foundation", with: "")
}
driver += """

struct Vector: Codable { let host: String; let rules: [String]; let risk: Double }
let scanner = HeuristicScanner()
let hosts = \(hosts)
let vectors = hosts.map { host in
    Vector(host: host,
           rules: scanner.signals(for: host).map(\\.rule).sorted(),
           risk: (scanner.risk(for: host) * 10_000).rounded() / 10_000)
}
let encoder = JSONEncoder()
encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
FileHandle.standardOutput.write(try! encoder.encode(vectors))

"""
let driverURL = temp.appendingPathComponent("driver.swift")
try driver.write(to: driverURL, atomically: true, encoding: .utf8)

let out = temp.appendingPathComponent("driver")
let build = Process()
build.executableURL = URL(fileURLWithPath: "/usr/bin/env")
build.arguments = ["swiftc", "-O", driverURL.path, "-o", out.path]
try build.run(); build.waitUntilExit()
guard build.terminationStatus == 0 else { exit(1) }

let run = Process()
run.executableURL = out
let pipe = Pipe(); run.standardOutput = pipe
try run.run(); run.waitUntilExit()
let json = pipe.fileHandleForReading.readDataToEndOfFile()

let dest = root.appendingPathComponent("Tests/heuristic-vectors.json")
try json.write(to: dest)
FileHandle.standardError.write("wrote \(dest.path) (\(hosts.count) vectors)\n".data(using: .utf8)!)
