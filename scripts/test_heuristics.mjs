// The JavaScript half of the cross-implementation check.
//
// Runs WebExtension/Shared/heuristics.js against the vectors generated from the
// Swift scanner. If the two implementations disagree about which rules fire or
// what a host scores, this fails — which is the point: Chrome has no native
// side, so the logic exists twice and would otherwise drift silently.
//
//   node scripts/test_heuristics.mjs
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { signalsFor, riskFor, damerauLevenshtein, shannonEntropy } from "../WebExtension/Shared/heuristics.js";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const vectors = JSON.parse(readFileSync(join(root, "Tests/heuristic-vectors.json"), "utf8"));

let failures = 0;
const fail = (msg) => { console.error(`  ✗ ${msg}`); failures++; };

for (const v of vectors) {
  const rules = signalsFor(v.host).map((s) => s.rule).sort();
  const expected = [...v.rules].sort();
  if (JSON.stringify(rules) !== JSON.stringify(expected)) {
    fail(`${v.host}: JS fired [${rules}], Swift fired [${expected}]`);
  }
  const risk = Math.round(riskFor(v.host) * 10_000) / 10_000;
  if (Math.abs(risk - v.risk) > 0.0001) {
    fail(`${v.host}: JS risk ${risk}, Swift risk ${v.risk}`);
  }
}

// A couple of direct checks on the primitives, so a mismatch points at the
// cause rather than just at a host that scored differently.
if (damerauLevenshtein("gogole", "google") !== 1) fail("transposition should cost 1 edit");
if (damerauLevenshtein("apple", "apple") !== 0) fail("identical strings should cost 0");
if (!(shannonEntropy("aaaaaaaa") < 1)) fail("repeated characters should score low entropy");
if (!(shannonEntropy("x7q2mzbv9kdf") > 3)) fail("mixed characters should score high entropy");

if (failures) {
  console.error(`\n${failures} mismatch(es) between heuristics.js and HeuristicScanner.swift`);
  console.error("Edit both, then regenerate: swift scripts/make_heuristic_vectors.swift");
  process.exit(1);
}
console.log(`✓ heuristics.js matches HeuristicScanner.swift across ${vectors.length} vectors`);
