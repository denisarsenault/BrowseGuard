// A port of Swift's `HeuristicScanner`, for browsers that cannot reach it.
//
// Safari does not use this file — it asks the native scanner, which is the one
// source of truth there. Chrome has no native side, so the logic has to exist
// twice. Two implementations of the same rules *will* drift unless something
// stops them, so both are checked against the same vectors in
// `Tests/heuristic-vectors.json`: the Swift suite reads it, and
// `scripts/test_heuristics.mjs` reads it, and a disagreement fails the build.
//
// Keep this file and `Shared/Core/HeuristicScanner.swift` edited together.

export const PROTECTED_BRANDS = [
  "apple", "icloud", "paypal", "amazon", "microsoft", "office365",
  "google", "gmail", "facebook", "instagram", "netflix", "chase",
  "wellsfargo", "bankofamerica", "coinbase", "binance", "dropbox",
  "linkedin", "whatsapp", "steamcommunity", "roblox", "usps", "fedex",
];

export const HIGH_RISK_TLDS = new Set([
  "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click", "link",
  "zip", "mov", "country", "kim", "loan", "download", "review", "rest",
]);

const SCAM_TOKENS = [
  "verify", "secure", "account", "update", "signin", "login", "wallet",
  "recovery", "support", "billing", "unlock", "confirm", "suspended",
];

export const SENSITIVITY = {
  relaxed: { block: 0.9, warn: 0.6 },
  balanced: { block: 0.75, warn: 0.45 },
  strict: { block: 0.5, warn: 0.3 },
};

/** Optimal string alignment distance — counts a transposition as one edit. */
export function damerauLevenshtein(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  let beforePrevious = [];
  let previous = Array.from({ length: b.length + 1 }, (_, i) => i);

  for (let i = 1; i <= a.length; i++) {
    const current = new Array(b.length + 1).fill(0);
    current[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      current[j] = Math.min(
        previous[j] + 1,          // deletion
        current[j - 1] + 1,       // insertion
        previous[j - 1] + cost,   // substitution
      );
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        current[j] = Math.min(current[j], beforePrevious[j - 2] + cost);
      }
    }
    beforePrevious = previous;
    previous = current;
  }
  return previous[b.length];
}

export function shannonEntropy(value) {
  if (!value.length) return 0;
  const counts = new Map();
  for (const ch of value) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Short brands need a tighter radius or every four-letter word matches. */
function allowedDistance(brand) {
  return brand.length < 6 ? 1 : 2;
}

function isIPLiteral(host) {
  if (host.startsWith("[")) return true;
  const parts = host.split(".");
  if (parts.length !== 4) return host.includes(":");
  return parts.every((p) => /^\d+$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}


/**
 * RFC 3492 punycode decoding of a single label (without the `xn--`).
 * Mirrors `URLNormalizer.punycodeDecode` in Swift.
 */
export function punycodeDecode(input) {
  const base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700;
  const initialBias = 72, initialN = 128;

  const adapt = (delta, numPoints, firstTime) => {
    delta = firstTime ? Math.floor(delta / damp) : Math.floor(delta / 2);
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((base - tmin) * tmax) / 2) {
      delta = Math.floor(delta / (base - tmin));
      k += base;
    }
    return k + Math.floor(((base - tmin + 1) * delta) / (delta + skew));
  };

  const digit = (ch) => {
    const c = ch.charCodeAt(0);
    if (c >= 0x41 && c <= 0x5a) return c - 0x41;        // A-Z
    if (c >= 0x61 && c <= 0x7a) return c - 0x61;        // a-z
    if (c >= 0x30 && c <= 0x39) return c - 0x30 + 26;   // 0-9
    return null;
  };

  const output = [];
  let encoded = input;

  const delimiter = input.lastIndexOf("-");
  if (delimiter >= 0) {
    for (const ch of input.slice(0, delimiter)) {
      if (ch.charCodeAt(0) > 0x7f) return null;
      output.push(ch.codePointAt(0));
    }
    encoded = input.slice(delimiter + 1);
  }

  let n = initialN, i = 0, bias = initialBias, pos = 0;
  while (pos < encoded.length) {
    const oldI = i;
    let weight = 1, k = base;
    for (;;) {
      if (pos >= encoded.length) return null;
      const d = digit(encoded[pos++]);
      if (d === null) return null;
      i += d * weight;
      if (!Number.isSafeInteger(i)) return null;
      const t = k <= bias ? tmin : k >= bias + tmax ? tmax : k - bias;
      if (d < t) break;
      weight *= base - t;
      k += base;
    }
    bias = adapt(i - oldI, output.length + 1, oldI === 0);
    n += Math.floor(i / (output.length + 1));
    i %= output.length + 1;
    if (n > 0x10ffff) return null;
    output.splice(i, 0, n);
    i++;
  }

  return output.length ? String.fromCodePoint(...output) : null;
}

/** Decodes every `xn--` label in a host. Null when none decode. */
export function decodeIDN(host) {
  if (!host.includes("xn--")) return null;
  let changed = false;
  const labels = host.split(".").map((label) => {
    if (!label.toLowerCase().startsWith("xn--")) return label;
    const decoded = punycodeDecode(label.slice(4));
    if (decoded === null) return label;
    changed = true;
    return decoded;
  });
  return changed ? labels.join(".") : null;
}


/**
 * Non-Latin characters that render like an ASCII letter, mapped to the letter
 * they imitate. Mirrors `URLNormalizer.confusables` in Swift.
 *
 * Deliberately small: not a general UTS #39 table, just the Cyrillic and Greek
 * letters that actually appear in brand-impersonation domains.
 */
const CONFUSABLES = new Map(Object.entries({
  "\u0430": "a", "\u0432": "b", "\u0441": "c", "\u0501": "d", "\u0435": "e",
  "\u0455": "s", "\u04bb": "h", "\u0456": "i", "\u04cf": "l", "\u0458": "j",
  "\u043a": "k", "\u043c": "m", "\u043d": "h", "\u043e": "o", "\u0440": "p",
  "\u051b": "q", "\u0433": "r", "\u0442": "t", "\u0475": "v", "\u0445": "x",
  "\u0443": "y",
  "\u03b1": "a", "\u03b2": "b", "\u03b5": "e", "\u03b9": "i", "\u03ba": "k",
  "\u03bd": "v", "\u03bf": "o", "\u03c1": "p", "\u03c3": "o", "\u03c4": "t",
  "\u03c5": "u", "\u03c7": "x", "\u03b3": "y", "\u03bc": "u",
}));

/**
 * Rewrites confusable characters to the ASCII letters they imitate, so a
 * whole-script lookalike can be compared against a brand name. Null when
 * nothing was confusable.
 */
export function confusableSkeleton(label) {
  let changed = false;
  let out = "";
  for (const ch of label) {
    const ascii = CONFUSABLES.get(ch.toLowerCase());
    if (ascii) { changed = true; out += ascii; } else { out += ch; }
  }
  return changed ? out : null;
}

/**
 * True when a decoded host mixes ASCII letters with non-ASCII letters in the
 * same label — the shape of a homograph attack (`аpple.com`, Cyrillic `а`).
 */
export function mixesScripts(decodedHost) {
  const isLetter = (ch) => /\p{L}/u.test(ch);
  for (const label of decodedHost.split(".")) {
    let ascii = false, nonAscii = false;
    for (const ch of label) {
      if (!isLetter(ch)) continue;
      if (ch.charCodeAt(0) < 0x80) ascii = true;
      else nonAscii = true;
    }
    if (ascii && nonAscii) return true;
  }
  return false;
}

/** Every heuristic that fired, matching the Swift scanner's rule names. */
export function signalsFor(host) {
  if (isIPLiteral(host)) {
    return [{
      rule: "ip-literal",
      explanation: "The address is a raw IP with no domain name.",
      weight: 0.35,
    }];
  }

  const signals = [];
  const labels = host.split(".");
  if (labels.length < 2) return signals;

  const tld = labels[labels.length - 1];
  const registrable = labels[labels.length - 2];

  if (HIGH_RISK_TLDS.has(tld)) {
    signals.push({
      rule: "high-risk-tld",
      explanation: `\`.${tld}\` domains are abused far more often than they are used legitimately.`,
      weight: 0.3,
    });
  }

  // Only a *mixed-script* label is flagged. A domain written entirely in one
  // non-Latin script is an ordinary international site, and treating every IDN
  // as an attack would make the extension useless outside the Latin web.
  const decoded = decodeIDN(host);
  if (decoded) {
    const decodedLabels = decoded.split(".");
    const decodedRegistrable = decodedLabels.length >= 2
      ? decodedLabels[decodedLabels.length - 2]
      : (decodedLabels[0] ?? "");

    if (mixesScripts(decoded)) {
      signals.push({
        rule: "idn-homograph",
        explanation: `The name mixes alphabets so it renders like "${decoded}".`,
        weight: 0.45,
      });
    } else {
      const skeleton = confusableSkeleton(decodedRegistrable);
      const brand = skeleton
        ? PROTECTED_BRANDS.find((b) => skeleton === b || damerauLevenshtein(skeleton, b) <= 1)
        : undefined;
      if (brand) {
        // Whole-script lookalike: nothing is "mixed", but rendered it is
        // indistinguishable from a brand. The аррӏе.com case.
        signals.push({
          rule: "idn-homograph",
          explanation: `"${decoded}" is written in another alphabet to look like "${brand}".`,
          weight: 0.6,
        });
      }
    }
  }

  if (labels.length >= 5) {
    signals.push({
      rule: "deep-subdomain",
      explanation: `${labels.length} levels of subdomain — a common way to hide the real domain.`,
      weight: 0.2,
    });
  }

  // Brand in a subdomain but not in the registrable domain:
  // `apple.com.secure-login.ru` is the canonical phishing shape.
  const prefix = labels.slice(0, -2).join(".");
  const brandInPrefix = PROTECTED_BRANDS.find((b) => prefix.includes(b));
  if (brandInPrefix && !registrable.includes(brandInPrefix)) {
    signals.push({
      rule: "brand-in-subdomain",
      explanation: `"${brandInPrefix}" appears in the subdomain but the real domain is "${registrable}.${tld}".`,
      weight: 0.55,
    });
  }

  const core = registrable.replaceAll("-", "");
  for (const brand of PROTECTED_BRANDS) {
    if (core === brand) continue;
    const distance = damerauLevenshtein(core, brand);
    if (distance === 0 || distance > allowedDistance(brand)) continue;
    signals.push({
      rule: "typosquat",
      explanation: `"${registrable}" is ${distance} character${distance === 1 ? "" : "s"} away from "${brand}".`,
      weight: distance === 1 ? 0.6 : 0.4,
    });
    break;
  }

  const digits = (registrable.match(/\d/g) ?? []).length;
  const hyphens = (registrable.match(/-/g) ?? []).length;
  if (registrable.length >= 12 && hyphens >= 3) {
    signals.push({
      rule: "hyphen-stuffing",
      explanation: `The domain is padded with ${hyphens} hyphens to look like a phrase.`,
      weight: 0.25,
    });
  }
  if (digits >= 4 && digits / Math.max(registrable.length, 1) > 0.3) {
    signals.push({
      rule: "digit-stuffing",
      explanation: "The domain is mostly digits, typical of auto-generated hosts.",
      weight: 0.25,
    });
  }

  if (registrable.length >= 12 && shannonEntropy(registrable) > 3.6) {
    signals.push({
      rule: "high-entropy",
      explanation: "The name looks machine-generated rather than chosen.",
      weight: 0.3,
    });
  }

  for (const token of SCAM_TOKENS) {
    if (registrable.includes(token)) {
      signals.push({
        rule: "scam-token",
        explanation: `Contains "${token}", a word phishing kits lean on.`,
        weight: 0.2,
      });
      break;
    }
  }

  return signals;
}

/** Clamped sum of the signals that fired. */
export function riskFor(host) {
  return Math.min(1, signalsFor(host).reduce((total, s) => total + s.weight, 0));
}
