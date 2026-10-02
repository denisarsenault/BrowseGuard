// Chrome's verdict source: lists the extension carries itself.
//
// Chrome cannot reach the Swift engine — a sandboxed Mac App Store app is not
// allowed to install a native messaging host manifest into Chrome's support
// directory — so the decision is made here instead. The shape of the answer is
// identical to the Safari adapter's, which is what lets `background.js` be
// shared between them.
//
// The split of work mirrors Safari's:
//
//   - declarativeNetRequest blocks *sub-resource* requests (ads, trackers,
//     miners, and every listed host). That is the fast path; no JS runs.
//   - This file handles *top-level navigations*, so a block can show the
//     interstitial and explain itself rather than dropping the user on
//     Chrome's generic error page.
//
// Its lists therefore only need the hosts, not the rules.

import "./compat.js";
import { signalsFor, SENSITIVITY } from "./heuristics.js";

const CATALOG_URL = "lists/hosts.json";
const SETTINGS_KEY = "settings";
const ALLOWLIST_KEY = "allowlist";
const BLOCKLIST_KEY = "blocklist";

const CATEGORY_TITLES = {
  malware: "Malware",
  scam: "Scams & Phishing",
  advertising: "Ads",
  tracking: "Trackers",
  clickbait: "Clickbait",
  cryptojacking: "Cryptojacking",
  pup: "Unwanted Programs",
  userBlocked: "Blocked by You",
};

const SEVERITY = {
  malware: 3, scam: 2, cryptojacking: 2, pup: 1,
  advertising: 0, tracking: 0, clickbait: 0, userBlocked: 0,
};

const SECURITY_CRITICAL = new Set(["malware", "scam", "cryptojacking"]);

const DEFAULT_SETTINGS = {
  isProtectionEnabled: true,
  enabledCategories: Object.keys(CATEGORY_TITLES),
  heuristicsEnabled: true,
  heuristicSensitivity: "balanced",
  showsInterstitial: true,
  logsActivity: true,
  temporaryBypassDuration: 3600,
};

// Held for the life of the service worker. Chrome restarts workers freely, so
// this is rebuilt on demand rather than assumed to exist.
let catalog = null;

async function loadCatalog() {
  if (catalog) return catalog;
  try {
    const response = await fetch(browser.runtime.getURL(CATALOG_URL));
    const byCategory = await response.json();
    const map = new Map();
    for (const [category, hosts] of Object.entries(byCategory)) {
      for (const host of hosts) {
        // A more severe listing wins when feeds disagree, matching
        // BlocklistCatalog in Swift.
        const existing = map.get(host);
        if (existing && SEVERITY[existing] >= SEVERITY[category]) continue;
        map.set(host, category);
      }
    }
    catalog = map;
  } catch (error) {
    console.warn("BrowseGuard: could not load host lists", error);
    catalog = new Map();
  }
  return catalog;
}

/** Most specific match first, so `ads.example.com` beats `example.com`. */
function matchHost(map, host) {
  const labels = host.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const candidate = labels.slice(i).join(".");
    const category = map.get(candidate);
    if (category) return { host: candidate, category };
  }
  return null;
}

async function stored(key, fallback) {
  try {
    const result = await browser.storage.local.get(key);
    return result?.[key] ?? fallback;
  } catch {
    return fallback;
  }
}

export async function getSettings() {
  const settings = { ...DEFAULT_SETTINGS, ...(await stored(SETTINGS_KEY, {})) };
  return {
    ok: true,
    enabled: settings.isProtectionEnabled,
    showsInterstitial: settings.showsInterstitial,
    logsActivity: settings.logsActivity,
    bypassDuration: settings.temporaryBypassDuration,
  };
}

function activeAllowlistEntry(allowlist, host, now) {
  const labels = host.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const candidate = labels.slice(i).join(".");
    const entry = allowlist[candidate];
    if (!entry) continue;
    if (entry.expiresAt && entry.expiresAt <= now) continue;
    return { host: candidate, ...entry };
  }
  return null;
}

export async function evaluateHost(host) {
  const settings = { ...DEFAULT_SETTINGS, ...(await stored(SETTINGS_KEY, {})) };
  if (!settings.isProtectionEnabled) return { ok: true, decision: "allow", host };

  const now = Date.now();

  // The user's own block list is checked before the allowlist, matching
  // ProtectionEngine: deliberately blocking something you once allowed should
  // take effect without hunting down the old allowlist entry first.
  const blocklist = await stored(BLOCKLIST_KEY, {});
  const blocked = matchHost(new Map(Object.entries(blocklist).map(([h]) => [h, "userBlocked"])), host);
  if (blocked) return verdict(host, "block", "userBlocked", 1, [], "Your block list", settings);

  const allowlist = await stored(ALLOWLIST_KEY, {});
  const allowed = activeAllowlistEntry(allowlist, host, now);
  if (allowed) {
    return { ok: true, decision: "allowlisted", host, source: allowed.expiresAt ? "Temporary bypass" : "Allowlist" };
  }

  const listed = matchHost(await loadCatalog(), host);
  if (listed) {
    if (!settings.enabledCategories.includes(listed.category)) {
      return { ok: true, decision: "allow", host };
    }
    return verdict(host, "block", listed.category, 1, [], "BrowseGuard lists", settings);
  }

  if (!settings.heuristicsEnabled || !settings.enabledCategories.includes("scam")) {
    return { ok: true, decision: "allow", host };
  }

  const signals = signalsFor(host);
  if (!signals.length) return { ok: true, decision: "allow", host };

  const risk = Math.min(1, signals.reduce((t, s) => t + s.weight, 0));
  const thresholds = SENSITIVITY[settings.heuristicSensitivity] ?? SENSITIVITY.balanced;
  if (risk >= thresholds.block) {
    return verdict(host, "block", "scam", risk, signals, "Heuristics", settings);
  }
  if (risk >= thresholds.warn) {
    return verdict(host, "warn", "scam", risk, signals, "Heuristics", settings);
  }
  return { ok: true, decision: "allow", host };
}

function verdict(host, decision, category, confidence, signals, source, settings) {
  const headline = decision === "warn"
    ? "This site looks suspicious"
    : {
        malware: "This site distributes malware",
        scam: "This site is a known scam",
        cryptojacking: "This site mines cryptocurrency",
        pup: "This site pushes unwanted software",
        userBlocked: "You blocked this site",
      }[category] ?? "Blocked by BrowseGuard";

  const explanation = category === "userBlocked"
    ? `${host} is on your own block list. Nothing suggests it is dangerous — you chose to block it.`
    : signals.length
      ? signals.map((s) => s.explanation).join(" ")
      : `${host} is on the ${source} ${(CATEGORY_TITLES[category] ?? "threat").toLowerCase()} list.`;

  if (settings.logsActivity) void appendEvent(host, category, decision);

  return {
    ok: true,
    decision,
    host,
    category,
    categoryTitle: CATEGORY_TITLES[category] ?? "",
    severity: SEVERITY[category] ?? 0,
    confidence,
    headline,
    explanation,
    source,
    signals: signals.map((s) => ({ rule: s.rule, explanation: s.explanation })),
    // Critical blocks always show the interstitial: silently swallowing a
    // malware navigation leaves the user wondering why the page is blank.
    showInterstitial: SECURITY_CRITICAL.has(category) || settings.showsInterstitial,
  };
}

const EVENT_CAP = 5000;

async function appendEvent(host, category, decision) {
  try {
    const { events = [] } = await browser.storage.local.get("events");
    events.push({ host, category, decision, timestamp: new Date().toISOString(), wasBypassed: false });
    if (events.length > EVENT_CAP) events.splice(0, events.length - EVENT_CAP);
    await browser.storage.local.set({ events });
  } catch (error) {
    console.warn("BrowseGuard: could not log event", error);
  }
}

export async function bypassHost(host, category) {
  const settings = { ...DEFAULT_SETTINGS, ...(await stored(SETTINGS_KEY, {})) };
  const allowlist = await stored(ALLOWLIST_KEY, {});
  allowlist[host] = {
    addedAt: Date.now(),
    expiresAt: Date.now() + settings.temporaryBypassDuration * 1000,
    bypassedCategory: category || null,
  };
  await browser.storage.local.set({ [ALLOWLIST_KEY]: allowlist });

  try {
    const { events = [] } = await browser.storage.local.get("events");
    for (let i = events.length - 1; i >= 0; i--) {
      if (events[i].host === host) { events[i].wasBypassed = true; break; }
    }
    await browser.storage.local.set({ events });
  } catch { /* logging is best-effort */ }

  return { ok: true, expiresIn: settings.temporaryBypassDuration };
}

export async function blockHost(host) {
  const blocklist = await stored(BLOCKLIST_KEY, {});
  blocklist[host] = { addedAt: Date.now() };
  // Blocking something previously allowed should just work, rather than
  // silently losing to a stale allowlist entry.
  const allowlist = await stored(ALLOWLIST_KEY, {});
  delete allowlist[host];
  await browser.storage.local.set({ [BLOCKLIST_KEY]: blocklist, [ALLOWLIST_KEY]: allowlist });
  return { ok: true, count: Object.keys(blocklist).length };
}

export async function unblockHost(host) {
  const blocklist = await stored(BLOCKLIST_KEY, {});
  delete blocklist[host];
  await browser.storage.local.set({ [BLOCKLIST_KEY]: blocklist });
  return { ok: true, count: Object.keys(blocklist).length };
}

export async function reportInPage(host, category, source) {
  const settings = { ...DEFAULT_SETTINGS, ...(await stored(SETTINGS_KEY, {})) };
  if (!settings.logsActivity) return { ok: true };
  await appendEvent(host, category, "block");
  return { ok: true, source };
}

/** Warm the host list so the first navigation does not pay for the load. */
export async function prepare() {
  await loadCatalog();
}
