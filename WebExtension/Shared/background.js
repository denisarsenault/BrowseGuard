// BrowseGuard — service worker orchestration, shared by Safari and Chrome.
//
// This file decides *what happens* to a navigation. It never decides whether a
// host is bad: that comes from `./engine.js`, which is a different file in each
// browser's bundle — Safari asks its native handler, Chrome consults lists it
// carries itself. Keeping the orchestration in one place is what stops the two
// browsers' behaviour from quietly drifting apart.

import "./compat.js";
import {
  evaluateHost,
  getSettings,
  bypassHost,
  blockHost,
  unblockHost,
  reportInPage,
  prepare,
} from "./engine.js";

// Verdicts are stable for a host over a short window, and a page can easily
// kick off a dozen navigations. Cache briefly so we resolve once per host
// rather than once per redirect hop.
const VERDICT_TTL_MS = 30_000;
// Hard cap as well as a TTL. The TTL alone is checked lazily, on re-query, so
// a host visited once and never again would sit in the map for the lifetime of
// the service worker — an unbounded leak across a long browsing session.
const VERDICT_CACHE_MAX = 500;
const verdictCache = new Map();

// The URL the user was trying to reach, per tab, so "Continue anyway" knows
// where to send them back to.
const pendingNavigation = new Map();

function rememberVerdict(host, verdict) {
  if (verdictCache.size >= VERDICT_CACHE_MAX) {
    const now = Date.now();
    for (const [key, entry] of verdictCache) {
      if (now - entry.at > VERDICT_TTL_MS) verdictCache.delete(key);
    }
    // Still full of live entries: drop the oldest. Map preserves insertion
    // order, so the first key is the least recently added.
    while (verdictCache.size >= VERDICT_CACHE_MAX) {
      const oldest = verdictCache.keys().next();
      if (oldest.done) break;
      verdictCache.delete(oldest.value);
    }
  }
  verdictCache.set(host, { verdict, at: Date.now() });
}

function cachedVerdict(host) {
  const entry = verdictCache.get(host);
  if (!entry) return null;
  if (Date.now() - entry.at > VERDICT_TTL_MS) {
    verdictCache.delete(host);
    return null;
  }
  return entry.verdict;
}

async function evaluate(host) {
  const cached = cachedVerdict(host);
  if (cached) return cached;

  const verdict = await evaluateHost(host);
  if (verdict && verdict.ok) rememberVerdict(host, verdict);
  return verdict;
}

export function hostOf(url) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return parsed.hostname.replace(/^www\./, "").toLowerCase();
  } catch {
    return null;
  }
}

function blockPageURL(verdict, originalURL) {
  const page = browser.runtime.getURL("pages/blocked.html");
  const params = new URLSearchParams({
    host: verdict.host,
    decision: verdict.decision,
    category: verdict.category || "",
    categoryTitle: verdict.categoryTitle || "",
    headline: verdict.headline || "Blocked",
    explanation: verdict.explanation || "",
    source: verdict.source || "",
    severity: String(verdict.severity ?? 0),
    url: originalURL,
  });
  return `${page}?${params.toString()}`;
}

// The navigation hook. `onBeforeNavigate` fires before the request goes out,
// which is what lets us stop a malware host from ever being contacted.
browser.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // Top-level documents only.

  const host = hostOf(details.url);
  if (!host) return;

  const verdict = await evaluate(host);
  if (!verdict || !verdict.ok) return;
  if (verdict.decision !== "block" && verdict.decision !== "warn") return;

  if (!verdict.showInterstitial) {
    // Silent mode: stop the load without an interstitial. Still logged.
    browser.tabs.update(details.tabId, { url: "about:blank" });
    return;
  }

  pendingNavigation.set(details.tabId, details.url);
  browser.tabs.update(details.tabId, { url: blockPageURL(verdict, details.url) });
});

browser.tabs.onRemoved.addListener((tabId) => {
  pendingNavigation.delete(tabId);
});

// Messages from the block page, the popup, and the content script.
browser.runtime.onMessage.addListener(async (message, sender) => {
  switch (message?.action) {
    case "bypass": {
      const result = await bypassHost(message.host, message.category);
      verdictCache.delete(message.host);
      const tabId = sender?.tab?.id;
      const target = message.url || (tabId != null ? pendingNavigation.get(tabId) : null);
      if (tabId != null && target) {
        pendingNavigation.delete(tabId);
        browser.tabs.update(tabId, { url: target });
      }
      return result || { ok: false };
    }

    case "block": {
      const result = await blockHost(message.host);
      // The verdict for this host just changed; do not serve the old one.
      verdictCache.delete(message.host);
      return result || { ok: false };
    }

    case "unblock": {
      const result = await unblockHost(message.host);
      verdictCache.delete(message.host);
      return result || { ok: false };
    }

    case "goBack": {
      const tabId = sender?.tab?.id;
      if (tabId != null) browser.tabs.update(tabId, { url: "about:blank" });
      return { ok: true };
    }

    case "reportInPage": {
      // The content script found something the network rules missed, most
      // often a miner injected after load.
      verdictCache.delete(message.host);
      return await reportInPage(message.host, message.category, "In-page detection");
    }

    case "status": {
      const settings = await getSettings();
      const tabs = await browser.tabs.query({ active: true, currentWindow: true });
      const host = tabs[0] ? hostOf(tabs[0].url) : null;
      const verdict = host ? await evaluate(host) : null;
      return { settings, host, verdict };
    }

    default:
      return { ok: false, error: "unknown action" };
  }
});

// Chrome needs its lists loaded before the first navigation; on Safari this is
// a no-op because the native side already has them.
prepare().catch((error) => console.warn("BrowseGuard: prepare failed", error));
