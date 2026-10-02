// Safari's verdict source: the native handler.
//
// Safari can reach Swift, so the blocklists, the heuristics and the user's
// settings stay behind the App Group where a page cannot read or tamper with
// them, and the same `ProtectionEngine` the app's UI shows is the one that
// decides. Chrome has no equivalent, which is why this file has a sibling.

import "./compat.js";

const NATIVE_APP = "application.id"; // Safari routes this to our handler.

async function nativeRequest(message) {
  try {
    return await browser.runtime.sendNativeMessage(NATIVE_APP, message);
  } catch (error) {
    // If the container app was removed or the App Group is unavailable, fail
    // open rather than bricking the user's browsing.
    console.warn("BrowseGuard: native handler unreachable", error);
    return null;
  }
}

export async function evaluateHost(host) {
  return nativeRequest({ action: "evaluate", host });
}

export async function getSettings() {
  return nativeRequest({ action: "settings" });
}

export async function bypassHost(host, category) {
  return nativeRequest({ action: "bypass", host, category });
}

export async function blockHost(host) {
  return nativeRequest({ action: "block", host });
}

export async function unblockHost(host) {
  return nativeRequest({ action: "unblock", host });
}

export async function reportInPage(host, category, source) {
  return nativeRequest({ action: "report", host, category, source });
}

/// Safari keeps its lists natively; nothing to prime at startup.
export async function prepare() {}
