// BrowseGuard — in-page detection.
//
// The content blocker stops requests to known hosts, and the service worker
// stops navigations to known sites. This script covers the gap between them:
// a miner or skimmer that is injected into an otherwise ordinary page after it
// loads, from a host nobody has listed yet.
//
// Runs at document_start in every frame. Kept small and synchronous where it
// matters, because anything slow here is felt on every page the user opens.

(() => {
  "use strict";

  const host = location.hostname.replace(/^www\./, "").toLowerCase();
  let reported = false;

  function report(category, detail) {
    if (reported) return;
    reported = true;
    browser.runtime.sendMessage({
      action: "reportInPage",
      host,
      category,
      detail,
    });
  }

  // --- Cryptojacking -------------------------------------------------------
  // Miner kits are distributed as a handful of well-known library names. They
  // also all share one shape: a WASM module driving N workers, where N tracks
  // the core count. Either is enough to act on.

  const MINER_GLOBALS = [
    "CoinHive", "CryptoLoot", "CRLT", "JSECoin", "deepMiner",
    "Client", "WMP", "CoinImp", "Anonymous", "WebMinerPool",
  ];

  const MINER_SCRIPT_PATTERN =
    /(coinhive|coin-hive|cryptoloot|crypto-loot|webminepool|coinimp|deepminer|jsecoin|minero\.cc|monerise)/i;

  function scanForMinerGlobals() {
    for (const name of MINER_GLOBALS) {
      const candidate = window[name];
      if (typeof candidate !== "function") continue;
      // `Client` and `Anonymous` are too generic on their own; require the
      // miner-specific surface before calling it.
      if (candidate.prototype && typeof candidate.prototype.start === "function"
          && typeof candidate.prototype.setThrottle === "function") {
        report("cryptojacking", `miner global ${name}`);
        return;
      }
      if (!["Client", "Anonymous"].includes(name)) {
        report("cryptojacking", `miner global ${name}`);
        return;
      }
    }
  }

  // Worker flooding: a page that spins up one worker per CPU core within a
  // second of load is mining, not doing layout work.
  const cores = navigator.hardwareConcurrency || 4;
  let workerCount = 0;
  const NativeWorker = window.Worker;

  if (typeof NativeWorker === "function") {
    window.Worker = function GuardedWorker(scriptURL, options) {
      workerCount += 1;
      const source = String(scriptURL);
      if (MINER_SCRIPT_PATTERN.test(source)) {
        report("cryptojacking", `miner worker ${source}`);
        // Hand back a worker pointed at nothing rather than throwing, so the
        // page's own error handling does not spiral.
        return new NativeWorker(URL.createObjectURL(new Blob([""], { type: "text/javascript" })), options);
      }
      if (workerCount >= Math.max(cores, 4)) {
        report("cryptojacking", `${workerCount} workers spawned`);
      }
      return new NativeWorker(scriptURL, options);
    };
    window.Worker.prototype = NativeWorker.prototype;
  }

  // --- Injected scripts ----------------------------------------------------
  // Watch for <script> elements added after load whose source matches a known
  // miner or skimmer kit.

  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeName !== "SCRIPT") continue;
        const src = node.src || "";
        if (src && MINER_SCRIPT_PATTERN.test(src)) {
          node.type = "text/blocked-by-browseguard";
          node.remove();
          report("cryptojacking", `injected script ${src}`);
        }
      }
    }
  });

  observer.observe(document.documentElement, { childList: true, subtree: true });

  document.addEventListener("DOMContentLoaded", () => {
    scanForMinerGlobals();
    // Stop watching once the page has settled; long-lived observers on busy
    // single-page apps are a real battery cost.
    setTimeout(() => observer.disconnect(), 10_000);
  });
})();
