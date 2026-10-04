// The interstitial.
//
// Everything on this page comes from query parameters the service worker set,
// and every value is written with `textContent` — never `innerHTML`. The host
// name is attacker-controlled by definition, so treating it as markup would
// turn the block page into the vulnerability.

const params = new URLSearchParams(location.search);

// A declarative redirect can only name a static page, so when the network
// layer sent us here there is nothing in the query string to read. Ask the
// service worker what it blocked in this tab instead.
if (params.get("via") === "net" || !params.get("host")) {
  browser.runtime.sendMessage({ action: "context" }).then((ctx) => {
    if (!ctx?.ok) return;
    const v = ctx.verdict ?? {};
    const merged = new URLSearchParams({
      host: v.host ?? "", decision: v.decision ?? "block",
      category: v.category ?? "", categoryTitle: v.categoryTitle ?? "",
      headline: v.headline ?? "Blocked by BrowseGuard",
      explanation: v.explanation ?? "", source: v.source ?? "",
      severity: String(v.severity ?? 0), url: ctx.url ?? "",
    });
    location.replace(`${location.pathname}?${merged.toString()}`);
  }).catch(() => {});
}

const host = params.get("host") || "";
const decision = params.get("decision") || "block";
const category = params.get("category") || "";
const categoryTitle = params.get("categoryTitle") || "Threat";
const headline = params.get("headline") || "Blocked by BrowseGuard";
const explanation = params.get("explanation") || "";
const source = params.get("source") || "BrowseGuard";
const severity = Number(params.get("severity") || 0);
const originalURL = params.get("url") || "";

document.getElementById("headline").textContent = headline;
document.getElementById("host").textContent = host;
document.getElementById("explanation").textContent = explanation;
document.getElementById("category").textContent = categoryTitle;
document.getElementById("source").textContent = source;

document.body.dataset.severity = String(severity);
document.body.dataset.decision = decision;

// A "warn" is a heuristic guess, not a known-bad listing. Say so plainly rather
// than overclaiming — the user is the one who has to judge the borderline case.
if (decision === "warn") {
  document.getElementById("fineprint").textContent =
    "BrowseGuard hasn't seen this site before and it looks suspicious. If you're sure it's genuine, you can continue.";
}

document.getElementById("back").addEventListener("click", async () => {
  if (history.length > 1) {
    history.back();
    return;
  }
  await browser.runtime.sendMessage({ action: "goBack" });
});

document.getElementById("continue").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  button.textContent = "Allowing…";
  await browser.runtime.sendMessage({
    action: "bypass",
    host,
    category,
    url: originalURL,
  });
});
