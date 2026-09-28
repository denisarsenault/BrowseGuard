// The interstitial.
//
// Everything on this page comes from query parameters the service worker set,
// and every value is written with `textContent` — never `innerHTML`. The host
// name is attacker-controlled by definition, so treating it as markup would
// turn the block page into the vulnerability.

const params = new URLSearchParams(location.search);

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
