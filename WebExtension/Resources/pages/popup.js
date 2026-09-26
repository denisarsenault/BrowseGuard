// Toolbar popup: what BrowseGuard thinks of the site in front of you.

const dot = document.getElementById("dot");
const state = document.getElementById("state");
const substate = document.getElementById("substate");
const hostEl = document.getElementById("host");
const verdictEl = document.getElementById("verdict");
const allowButton = document.getElementById("allow");

function render({ settings, host, verdict }) {
  if (!settings || !settings.ok) {
    dot.className = "dot off";
    state.textContent = "Not connected";
    substate.textContent = "Open the BrowseGuard app once to finish setup.";
    return;
  }

  if (!settings.enabled) {
    dot.className = "dot off";
    state.textContent = "Protection is off";
    substate.textContent = "Turn it back on in the BrowseGuard app.";
    return;
  }

  hostEl.textContent = host || "";

  if (!verdict || !verdict.ok) {
    dot.className = "dot";
    state.textContent = "Protected";
    substate.textContent = "Nothing to report on this page.";
    return;
  }

  switch (verdict.decision) {
    case "block":
    case "warn":
      dot.className = "dot blocked";
      state.textContent = verdict.headline;
      substate.textContent = verdict.categoryTitle;
      verdictEl.textContent = verdict.explanation;
      break;
    case "allowlisted":
      dot.className = "dot off";
      state.textContent = "Allowed by you";
      substate.textContent = "BrowseGuard is standing down on this site.";
      break;
    default:
      dot.className = "dot";
      state.textContent = "Protected";
      substate.textContent = "No threats detected.";
      allowButton.hidden = true;
      return;
  }

  if (verdict.decision === "block" || verdict.decision === "warn") {
    allowButton.hidden = false;
    allowButton.addEventListener("click", async () => {
      allowButton.disabled = true;
      await browser.runtime.sendMessage({
        action: "bypass",
        host: verdict.host,
        category: verdict.category,
      });
      allowButton.textContent = "Allowed";
    });
  }
}

browser.runtime
  .sendMessage({ action: "status" })
  .then(render)
  .catch(() => {
    dot.className = "dot off";
    state.textContent = "Unavailable";
    substate.textContent = "BrowseGuard could not reach its background service.";
  });
