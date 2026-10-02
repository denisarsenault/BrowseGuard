// Toolbar popup: what BrowseGuard thinks of the site in front of you, and the
// two things you can do about it.
//
// Both actions matter on Chrome in particular, because there is no companion
// app there — this popup is the only place a Chrome user can add a block or an
// allowance at all.

const dot = document.getElementById("dot");
const state = document.getElementById("state");
const substate = document.getElementById("substate");
const hostEl = document.getElementById("host");
const verdictEl = document.getElementById("verdict");
const allowButton = document.getElementById("allow");
const blockButton = document.getElementById("block");

let currentHost = null;
let currentVerdict = null;

function show(button, label, visible) {
  button.hidden = !visible;
  button.textContent = label;
  button.disabled = false;
}

async function refresh() {
  const { settings, host, verdict } = await browser.runtime.sendMessage({ action: "status" });
  currentHost = host;
  currentVerdict = verdict;

  if (!settings || !settings.ok) {
    dot.className = "dot off";
    state.textContent = "Not connected";
    substate.textContent = "Open the BrowseGuard app once to finish setup.";
    return;
  }

  if (!settings.enabled) {
    dot.className = "dot off";
    state.textContent = "Protection is off";
    substate.textContent = "Turn it back on in BrowseGuard.";
    return;
  }

  hostEl.textContent = host || "";
  verdictEl.textContent = "";

  if (!host) {
    dot.className = "dot";
    state.textContent = "Protected";
    substate.textContent = "Nothing to check on this page.";
    return;
  }

  const decision = verdict?.ok ? verdict.decision : "allow";

  switch (decision) {
    case "block":
    case "warn":
      dot.className = "dot blocked";
      state.textContent = verdict.headline;
      substate.textContent = verdict.categoryTitle || "";
      verdictEl.textContent = verdict.explanation || "";
      // A site blocked by the user's own list is unblocked here; one blocked
      // by a threat feed is allowed past instead. Different actions, because
      // they undo different things.
      if (verdict.category === "userBlocked") {
        show(blockButton, `Unblock ${host}`, true);
        allowButton.hidden = true;
      } else {
        show(allowButton, "Always allow this site", true);
        show(blockButton, "Block this site", true);
      }
      break;

    case "allowlisted":
      dot.className = "dot off";
      state.textContent = "Allowed by you";
      substate.textContent = "BrowseGuard is standing down on this site.";
      show(blockButton, "Block this site", true);
      allowButton.hidden = true;
      break;

    default:
      dot.className = "dot";
      state.textContent = "Protected";
      substate.textContent = "No threats detected.";
      allowButton.hidden = true;
      // The point people reach for most: a site that is perfectly fine but
      // that they do not want to load. Without this there is nowhere to say so.
      show(blockButton, "Block this site", true);
      break;
  }
}

allowButton.addEventListener("click", async () => {
  if (!currentHost) return;
  allowButton.disabled = true;
  await browser.runtime.sendMessage({
    action: "bypass",
    host: currentVerdict?.host ?? currentHost,
    category: currentVerdict?.category,
  });
  await refresh();
});

blockButton.addEventListener("click", async () => {
  if (!currentHost) return;
  blockButton.disabled = true;
  const unblocking = currentVerdict?.category === "userBlocked";
  await browser.runtime.sendMessage({
    action: unblocking ? "unblock" : "block",
    host: currentHost,
  });
  await refresh();
  // Reload the tab so the change takes effect on what the user is looking at,
  // rather than only on the next navigation.
  const tabs = await browser.tabs.query({ active: true, currentWindow: true });
  if (tabs[0]?.id != null) browser.tabs.reload(tabs[0].id);
});

refresh().catch(() => {
  dot.className = "dot off";
  state.textContent = "Unavailable";
  substate.textContent = "BrowseGuard could not reach its background service.";
});
