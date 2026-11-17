const $ = (id) => document.getElementById(id);
const lines = (text) => text.split(/\r?\n/).map((s) => s.trim().toLowerCase()).filter(Boolean);

async function load() {
  const s = await tiSettings();
  $("apiUrl").value = s.apiUrl;
  $("token").value = s.token;
  $("appUrl").value = s.appUrl;
  $("skipList").value = s.skipList.join("\n");
  $("mutedCards").value = s.mutedCards.join("\n");
  const radio = document.querySelector(`input[name=cardMode][value=${s.cardMode}]`);
  if (radio) radio.checked = true;
}

function status(text, ok) {
  $("status").textContent = text;
  $("status").className = ok === undefined ? "muted" : ok ? "ok" : "bad";
}

async function ensurePermission(apiUrl) {
  // 127.0.0.1 and localhost are granted at install; any other server needs explicit permission.
  const u = new URL(apiUrl);
  if (u.hostname === "127.0.0.1" || u.hostname === "localhost") return true;
  return chrome.permissions.request({ origins: [`${u.protocol}//${u.hostname}/*`] });
}

$("save").addEventListener("click", async () => {
  let apiUrl;
  try {
    apiUrl = new URL($("apiUrl").value.trim() || TI_DEFAULTS.apiUrl).origin;
  } catch (e) {
    return status("The API address isn't a valid URL.", false);
  }
  if (!(await ensurePermission(apiUrl))) return status("Permission to reach that server was not granted.", false);
  await chrome.storage.sync.set({
    apiUrl,
    token: $("token").value.trim(),
    appUrl: $("appUrl").value.trim() || TI_DEFAULTS.appUrl,
    cardMode: (document.querySelector("input[name=cardMode]:checked") || {}).value || "all",
    skipList: lines($("skipList").value),
    mutedCards: lines($("mutedCards").value),
  });
  await chrome.storage.session.clear();  // drop cached answers made with old settings
  status("Saved. Testing…");
  chrome.runtime.sendMessage({ type: "health" }, (r) => {
    if (!r || r.error) return status(`Saved, but ${r ? r.error : "no answer"}. Is "python -m api" running?`, false);
    if (!r.auth) return status(`Server found (v${r.health.version}), but the token was rejected.`, false);
    const on = Object.entries(r.health.sources).filter(([, v]) => v).map(([k]) => k).join(", ");
    status(`Connected to ${r.health.app} v${r.health.version}. Sources: ${on}.`, true);
  });
});

load();
