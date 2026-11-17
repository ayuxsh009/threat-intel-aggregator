// Background service worker: talks to the API, keeps the toolbar badge up to date.
importScripts("common.js");

const READY_TTL_MS = 10 * 60 * 1000;   // reuse a ready answer for 10 minutes
const inflight = new Map();             // host -> Promise

async function cacheGet(host) {
  const key = "r:" + host;
  const data = (await chrome.storage.session.get(key))[key];
  if (data && Date.now() - data.at < READY_TTL_MS) return data.response;
  return null;
}

async function cacheSet(host, response) {
  await chrome.storage.session.set({ ["r:" + host]: { at: Date.now(), response } });
}

async function cacheDrop(host) {
  await chrome.storage.session.remove("r:" + host);
}

async function api(path, { method = "GET", body } = {}) {
  const s = await tiSettings();
  if (!s.token) return { status: "setup", reason: "Add the API token in the extension settings." };
  let resp;
  try {
    resp = await fetch(s.apiUrl.replace(/\/$/, "") + path, {
      method,
      headers: { "X-TI-Token": s.token, "Content-Type": "application/json" },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    return { status: "offline", reason: `Can't reach ${s.apiUrl}. Start it with: python -m api` };
  }
  if (resp.status === 401) return { status: "setup", reason: "The API token was rejected. Copy it again." };
  if (!resp.ok) return { status: "offline", reason: `Server answered HTTP ${resp.status}.` };
  return resp.json();
}

async function lookup(url, { force = false } = {}) {
  const host = tiHostOf(url);
  if (!host) return { status: "skipped", reason: "Browser pages are not checked." };
  const s = await tiSettings();
  if (tiLocalHost(host)) return { status: "skipped", host, reason: "Local or private address." };
  if (tiMatches(host, s.skipList)) return { status: "skipped", host, reason: "On your skip list." };

  if (!force) {
    const cached = await cacheGet(host);
    if (cached) return cached;
    if (inflight.has(host)) return inflight.get(host);
  }
  const p = (async () => {
    const r = await api(`/api/lookup?target=${encodeURIComponent(host)}${force ? "&force=true" : ""}`);
    if (r.status === "ready") await cacheSet(host, r);
    else await cacheDrop(host);
    return r;
  })();
  inflight.set(host, p);
  try {
    return await p;
  } finally {
    inflight.delete(host);
  }
}

function badgeFor(r) {
  switch (r.status) {
    case "ready": {
      const res = r.result;
      return { text: tiScoreText(res), color: TI_COLORS[res.risk] || TI_COLORS.Unknown, title: `${res.ioc}: ${tiLabel(res)} · score ${res.score}/100` };
    }
    case "pending":
      if (r.stale) return { text: "…", color: TI_COLORS[r.stale.risk] || TI_COLORS.Unknown, title: `${r.host}: refreshing (last: ${r.stale.risk})` };
      return { text: "…", color: "#30363d", title: `${r.host}: checking (queue position ${r.position})` };
    case "skipped":
      return { text: "", color: "#30363d", title: `Threat Intel: ${r.reason}` };
    case "setup":
      return { text: "!", color: "#d29922", title: `Threat Intel: ${r.reason}` };
    default:
      return { text: "×", color: "#6e7681", title: `Threat Intel: ${r.reason || r.error || "unavailable"}` };
  }
}

async function setBadge(tabId, r) {
  const b = badgeFor(r);
  try {
    await chrome.action.setBadgeText({ tabId, text: b.text });
    await chrome.action.setBadgeBackgroundColor({ tabId, color: b.color });
    if (chrome.action.setBadgeTextColor) await chrome.action.setBadgeTextColor({ tabId, color: "#ffffff" });
    await chrome.action.setTitle({ tabId, title: b.title });
  } catch (e) {
    // the tab was closed
  }
}

async function refreshTab(tabId, url, opts) {
  const r = await lookup(url, opts);
  await setBadge(tabId, r);
  return r;
}

// Badge for pages where the content script can't run, and on every navigation.
chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === "complete" && tab.url) refreshTab(tabId, tab.url);
});
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId);
  if (tab.url) refreshTab(tabId, tab.url);
});

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    const tabId = msg.tabId ?? sender.tab?.id;
    if (msg.type === "lookup") {
      const r = await refreshTab(tabId, msg.url, { force: !!msg.force });
      sendResponse({ response: r, settings: await tiSettings() });
    } else if (msg.type === "verdict") {
      const host = tiHostOf(msg.url);
      const r = await api("/api/verdict", { method: "POST", body: { target: host, verdict: msg.verdict, note: msg.note || "" } });
      if (r.status === "ready") await cacheSet(host, r); else await cacheDrop(host);
      if (tabId != null) await setBadge(tabId, r);
      sendResponse({ response: r });
    } else if (msg.type === "health") {
      const s = await tiSettings();
      try {
        const h = await (await fetch(s.apiUrl.replace(/\/$/, "") + "/api/health")).json();
        const auth = await api("/api/auth-check");
        sendResponse({ health: h, auth: auth.ok === true, authReason: auth.reason });
      } catch (e) {
        sendResponse({ error: `Can't reach ${s.apiUrl}` });
      }
    } else if (msg.type === "muteCard") {
      const s = await tiSettings();
      const host = tiHostOf(msg.url);
      if (host && !s.mutedCards.includes(host)) await chrome.storage.sync.set({ mutedCards: [...s.mutedCards, host] });
      sendResponse({ ok: true });
    } else if (msg.type === "openOptions") {
      chrome.runtime.openOptionsPage();
      sendResponse({ ok: true });
    }
  })();
  return true; // keep the channel open for the async reply
});

chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === "install") chrome.runtime.openOptionsPage();
});
