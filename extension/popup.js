const main = document.getElementById("main");
let tab, pollTimer, polls = 0;

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k === "style") e.style.cssText = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const c of children) if (c != null && c !== false) e.append(c);
  return e;
}

const stat = (label, value) => el("div", { class: "stat" }, el("span", {}, label), el("span", {}, value == null || value === "" ? "—" : String(value)));

function setMain(...nodes) {
  main.replaceChildren(...nodes);
}

function stateView(title, text, ...extra) {
  setMain(el("div", { class: "state" }, el("b", {}, title), text, ...extra));
}

function since(seconds) {
  if (seconds == null) return "";
  if (seconds < 90) return "just now";
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h ago`;
  return `${Math.round(seconds / 86400)} days ago`;
}

function renderResult(res, { pending = false, cached = false } = {}) {
  const c = TI_COLORS[res.risk] || TI_COLORS.Unknown;
  document.body.style.setProperty("--c", c);
  const nodes = [];
  nodes.push(el("div", { class: "verdict" },
    el("div", { class: "score" }, tiScoreText(res), el("small", {}, res.verdict ? `computed: ${res.score}` : "threat score")),
    el("div", {},
      el("span", { class: "sev" }, tiLabel(res) + (pending ? " · refreshing" : "")),
      el("div", { class: "host mono" }, res.ioc),
      el("div", { class: "muted", style: "font-size:11px;margin-top:2px" }, `${res.type} · checked ${since(res.age_seconds)}${cached ? " (cached)" : ""}`))));
  nodes.push(el("div", { class: "bar" }, el("div", { style: `width:${res.score}%` })));

  if (res.verdict) {
    const v = res.verdict;
    nodes.push(el("div", { class: "override" },
      `Analyst verdict: ${v.verdict === "malicious" ? "confirmed malicious" : "false positive"} by ${v.username || "unknown"}${v.note ? ` · ${v.note}` : ""}`));
  }
  if (res.changes && res.changes.length) {
    nodes.push(el("div", { class: "changes" }, el("b", {}, "Changed since last check"), el("ul", {}, ...res.changes.map((t) => el("li", {}, t)))));
  }

  nodes.push(el("div", { class: "section" }, "Why"));
  nodes.push(el("ul", {}, ...(res.reasons || []).map((t) => el("li", {}, t))));
  if ((res.errors || []).length) nodes.push(el("ul", { style: "color:#d29922" }, ...res.errors.map((t) => el("li", {}, t))));

  if ((res.factors || []).length) {
    nodes.push(el("div", { class: "section" }, "Score breakdown"));
    nodes.push(el("div", {}, ...res.factors.map((f) =>
      el("div", { class: "factor" }, el("b", { class: f.points < 0 ? "neg" : "" }, (f.points > 0 ? "+" : "") + f.points),
        el("span", {}, f.label, el("span", { class: "muted", style: "font-size:11px" }, ` · ${f.source}`))))));
  }

  nodes.push(el("div", { class: "section" }, "Details"));
  const d = [];
  if (res.vt) d.push(stat("VirusTotal", `${res.vt.malicious}/${res.vt.total} engines`));
  if (res.abuse) d.push(stat("AbuseIPDB", `${res.abuse.confidence}% · ${res.abuse.reports} reports`));
  if (res.rdap) d.push(stat("Domain age", res.rdap.age_days != null ? `${res.rdap.age_days} days (since ${res.rdap.registered})` : "unknown"));
  if (res.rdap && res.rdap.registrar) d.push(stat("Registrar", res.rdap.registrar));
  d.push(stat("ThreatFox", res.threatfox ? (res.threatfox.families || []).join(", ") || "listed" : "not listed"));
  d.push(stat("URLhaus", res.urlhaus ? `${res.urlhaus.count} URLs, ${res.urlhaus.online} online` : "not listed"));
  d.push(stat("Seen before here", res.sightings && res.sightings.count ? `${res.sightings.count}× (worst: ${res.sightings.worst_risk || "—"})` : "first time"));
  nodes.push(el("div", {}, ...d));

  const note = el("input", { type: "text", class: "note", placeholder: "Note for the verdict (optional)" });
  const setVerdict = (verdict) => {
    chrome.runtime.sendMessage({ type: "verdict", url: tab.url, tabId: tab.id, verdict, note: note.value }, (reply) => show(reply.response));
  };
  nodes.push(note);
  nodes.push(el("div", { class: "row" },
    el("button", { class: "btn danger", onclick: () => setVerdict("malicious") }, "Mark malicious"),
    el("button", { class: "btn good", onclick: () => setVerdict("benign") }, "False positive"),
    res.verdict ? el("button", { class: "btn", onclick: () => setVerdict(null) }, "Clear verdict") : null));
  nodes.push(el("div", { class: "row" },
    el("button", { class: "btn", onclick: () => ask(true), disabled: pending ? "" : null }, "Re-check now"),
    res.vt && res.vt.link ? el("button", { class: "btn", onclick: () => chrome.tabs.create({ url: res.vt.link }) }, "VirusTotal ↗") : null));
  setMain(...nodes);
}

function show(r) {
  clearTimeout(pollTimer);
  if (!r) return stateView("No answer", "The background worker didn't respond. Try again.");
  switch (r.status) {
    case "ready":
      renderResult(r.result, { cached: r.cached });
      break;
    case "pending":
      if (r.stale) renderResult(r.stale, { pending: true });
      else stateView("Checking…", r.position > 1 ? `Queue position ${r.position}, about ${r.eta_seconds}s.` : `Looking up ${r.host}.`);
      if (polls++ < 60) pollTimer = setTimeout(() => ask(false), 2500);
      break;
    case "skipped":
      stateView("Not checked", r.reason);
      break;
    case "setup":
      stateView("Set up needed", r.reason, el("div", { style: "margin-top:12px" },
        el("button", { class: "btn primary", onclick: () => chrome.runtime.openOptionsPage() }, "Open settings")));
      break;
    case "offline":
      stateView("Server not reachable", "", el("div", {}, "Start the API on the computer running the app:"),
        el("div", { style: "margin-top:8px" }, el("code", {}, "python -m api")),
        el("div", { class: "muted", style: "margin-top:8px;font-size:11px" }, r.reason));
      break;
    case "error":
      if (r.result) renderResult(r.result);
      else stateView("Lookup failed", r.error || "Unknown error.");
      break;
    default:
      stateView("Unexpected answer", JSON.stringify(r).slice(0, 200));
  }
}

function ask(force) {
  chrome.runtime.sendMessage({ type: "lookup", url: tab.url, tabId: tab.id, force }, (reply) => {
    if (chrome.runtime.lastError) return stateView("Error", chrome.runtime.lastError.message);
    show(reply && reply.response);
  });
}

document.getElementById("open-options").addEventListener("click", (e) => { e.preventDefault(); chrome.runtime.openOptionsPage(); });

(async () => {
  const s = await tiSettings();
  document.getElementById("open-app").addEventListener("click", (e) => { e.preventDefault(); chrome.tabs.create({ url: s.appUrl }); });
  document.getElementById("foot-left").textContent = s.apiUrl.replace(/^https?:\/\//, "");
  const forced = Number(new URLSearchParams(location.search).get("tabId"));  // popup opened as a page (testing)
  [tab] = forced ? [await chrome.tabs.get(forced)] : await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.url) return stateView("Not checked", "No page in this tab.");
  ask(false);
})();
