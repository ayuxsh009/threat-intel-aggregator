// In-page card: shows the verdict for the current site in the corner.
// Built inside a closed shadow root so page styles can't affect it (and it can't affect the page).
(() => {
  if (window.top !== window || window.__tiCard) return;
  window.__tiCard = true;

  const COLORS = { High: "#f85149", Medium: "#db6d28", Low: "#d29922", Legitimate: "#3fb950", Unknown: "#8b949e" };
  const LABEL = { High: "High risk", Medium: "Medium risk", Low: "Low risk", Legitimate: "No threats found", Unknown: "Unknown" };
  const label = (res) => (res.verdict && res.verdict.verdict === "benign" ? "Marked safe by analyst"
    : res.verdict && res.verdict.verdict === "malicious" ? "Confirmed malicious" : LABEL[res.risk] || res.risk);
  const scoreText = (res) => (res.verdict && res.verdict.verdict === "benign" ? "OK" : res.risk === "Unknown" ? "?" : String(res.score));
  const HIDE_AFTER = { Legitimate: 6000, Unknown: 6000, Low: 9000, Medium: 15000 };

  let host, root, card, hideTimer, polls = 0, dismissed = false;

  function el(tag, attrs = {}, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === "class") e.className = v;
      else if (k === "style") e.style.cssText = v;
      else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
      else e.setAttribute(k, v);
    }
    for (const c of children) if (c != null) e.append(c);
    return e;
  }

  const CSS = `
    :host { all: initial; }
    * { box-sizing: border-box; font-family: Inter, -apple-system, "Segoe UI", Roboto, sans-serif; }
    .card { position: fixed; right: 16px; bottom: 16px; width: 320px; z-index: 2147483647;
      background: #161b22; color: #e6edf3; border: 1px solid #30363d; border-left: 4px solid var(--c);
      border-radius: 8px; box-shadow: 0 8px 24px rgba(1,4,9,.5); padding: 12px 14px; font-size: 13px;
      line-height: 1.4; transition: opacity .25s, transform .25s; }
    .card.hidden { opacity: 0; transform: translateY(8px); pointer-events: none; }
    .top { display: flex; align-items: center; gap: 10px; }
    .score { font-size: 24px; font-weight: 700; color: var(--c); min-width: 44px; text-align: center; }
    .score small { display: block; font-size: 10px; font-weight: 500; color: #8b949e; }
    .meta { flex: 1; min-width: 0; }
    .sev { display: inline-block; font-size: 11px; font-weight: 600; color: var(--c); border: 1px solid var(--c);
      border-radius: 4px; padding: 0 6px; }
    .host { font-family: "JetBrains Mono", Consolas, monospace; font-size: 12px; color: #e6edf3; margin-top: 3px;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .x { background: none; border: 0; color: #8b949e; font-size: 18px; cursor: pointer; line-height: 1; padding: 0 2px; }
    .x:hover { color: #e6edf3; }
    ul { margin: 8px 0 0; padding: 8px 0 0 16px; border-top: 1px solid #21262d; }
    li { margin: 2px 0; color: #c9d1d9; font-size: 12px; }
    .actions { display: flex; gap: 6px; margin-top: 10px; }
    .btn { flex: 1; background: #21262d; color: #e6edf3; border: 1px solid #30363d; border-radius: 6px;
      padding: 5px 8px; font-size: 12px; cursor: pointer; }
    .btn:hover { background: #30363d; }
    .muted { color: #8b949e; font-size: 12px; margin-top: 6px; }
    .banner { position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647; background: #3d1214;
      border-bottom: 2px solid #f85149; color: #ffdcd7; padding: 12px 18px; display: flex; gap: 14px;
      align-items: center; font-size: 14px; box-shadow: 0 4px 16px rgba(0,0,0,.4); }
    .banner b { color: #fff; }
    .banner .grow { flex: 1; }
    .banner .btn { flex: none; }
    .banner .danger { background: #da3633; border-color: #f85149; color: #fff; }
  `;

  function mount() {
    const holder = document.createElement("ti-threat-card");
    root = holder.attachShadow({ mode: "closed" });
    root.append(el("style", {}, CSS));
    document.documentElement.append(holder);
  }

  function clear() {
    clearTimeout(hideTimer);
    if (root) for (const n of [...root.children]) if (n.tagName !== "STYLE") n.remove();
  }

  function dismiss() {
    dismissed = true;
    if (card) card.classList.add("hidden");
    setTimeout(clear, 300);
  }

  function muteButton() {
    return el("button", { class: "btn", onclick: () => { chrome.runtime.sendMessage({ type: "muteCard", url: location.href }); dismiss(); } }, "Hide on this site");
  }

  function showPending(r) {
    clear();
    const base = r.stale;
    card = el("div", { class: "card", style: `--c:${base ? COLORS[base.risk] : "#6e7681"}` },
      el("div", { class: "top" },
        el("div", { class: "score" }, base ? String(base.score) : "…", el("small", {}, base ? "last score" : "checking")),
        el("div", { class: "meta" },
          el("span", { class: "sev" }, base ? `${label(base)} (refreshing)` : "Checking…"),
          el("div", { class: "host" }, r.host || host)),
        el("button", { class: "x", title: "Close", onclick: dismiss }, "×")),
      el("div", { class: "muted" }, r.position > 1 ? `In queue: position ${r.position}, about ${r.eta_seconds}s` : "Looking this site up…"));
    root.append(card);
  }

  function showReady(res) {
    clear();
    const c = COLORS[res.risk] || COLORS.Unknown;
    const reasons = (res.reasons || []).slice(0, 3).map((t) => el("li", {}, t));
    if (res.rdap && res.rdap.age_days != null && res.rdap.age_days < 180) reasons.push(el("li", {}, `Domain is ${res.rdap.age_days} days old`));
    card = el("div", { class: "card", style: `--c:${c}` },
      el("div", { class: "top" },
        el("div", { class: "score" }, scoreText(res), el("small", {}, res.verdict ? "analyst" : "/ 100")),
        el("div", { class: "meta" },
          el("span", { class: "sev" }, label(res)),
          el("div", { class: "host" }, res.ioc)),
        el("button", { class: "x", title: "Close", onclick: dismiss }, "×")),
      reasons.length ? el("ul", {}, ...reasons) : null,
      el("div", { class: "actions" }, muteButton(), el("button", { class: "btn", onclick: dismiss }, "Dismiss")));
    root.append(card);
    if (HIDE_AFTER[res.risk]) {
      hideTimer = setTimeout(dismiss, HIDE_AFTER[res.risk]);
      card.addEventListener("mouseenter", () => clearTimeout(hideTimer));
      card.addEventListener("mouseleave", () => { hideTimer = setTimeout(dismiss, 3000); });
    }
  }

  function showBanner(res) {
    clear();
    const why = (res.reasons || [])[0] || "Flagged by threat intelligence";
    card = el("div", { class: "banner" },
      el("div", { class: "score", style: "--c:#f85149" }, String(res.score), el("small", {}, "/ 100")),
      el("div", { class: "grow" }, el("b", {}, res.verdict ? `Warning: ${res.ioc} was confirmed malicious by an analyst. `
        : `Warning: ${res.ioc} is rated high risk. `), why),
      el("button", { class: "btn danger", onclick: () => (history.length > 1 ? history.back() : location.replace("about:blank")) }, "Leave site"),
      el("button", { class: "btn", onclick: dismiss }, "I understand, continue"));
    root.append(card);
  }

  function render(r, settings) {
    const mode = settings.cardMode;
    if (mode === "off") return;
    const muted = (settings.mutedCards || []).includes(host);
    if (r.status === "ready") {
      const res = r.result;
      if (res.risk === "High") return showBanner(res);          // always warn, even if muted
      if (muted || dismissed) return;
      if (mode === "risky" && res.risk !== "Medium") return;
      return showReady(res);
    }
    if (r.status === "pending") {
      if (mode === "all" && !muted && !dismissed) showPending(r);
      if (polls++ < 40) setTimeout(ask, Math.min(15000, 3000 + polls * 500));
    }
    // skipped / setup / offline: stay silent on the page; the toolbar badge explains.
  }

  function ask() {
    chrome.runtime.sendMessage({ type: "lookup", url: location.href }, (reply) => {
      if (chrome.runtime.lastError || !reply) return;
      render(reply.response, reply.settings);
    });
  }

  host = location.hostname.toLowerCase().replace(/^www\./, "");
  mount();
  ask();
})();
