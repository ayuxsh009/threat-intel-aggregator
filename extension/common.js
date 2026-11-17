// Shared by the background worker, popup and options page.

const TI_DEFAULTS = {
  apiUrl: "http://127.0.0.1:8600",
  appUrl: "http://localhost:8501",
  token: "",
  cardMode: "all",        // "all" | "risky" | "off"
  skipList: [],           // hosts never sent to the server
  mutedCards: [],         // hosts where the in-page card is hidden (still checked)
};

const TI_COLORS = {
  High: "#f85149",
  Medium: "#db6d28",
  Low: "#d29922",
  Legitimate: "#3fb950",
  Unknown: "#8b949e",
};

// Severity label, taking an analyst verdict into account.
function tiLabel(res) {
  if (res.verdict && res.verdict.verdict === "benign") return "Marked safe by analyst";
  if (res.verdict && res.verdict.verdict === "malicious") return "Confirmed malicious";
  return { High: "High risk", Medium: "Medium risk", Low: "Low risk", Legitimate: "No threats found", Unknown: "Unknown" }[res.risk] || res.risk;
}

// Text for the toolbar badge and the big number: the score, "OK" for analyst-approved sites, "?" when unknown.
function tiScoreText(res) {
  if (res.verdict && res.verdict.verdict === "benign") return "OK";
  return res.risk === "Unknown" ? "?" : String(res.score);
}

async function tiSettings() {
  const stored = await chrome.storage.sync.get(TI_DEFAULTS);
  return { ...TI_DEFAULTS, ...stored };
}

function tiHostOf(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    return u.hostname.toLowerCase().replace(/^www\./, "").replace(/\.$/, "");
  } catch (e) {
    return null;
  }
}

function tiMatches(host, list) {
  return (list || []).some((d) => {
    const x = String(d).trim().toLowerCase().replace(/^\*\./, "").replace(/^www\./, "");
    return x && (host === x || host.endsWith("." + x));
  });
}

function tiLocalHost(host) {
  if (!host || host === "localhost" || !host.includes(".")) return true;
  if (/\.(local|localhost|internal|lan|home|corp|test|invalid|example)$/.test(host)) return true;
  if (/^(10\.|127\.|192\.168\.|169\.254\.|0\.)/.test(host)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(host)) return true;
  return host.startsWith("[");  // IPv6 literals: let the server decide only for public ones
}
