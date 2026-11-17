# Threat Intel Aggregator: Chrome extension

Shows a threat score and verdict for every site you visit, using **your own** Threat Intel Aggregator server.

- **Toolbar badge** on every site: the score (0–100), coloured by severity. `OK` means an analyst marked the site safe, `?` means unknown, `…` means checking.
- **Corner card** on each page with the severity, score and top reasons. It hides by itself; hover to keep it open.
- **Red warning bar** on high-risk sites, with **Leave site** and **Continue** buttons.
- **Popup** (click the icon): full score breakdown, domain age, ThreatFox and URLhaus listings, how often the workspace has seen the site, and buttons to **mark it malicious or a false positive** or **re-check now**.

## Install

1. Start the API next to the app (same database):
   ```bash
   pip install -r requirements-api.txt
   python -m api
   ```
   It listens on `http://127.0.0.1:8600` and prints the **extension token**. Admins can also find the token in the app under **Settings → Browser extension**.
2. In Chrome, open `chrome://extensions`, switch on **Developer mode** and click **Load unpacked**. Choose this `extension` folder.
3. The settings page opens. Paste the token and click **Save and test**. You should see "Connected… Sources: …".

Works in Chrome, Edge, Brave and other Chromium browsers (Manifest V3).

## Settings

| Setting | Default | Meaning |
|---|---|---|
| API address | `http://127.0.0.1:8600` | Where `python -m api` runs. Another host needs permission, which the extension asks for when you save |
| Extension token | — | Must match the server's token |
| App address | `http://localhost:8501` | Used by "Open app" |
| On-page card | Every site | **Every site**, **Risky sites only** (Medium and High) or **Badge only**. High always shows the warning bar |
| Never check these sites | empty | Hosts (and their subdomains) that are never sent to the server |
| Card hidden on these sites | empty | Still checked and badged, but no card. "Hide on this site" on the card adds to this list |

## Privacy

- Only the **host name** is sent (`login.example.com`), never the full URL, query string, page content or form data.
- Local and private addresses (`localhost`, `192.168.x.x`, `.local`, `.internal`, …), browser pages and your skip list are never sent.
- Your server looks each host up in VirusTotal, AbuseIPDB, abuse.ch and RDAP with **your** API keys, so those services see the hosts you visit. Use the skip list for sites you'd rather keep private.
- The token stays in Chrome's synced extension storage. The server only accepts requests that carry it, and its CORS policy only allows browser extensions.

## How lookups work

1. On each page load the extension asks the server about the host.
2. If the database has a result from the last 24 hours, the answer is immediate.
3. Otherwise the host is queued. With a free VirusTotal key the server waits 15.5 s between lookups to stay within 4 per minute, so a busy browsing session may queue for a while. The card shows "Checking…", or the previous result while refreshing.
4. Results are stored as a daily **Browser extension** investigation in the app, so they appear on the dashboard, in investigations and in the infrastructure graph. Analyst verdicts set in the extension or the app apply everywhere.

## Files

| File | Role |
|---|---|
| `manifest.json` | Manifest V3: permissions `storage` and `tabs`, host access to `127.0.0.1` and `localhost` |
| `background.js` | Service worker: calls the API, caches answers for 10 minutes, updates the badge |
| `content.js` | Corner card and warning bar, drawn in a closed shadow DOM so pages can't restyle or read it |
| `popup.html` / `popup.js` | Detail view and verdict buttons |
| `options.html` / `options.js` | Settings page |
| `common.js`, `ui.css` | Shared helpers and styles |
| `icons/` | 16, 32, 48 and 128 px icons |
