"use strict";

// ── state ────────────────────────────────────────────────────────────────────
let clientId = "";
let pollTimer = null;
let allEntries = [];  // full dataset from last scan
let scanTime   = "";

// ── DOM ───────────────────────────────────────────────────────────────────────
const elClientId    = document.getElementById("client-id");
const elBtnScan     = document.getElementById("btn-scan");
const elStatusPill  = document.getElementById("status-pill");
const elScanTime    = document.getElementById("scan-time");
const elEntryCount  = document.getElementById("entry-count");
const elShownCount  = document.getElementById("shown-count");
const elResultsArea = document.getElementById("results-area");
const elLog         = document.getElementById("log");
const elSearch      = document.getElementById("search-input");
const elSourceFilter = document.getElementById("source-filter");

// ── helpers ───────────────────────────────────────────────────────────────────
function log(msg) {
  const ts = new Date().toLocaleTimeString();
  elLog.textContent += `[${ts}] ${msg}\n`;
  elLog.scrollTop = elLog.scrollHeight;
}

function setStatus(state, text) {
  elStatusPill.className = `status-pill ${state}`;
  elStatusPill.textContent = text;
}

function escHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ── API ───────────────────────────────────────────────────────────────────────
async function sendPluginEvent(event, payload = {}) {
  const res = await fetch(`/api/clients/${clientId}/plugins/browser-history/event`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ event, payload }),
  });
  if (!res.ok) throw new Error(`sendPluginEvent ${res.status}`);
}

async function pollEvents() {
  try {
    const res = await fetch(`/api/clients/${clientId}/plugins/browser-history/events`);
    if (!res.ok) return;
    const events = await res.json();
    for (const { event, payload } of events) {
      handleIncomingEvent(event, payload);
    }
  } catch (_) {
    // network blip — silent
  }
}

// ── event handling ────────────────────────────────────────────────────────────
function handleIncomingEvent(event, payload) {
  if (event === "ready") {
    log("Plugin loaded on agent. Auto-scan running…");
    setStatus("scanning", "Scanning");
    return;
  }

  if (event === "history_result") {
    setStatus("done", "Done");
    allEntries = payload.entries || [];
    scanTime   = payload.scannedAt || "";
    const total = payload.total || allEntries.length;

    log(`Scan complete — ${total} unique URLs found (${scanTime})`);

    if (scanTime) {
      elScanTime.textContent = `Last scan: ${new Date(scanTime).toLocaleString()}`;
    }
    elEntryCount.textContent = total;
    elEntryCount.classList.toggle("hidden", total === 0);

    if (payload.errors && payload.errors.length) {
      log("Errors: " + payload.errors.join(" | "));
    }

    populateSourceFilter(allEntries);
    renderResults();
    return;
  }

  log(`Event: ${event}`);
}

// ── source filter ─────────────────────────────────────────────────────────────
function populateSourceFilter(entries) {
  const sources = [...new Set(entries.map(e => e.source))].sort();
  // preserve current selection
  const prev = elSourceFilter.value;
  // remove all except first option (All browsers)
  while (elSourceFilter.options.length > 1) elSourceFilter.remove(1);
  for (const src of sources) {
    const opt = document.createElement("option");
    opt.value = src;
    opt.textContent = src;
    elSourceFilter.appendChild(opt);
  }
  if (prev && sources.includes(prev)) elSourceFilter.value = prev;
}

// ── render ────────────────────────────────────────────────────────────────────
function renderResults() {
  const query  = elSearch.value.trim().toLowerCase();
  const source = elSourceFilter.value;

  let filtered = allEntries;
  if (source) {
    filtered = filtered.filter(e => e.source === source);
  }
  if (query) {
    filtered = filtered.filter(e =>
      e.url.toLowerCase().includes(query) ||
      (e.title || "").toLowerCase().includes(query)
    );
  }

  elShownCount.textContent = filtered.length;
  elShownCount.classList.toggle("hidden", filtered.length === 0 && allEntries.length === 0);

  if (filtered.length === 0) {
    const msg = allEntries.length === 0
      ? "Results will appear here after scanning."
      : "No results match your filter.";
    elResultsArea.innerHTML = `<p class="placeholder-text">${msg}</p>`;
    return;
  }

  const rows = filtered.map(e => `
    <tr>
      <td class="url-cell"><a href="${escHtml(e.url)}" target="_blank" rel="noopener noreferrer">${escHtml(e.url)}</a></td>
      <td class="title-cell">${escHtml(e.title || "")}</td>
      <td class="source-cell"><span class="source-tag">${escHtml(e.source)}</span></td>
    </tr>`).join("");

  elResultsArea.innerHTML = `
    <table class="history-table">
      <thead>
        <tr>
          <th>URL</th>
          <th>Title</th>
          <th>Source</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// ── scan button ───────────────────────────────────────────────────────────────
elBtnScan.addEventListener("click", async () => {
  setStatus("scanning", "Scanning");
  elBtnScan.disabled = true;
  log("Manual scan triggered…");
  try {
    await sendPluginEvent("scan");
  } catch (err) {
    log(`Error: ${err.message}`);
    setStatus("error", "Error");
  } finally {
    elBtnScan.disabled = false;
  }
});

// ── live filter ───────────────────────────────────────────────────────────────
elSearch.addEventListener("input", renderResults);
elSourceFilter.addEventListener("change", renderResults);

// ── init ──────────────────────────────────────────────────────────────────────
(function init() {
  const params = new URLSearchParams(window.location.search);
  clientId = params.get("clientId") || params.get("client_id") || "";
  elClientId.value = clientId;
  log(`Plugin started. clientId=${clientId}`);

  if (!clientId) {
    log("WARNING: no clientId in URL params.");
    return;
  }

  // Start polling for events
  pollTimer = setInterval(pollEvents, 2000);
  // Immediate first poll to catch buffered auto-scan result
  pollEvents();
})();
