const params       = new URLSearchParams(window.location.search);
const clientIdInput = document.getElementById("client-id");
const scanBtn       = document.getElementById("scan-btn");
const killBtn       = document.getElementById("kill-btn");
const selHighBtn    = document.getElementById("sel-high-btn");
const selAllBtn     = document.getElementById("sel-all-btn");
const deselBtn      = document.getElementById("desel-btn");
const selCount      = document.getElementById("sel-count");
const statusPill    = document.getElementById("status-pill");
const countHigh     = document.getElementById("count-high");
const countMed      = document.getElementById("count-med");
const countLow      = document.getElementById("count-low");
const resultsArea   = document.getElementById("results-area");
const logEl         = document.getElementById("log");

const pluginId = "bot-killer";
const clientId = params.get("clientId") || "";
clientIdInput.value = clientId;

let pollTimer  = null;
let allEntries = [];  // current scan entries (array, ordered)
let selected   = new Set(); // selected entry IDs

// ─── Logging ──────────────────────────────────────────────────────────────────
function log(line) {
  const ts = new Date().toISOString();
  logEl.textContent = `${ts}  ${line}\n` + logEl.textContent;
}

function setStatus(text, cls) {
  statusPill.textContent = text;
  statusPill.className = "status-pill " + cls;
}

// ─── API ──────────────────────────────────────────────────────────────────────
async function sendPluginEvent(event, payload) {
  if (!clientId) { log("Missing clientId"); return; }
  const res = await fetch(
    `/api/clients/${encodeURIComponent(clientId)}/plugins/${pluginId}/event`,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ event, payload }) }
  );
  if (!res.ok) log(`sendEvent failed: ${res.status} ${await res.text()}`);
}

async function pollEvents() {
  if (!clientId) return;
  try {
    const res = await fetch(`/api/clients/${encodeURIComponent(clientId)}/plugins/${pluginId}/events`);
    if (!res.ok) { log(`poll failed: ${res.status}`); return; }
    const data = await res.json();
    for (const item of data.events || []) handleIncomingEvent(item.event, item.payload);
  } catch (err) { log(`poll error: ${err.message}`); }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function riskClass(risk) {
  return risk === "high" ? "risk-high" : risk === "medium" ? "risk-medium" : "risk-low";
}

function riskRowClass(risk) {
  return risk === "high" ? "row-high" : risk === "medium" ? "row-medium" : "row-low";
}

function typeLabel(type) {
  const map = {
    run_key: "Run Key", startup_file: "Startup File", scheduled_task: "Task",
    service: "Service", winlogon: "Winlogon", ifeo: "IFEO",
    appinit: "AppInit DLL", lsa: "LSA Provider", boot_execute: "Boot Execute", wmi: "WMI"
  };
  return map[type] || type;
}

// ─── Selection ────────────────────────────────────────────────────────────────
function updateSelectionUI() {
  selCount.textContent = `${selected.size} selected`;
  killBtn.disabled = selected.size === 0;
}

function syncCheckbox(id, checked) {
  const cb = document.getElementById(`cb-${id}`);
  if (cb) cb.checked = checked;
}

function toggleSelect(id) {
  if (selected.has(id)) { selected.delete(id); } else { selected.add(id); }
  updateSelectionUI();
}

selHighBtn.addEventListener("click", () => {
  for (const e of allEntries) if (e.risk === "high" && !e.killed) { selected.add(e.id); syncCheckbox(e.id, true); }
  updateSelectionUI();
});

selAllBtn.addEventListener("click", () => {
  for (const e of allEntries) if (!e.killed) { selected.add(e.id); syncCheckbox(e.id, true); }
  updateSelectionUI();
});

deselBtn.addEventListener("click", () => {
  selected.clear();
  for (const e of allEntries) syncCheckbox(e.id, false);
  updateSelectionUI();
});

// ─── Render ───────────────────────────────────────────────────────────────────
function renderResults(entries, highCount, medCount, lowCount) {
  countHigh.textContent = `${highCount} High`;
  countMed.textContent  = `${medCount} Med`;
  countLow.textContent  = `${lowCount} Low`;
  countHigh.classList.toggle("hidden", highCount === 0);
  countMed.classList.toggle("hidden",  medCount === 0);
  countLow.classList.toggle("hidden",  lowCount === 0);

  if (entries.length === 0) {
    resultsArea.innerHTML = `<p class="no-threats">&#x2714; No suspicious persistence found on this machine.</p>`;
    return;
  }

  // Sort: high → medium → low, killed entries last
  const sorted = [...entries].sort((a, b) => {
    if (a.killed !== b.killed) return a.killed ? 1 : -1;
    const order = { high: 0, medium: 1, low: 2 };
    return (order[a.risk] ?? 3) - (order[b.risk] ?? 3);
  });

  const rows = sorted.map(e => {
    const killed   = e.killed;
    const rowCls   = killed ? "row-killed" : riskRowClass(e.risk);
    const isSel    = selected.has(e.id);
    const reasons  = (e.reasons || []).map(r => `<span>• ${escapeHtml(r)}</span>`).join("");

    return `<tr class="${rowCls}" data-id="${escapeHtml(e.id)}">
      <td><input type="checkbox" id="cb-${escapeHtml(e.id)}" ${isSel ? "checked" : ""} ${killed ? "disabled" : ""} onchange="toggleSelect('${escapeHtml(e.id)}')"></td>
      <td><span class="risk-badge ${riskClass(e.risk)}">${escapeHtml(e.risk)}</span></td>
      <td><span class="type-badge">${escapeHtml(typeLabel(e.type))}</span></td>
      <td class="name-cell">${escapeHtml(e.name)}</td>
      <td class="cmd-cell">${escapeHtml(e.command)}</td>
      <td class="loc-cell">${escapeHtml(e.location)}</td>
      <td class="reasons-cell">${reasons}</td>
      <td>${killed
        ? `<span style="color:#4ade80;font-size:11px">✓ Killed</span>`
        : `<button class="btn-kill-row" onclick="killOne('${escapeHtml(e.id)}')">Kill</button>`
      }</td>
    </tr>`;
  }).join("");

  resultsArea.innerHTML = `
    <table class="entries-table">
      <thead>
        <tr>
          <th style="width:28px"></th>
          <th>Risk</th>
          <th>Type</th>
          <th>Name</th>
          <th>Command / Path</th>
          <th>Location</th>
          <th>Reasons</th>
          <th></th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

// ─── Kill flow ────────────────────────────────────────────────────────────────
async function killOne(id) {
  const entry = allEntries.find(e => e.id === id);
  if (!entry) return;
  if (!confirm(`Kill "${entry.name}"?\n\nType: ${typeLabel(entry.type)}\nCommand: ${entry.command}`)) return;
  await doKill([id]);
}

killBtn.addEventListener("click", async () => {
  if (selected.size === 0) return;
  const names = allEntries.filter(e => selected.has(e.id)).map(e => `• ${e.name} (${typeLabel(e.type)})`).join("\n");
  if (!confirm(`Kill ${selected.size} selected persistence entry/entries?\n\n${names}\n\nThis cannot be undone.`)) return;
  await doKill([...selected]);
});

async function doKill(ids) {
  killBtn.disabled = true;
  setStatus(`Killing ${ids.length} entry/entries…`, "status-scanning");
  log(`Sending kill request for ${ids.length} ID(s)…`);
  try {
    await sendPluginEvent("kill", { ids });
    startPolling(); // watch for kill_result
  } catch (err) {
    log(`Kill request error: ${err.message}`);
    setStatus("Error", "status-found");
  }
}

// ─── Handle incoming events ───────────────────────────────────────────────────
function handleIncomingEvent(event, payload) {
  if (event === "ready") {
    log("Plugin ready on client — auto-scan started");
    setStatus("Scanning\u2026", "status-scanning");

  } else if (event === "scan_result") {
    stopPolling();
    allEntries = payload?.entries ?? [];
    const high = payload?.highCount ?? 0;
    const med  = payload?.medCount  ?? 0;
    const low  = payload?.lowCount  ?? 0;
    const total = payload?.total    ?? 0;

    // Restore killed state for entries we already killed this session
    for (const e of allEntries) {
      if (selected.has(e.id) && e.killed) selected.delete(e.id);
    }

    log(`Scan complete — ${total} persistence entries (${high} high, ${med} medium, ${low} low)`);
    if (high > 0) {
      setStatus(`\u26A0\uFE0F ${high} high-risk entries detected`, "status-found");
    } else {
      setStatus(total > 0 ? `${total} entries — no high risk` : "Clean", "status-clean");
    }

    renderResults(allEntries, high, med, low);
    scanBtn.disabled = false;
    updateSelectionUI();

  } else if (event === "kill_result") {
    stopPolling();
    const killed = payload?.killed ?? [];
    const failed = payload?.failed ?? [];

    log(`Kill complete — ${killed.length} removed, ${failed.length} failed`);
    for (const f of failed) log(`  FAILED: ${f.name} — ${f.error}`);

    // Mark killed entries in local state
    for (const id of killed) {
      selected.delete(id);
      const e = allEntries.find(x => x.id === id);
      if (e) e.killed = true;
    }

    const high = allEntries.filter(e => e.risk === "high" && !e.killed).length;
    const med  = allEntries.filter(e => e.risk === "medium" && !e.killed).length;
    const low  = allEntries.filter(e => e.risk === "low" && !e.killed).length;
    renderResults(allEntries, high, med, low);
    updateSelectionUI();
    setStatus(`Killed ${killed.length}${failed.length ? `, ${failed.length} failed` : ""}`, high > 0 ? "status-found" : "status-clean");
    killBtn.disabled = selected.size === 0;

  } else {
    log(`Event: ${event} \u2192 ${JSON.stringify(payload)}`);
  }
}

// ─── Polling ──────────────────────────────────────────────────────────────────
function startPolling() {
  stopPolling();
  pollTimer = setInterval(pollEvents, 2000);
  void pollEvents();
}
function stopPolling() {
  if (pollTimer !== null) { clearInterval(pollTimer); pollTimer = null; }
}

// ─── Scan button ──────────────────────────────────────────────────────────────
scanBtn.addEventListener("click", async () => {
  if (!clientId) { log("No clientId in URL"); return; }
  scanBtn.disabled = true;
  selected.clear();
  updateSelectionUI();
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
