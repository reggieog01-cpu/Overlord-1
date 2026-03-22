const { app, BrowserWindow, ipcMain } = require("electron");
const path = require("path");
const fs = require("fs");

// ── Persistence ──────────────────────────────────────────────
app.setAppUserModelId("com.overlord.desktop");

const CONFIG_DIR = path.join(app.getPath("userData"), "overlord-desktop");
const CONFIG_FILE = path.join(CONFIG_DIR, "connection.json");

function loadSavedConnection() {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      const raw = JSON.parse(fs.readFileSync(CONFIG_FILE, "utf-8"));
      if (raw && typeof raw.host === "string" && typeof raw.port === "number") {
        return {
          host: raw.host,
          port: raw.port,
          useTLS: raw.useTLS !== false,
        };
      }
    }
  } catch {
    // ignore corrupt config
  }
  return null;
}

function saveConnection(conn) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(conn, null, 2));
}

// ── Window ───────────────────────────────────────────────────
let win;
let serverBaseUrl = null; // e.g. "https://1.2.3.4:5173"

function createWindow() {
  win = new BrowserWindow({
    width: 1280,
    height: 800,
    title: "Overlord",
    icon: path.join(__dirname, "icon.ico"),
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  win.loadFile(path.join(__dirname, "connect", "index.html"));

  // Allow self-signed certs on the target Overlord server
  win.webContents.session.setCertificateVerifyProc((_req, cb) => cb(0));
}

app.whenReady().then(createWindow);

app.on("window-all-closed", () => {
  app.quit();
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

// ── IPC handlers ─────────────────────────────────────────────
ipcMain.handle("get-saved-connection", () => {
  return loadSavedConnection();
});

ipcMain.handle("connect-to-server", (_event, { host, port, useTLS }) => {
  if (!host || host.trim().length === 0) {
    return { success: false, error: "Host is required" };
  }
  if (port < 1 || port > 65535) {
    return { success: false, error: "Port must be between 1 and 65535" };
  }

  const protocol = useTLS ? "https" : "http";
  const url = `${protocol}://${host.trim()}:${port}`;

  saveConnection({ host: host.trim(), port, useTLS });
  serverBaseUrl = url;
  win.loadURL(url);

  return { success: true };
});

ipcMain.handle("go-back-to-connect", () => {
  serverBaseUrl = null;
  win.loadFile(path.join(__dirname, "connect", "index.html"));
});
