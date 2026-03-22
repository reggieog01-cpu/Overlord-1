# Overlord Desktop

A native desktop (fat) client for the Overlord server, built with [Electron](https://electronjs.org). Use this instead of a browser to connect to your Overlord instance.

## Features

- Native desktop window with a connection screen
- Remembers your last server address across launches
- TLS toggle for connecting to HTTPS or HTTP servers
- Accepts self-signed certificates
- Full keyboard shortcut support (cut/copy/paste)
- Cross-platform (macOS, Windows, Linux)

## Prerequisites

- [Node.js](https://nodejs.org) or [Bun](https://bun.sh) installed

## Quick Start

```bash
cd Overlord-Desktop
npm install    # or: bun install
npm start      # or: npx electron .
```

This will:
1. Show a connect screen where you enter the Overlord server's IP/hostname and port
2. Click **Connect** to load the Overlord web UI inside the native window
3. Your connection details are saved automatically for next launch

## Building for Distribution

```bash
# Windows
npm run build:win

# macOS
npm run build:mac

# Linux
npm run build:linux
```

## Configuration

On first connect, the app saves your connection to the Electron userData directory:
- **Windows:** `%APPDATA%/overlord-desktop/connection.json`
- **macOS:** `~/Library/Application Support/overlord-desktop/connection.json`
- **Linux:** `~/.config/overlord-desktop/connection.json`

Defaults:
- **Port:** 5173
- **TLS:** Enabled
