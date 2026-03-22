const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("overlord", {
  getSavedConnection: () => ipcRenderer.invoke("get-saved-connection"),
  connectToServer: (opts) => ipcRenderer.invoke("connect-to-server", opts),
  goBackToConnect: () => ipcRenderer.invoke("go-back-to-connect"),
});
