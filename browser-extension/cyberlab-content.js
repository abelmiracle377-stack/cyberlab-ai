(() => {
  const APP_ORIGINS = new Set(["https://cyberlab-ai.vercel.app", "http://localhost:3000", "http://127.0.0.1:3000"]);
  if (!APP_ORIGINS.has(location.origin)) return;
  const CHANNEL = "CYBERLAB_BROWSER_BRIDGE_V1";
  // Keep the extension worker alive while the operator keeps the CyberLab workspace open.
  const workspacePort = chrome.runtime.connect({ name: "cyberlab-workspace" });
  void workspacePort;
  window.addEventListener("message", (event) => {
    if (event.source !== window || event.origin !== location.origin) return;
    const message = event.data;
    if (!message || message.channel !== CHANNEL || message.direction !== "to-extension") return;
    if (message.type === "edit-attribute" || message.type === "fill-page-field" || message.type === "undo-last-edit" || message.type === "stop-sharing") {
      chrome.runtime.sendMessage({ type: message.type, payload: message.payload }, (response) => {
        window.postMessage({ channel: CHANNEL, direction: "from-extension", type: "edit-result", payload: response || { ok: false, error: "No extension response." } }, location.origin);
      });
    }
  });
  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type === "browser-snapshot") {
      window.postMessage({ channel: CHANNEL, direction: "from-extension", type: "browser-snapshot", payload: message.payload }, location.origin);
    }
    if (message?.type === "browser-edit-result") {
      window.postMessage({ channel: CHANNEL, direction: "from-extension", type: "edit-result", payload: message.payload }, location.origin);
    }
  });
})();