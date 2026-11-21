const APP_URLS = ["https://cyberlab-ai.vercel.app/browser-workspace", "http://localhost:3000/browser-workspace", "http://127.0.0.1:3000/browser-workspace"];
const attachedTabs = new Set();
let sharedTabId = null;
const editHistory = [];
const tabEvidence = new Map();
const MAX_EVENTS = 150;

function cleanUrl(raw) {
  try {
    const u = new URL(raw);
    return u.origin + u.pathname + (u.search ? "?[query values redacted]" : "");
  } catch { return "[invalid URL]"; }
}
function safeHeaders(headers = []) {
  const sensitive = /authorization|cookie|token|secret|session|api[-_]?key/i;
  return headers.slice(0, 60).map(h => ({ name: String(h.name || "").slice(0, 120), value: sensitive.test(h.name || "") ? "[REDACTED]" : String(h.value || "").slice(0, 500) }));
}
function record(tabId, item) {
  const list = tabEvidence.get(tabId) || [];
  list.push(item);
  if (list.length > MAX_EVENTS) list.splice(0, list.length - MAX_EVENTS);
  tabEvidence.set(tabId, list);
}
chrome.debugger.onEvent.addListener((source, method, params) => {
  if (!attachedTabs.has(source.tabId)) return;
  if (method === "Network.requestWillBeSent") {
    record(source.tabId, { kind: "request", method: params.request?.method || "?", url: cleanUrl(params.request?.url || ""), resourceType: params.type || "Other", timestamp: params.timestamp });
  } else if (method === "Network.responseReceived") {
    record(source.tabId, { kind: "response", url: cleanUrl(params.response?.url || ""), status: params.response?.status || 0, mimeType: params.response?.mimeType || "", fromDiskCache: !!params.response?.fromDiskCache });
  } else if (method === "Network.loadingFailed") {
    record(source.tabId, { kind: "network-error", error: String(params.errorText || "Request failed").slice(0, 200) });
  }
});
chrome.debugger.onDetach.addListener(source => { attachedTabs.delete(source.tabId); if (sharedTabId === source.tabId) sharedTabId = null; });
chrome.runtime.onConnect.addListener(port => { if (port.name === "cyberlab-workspace") port.onDisconnect.addListener(() => {}); });

async function appTab() {
  const tabs = await chrome.tabs.query({});
  return tabs.find(t => APP_URLS.some(url => (t.url || "").startsWith(url)));
}
async function sendToApp(payload) {
  let tab = await appTab();
  if (!tab) tab = await chrome.tabs.create({ url: APP_URLS[0] });
  if (!tab.id) throw new Error("Could not open CyberLab browser workspace.");
  for (let attempt = 0; attempt < 10; attempt++) {
    try { await chrome.tabs.sendMessage(tab.id, { type: "browser-snapshot", payload }); return; }
    catch { await new Promise(resolve => setTimeout(resolve, 300)); }
  }
  throw new Error("CyberLab workspace is open but its browser bridge did not become ready. Reload /browser-workspace and share again.");
}
async function inspectTab(tab) {
  if (!tab?.id || !tab.url || !/^https?:/.test(tab.url)) throw new Error("Select a normal HTTP or HTTPS browser tab.");
  const tabId = tab.id;
  await chrome.debugger.attach({ tabId }, "1.3");
  attachedTabs.add(tabId);
  sharedTabId = tabId;
  editHistory.length = 0;
  tabEvidence.set(tabId, []);
  try {
    await chrome.debugger.sendCommand({ tabId }, "Network.enable", { maxTotalBufferSize: 0, maxResourceBufferSize: 0 });
    await chrome.debugger.sendCommand({ tabId }, "Page.enable");
    const evaluated = await chrome.debugger.sendCommand({ tabId }, "Runtime.evaluate", {
      returnByValue: true,
      expression: `(() => {
        const redactUrl = (value) => { try { const u = new URL(value, location.href); return u.origin + u.pathname + (u.search ? "?[query values redacted]" : ""); } catch { return ""; } };
        const nodes = Array.from(document.querySelectorAll("body *")).slice(0, 1200).map((el) => ({
          tag: el.tagName.toLowerCase(),
          id: (el.id || "").slice(0, 120),
          className: (typeof el.className === "string" ? el.className : "").slice(0, 240),
          role: el.getAttribute("role") || "",
          type: el.getAttribute("type") || "",
          name: el.getAttribute("name") || "",
          href: el.hasAttribute("href") ? redactUrl(el.getAttribute("href")) : "",
          text: ["INPUT","TEXTAREA","SELECT"].includes(el.tagName) ? "" : (el.children.length ? "" : (el.textContent || "").trim().slice(0, 240)),
          passwordField: el.tagName === "INPUT" && el.type === "password"
        }));
        return { title: document.title, url: location.origin + location.pathname, readyState: document.readyState, nodes, forms: Array.from(document.forms).slice(0,80).map(f => ({ method: (f.method || "get").toUpperCase(), action: redactUrl(f.action), fields: Array.from(f.elements).slice(0,80).map(x => ({ tag: x.tagName.toLowerCase(), type: x.type || "", name: x.name || "", autocomplete: x.autocomplete || "" })) })) };
      })()`
    });
    // Keep the debugger attached briefly so the operator can navigate/interact and generate a small live network sample.
    await new Promise(resolve => setTimeout(resolve, 5000));
    const cookies = await chrome.debugger.sendCommand({ tabId }, "Network.getAllCookies");
    const targetHost = new URL(tab.url).hostname.toLowerCase();
    const cookieMetadata = (cookies.cookies || []).filter(c => { const domain = String(c.domain || "").replace(/^\\./, "").toLowerCase(); return targetHost === domain || targetHost.endsWith("." + domain); }).slice(0, 200).map(c => ({
      name: c.name, domain: c.domain, path: c.path, secure: !!c.secure,
      httpOnly: !!c.httpOnly, sameSite: c.sameSite || "unspecified",
      session: !!c.session, expires: c.session ? null : c.expires
    }));
    const snapshot = {
      version: 1, capturedAt: new Date().toISOString(), tabId,
      page: evaluated.result?.value || {}, cookies: cookieMetadata,
      network: tabEvidence.get(tabId) || [],
      safety: { cookieValuesIncluded: false, formValuesIncluded: false, requestBodiesIncluded: false, responseBodiesIncluded: false, queryValuesIncluded: false }
    };
    await sendToApp(snapshot);
    return { ok: true, title: snapshot.page.title || tab.title || "Shared tab", events: snapshot.network.length, cookies: snapshot.cookies.length };
  } catch (error) {
    try { await chrome.debugger.detach({ tabId }); } catch {}
    attachedTabs.delete(tabId);
    if (sharedTabId === tabId) sharedTabId = null;
    throw error;
  }
}
async function editAttribute(payload) {
  if (!sharedTabId || !attachedTabs.has(sharedTabId)) throw new Error("No active shared tab. Share a tab first.");
  if (!payload || typeof payload.selector !== "string" || !payload.selector.trim() || payload.selector.length > 500) throw new Error("Provide a CSS selector under 500 characters.");
  const allowed = new Set(["class", "title", "aria-label", "placeholder"]);
  if (!allowed.has(payload.attribute)) throw new Error("Only class, title, aria-label and placeholder can be edited.");
  if (typeof payload.value !== "string" || payload.value.length > 500) throw new Error("Attribute value must be text under 500 characters.");
  const tabId = sharedTabId;
  const doc = await chrome.debugger.sendCommand({ tabId }, "DOM.getDocument", { depth: -1, pierce: true });
  const found = await chrome.debugger.sendCommand({ tabId }, "DOM.querySelector", { nodeId: doc.root.nodeId, selector: payload.selector });
  if (!found.nodeId) throw new Error("The selector did not match an element.");
  const attrs = await chrome.debugger.sendCommand({ tabId }, "DOM.getAttributes", { nodeId: found.nodeId });
  let previous = null;
  for (let i = 0; i < attrs.attributes.length; i += 2) if (attrs.attributes[i] === payload.attribute) previous = attrs.attributes[i + 1];
  await chrome.debugger.sendCommand({ tabId }, "DOM.setAttributeValue", { nodeId: found.nodeId, name: payload.attribute, value: payload.value });
  editHistory.push({ selector: payload.selector, attribute: payload.attribute, previous });
  return { ok: true, message: "Temporary page DOM attribute updated. This does not change the website's saved source or server data.", undoAvailable: true };
}
async function undoLastEdit() {
  if (!sharedTabId || !attachedTabs.has(sharedTabId)) throw new Error("No active shared tab.");
  const edit = editHistory.pop();
  if (!edit) throw new Error("There is no DOM edit to undo.");
  const tabId = sharedTabId;
  const doc = await chrome.debugger.sendCommand({ tabId }, "DOM.getDocument", { depth: -1, pierce: true });
  const found = await chrome.debugger.sendCommand({ tabId }, "DOM.querySelector", { nodeId: doc.root.nodeId, selector: edit.selector });
  if (!found.nodeId) throw new Error("The edited element no longer exists; reload the page to restore its original DOM.");
  if (edit.previous === null) await chrome.debugger.sendCommand({ tabId }, "DOM.removeAttribute", { nodeId: found.nodeId, name: edit.attribute });
  else await chrome.debugger.sendCommand({ tabId }, "DOM.setAttributeValue", { nodeId: found.nodeId, name: edit.attribute, value: edit.previous });
  return { ok: true, message: "The last temporary DOM edit was reverted.", undoAvailable: editHistory.length > 0 };
}
async function stopSharing() {
  const tabId = sharedTabId;
  if (tabId && attachedTabs.has(tabId)) {
    try { await chrome.debugger.detach({ tabId }); } catch {}
  }
  if (tabId) attachedTabs.delete(tabId);
  sharedTabId = null;
  editHistory.length = 0;
  return { ok: true, message: "Browser sharing stopped and temporary edit history cleared." };
}
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "inspect-active-tab") {
    chrome.tabs.query({ active: true, lastFocusedWindow: true }).then(tabs => inspectTab(tabs[0])).then(sendResponse).catch(error => sendResponse({ ok: false, error: error.message }));
    return true;
  }
  if (message?.type === "edit-attribute") {
    editAttribute(message.payload).then(sendResponse).catch(error => sendResponse({ ok: false, error: error.message }));
    return true;
  }
  if (message?.type === "undo-last-edit") {
    undoLastEdit().then(sendResponse).catch(error => sendResponse({ ok: false, error: error.message }));
    return true;
  }
  if (message?.type === "stop-sharing") {
    stopSharing().then(sendResponse).catch(error => sendResponse({ ok: false, error: error.message }));
    return true;
  }
});
