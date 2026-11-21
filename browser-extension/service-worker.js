const APP_URLS = ["https://cyberlab-ai.vercel.app/browser-workspace", "http://localhost:3000/browser-workspace", "http://127.0.0.1:3000/browser-workspace"];
const attachedTabs = new Set();
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
chrome.debugger.onDetach.addListener(source => { attachedTabs.delete(source.tabId); });

async function appTab() {
  const tabs = await chrome.tabs.query({});
  return tabs.find(t => APP_URLS.some(url => (t.url || "").startsWith(url)));
}
async function sendToApp(payload) {
  let tab = await appTab();
  if (!tab) tab = await chrome.tabs.create({ url: APP_URLS[0] });
  if (!tab.id) throw new Error("Could not open CyberLab browser workspace.");
  for (let attempt = 0; attempt < 10; attempt++) {\n    try { await chrome.tabs.sendMessage(tab.id, { type: "browser-snapshot", payload }); return; }\n    catch { await new Promise(resolve => setTimeout(resolve, 300)); }\n  }\n  throw new Error("CyberLab workspace is open but its browser bridge did not become ready. Reload /browser-workspace and share again.");
}
async function inspectTab(tab) {
  if (!tab?.id || !tab.url || !/^https?:/.test(tab.url)) throw new Error("Select a normal HTTP or HTTPS browser tab.");
  const tabId = tab.id;
  await chrome.debugger.attach({ tabId }, "1.3");
  attachedTabs.add(tabId);
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
    // Keep the debugger attached briefly so the operator can navigate/interact and generate a small live network sample.\n    await new Promise(resolve => setTimeout(resolve, 5000));\n    const cookies = await chrome.debugger.sendCommand({ tabId }, "Network.getAllCookies");
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
  } finally {
    try { await chrome.debugger.detach({ tabId }); } catch {}
    attachedTabs.delete(tabId);
  }
}
async function editAttribute(payload) {
  if (!payload || typeof payload.selector !== "string" || payload.selector.length > 500) throw new Error("Provide a CSS selector under 500 characters.");
  const allowed = new Set(["class", "title", "aria-label", "placeholder"]);
  if (!allowed.has(payload.attribute)) throw new Error("Only class, title, aria-label and placeholder can be edited.");
  if (typeof payload.value !== "string" || payload.value.length > 500) throw new Error("Attribute value must be text under 500 characters.");
  const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  const target = tabs[0];
  if (!target?.id || !attachedTabs.has(target.id)) throw new Error("Share the target tab again before editing it. This first release keeps editing disabled after inspection.");
  return { ok: false, error: "Live editing is not enabled in this release. Inspection is read-only; the next release will add an explicit, reversible DOM edit session." };
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
});
