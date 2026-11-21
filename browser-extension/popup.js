const status = document.getElementById("status");
function run(type, payload, label) {
  status.textContent = label;
  chrome.runtime.sendMessage({type,payload}, response => {
    if (chrome.runtime.lastError) { status.textContent = chrome.runtime.lastError.message; return; }
    if (!response?.ok) { status.textContent = response?.error || "Operation failed."; return; }
    if (type === "inspect-active-tab") status.textContent = "Inspected " + response.title + "\\n" + response.events + " network events · " + response.cookies + " cookie metadata records.";
    else if (type === "capture-session-cookies") status.textContent = "Captured " + response.count + " cookie records for " + response.origin + ".\\nNames: " + response.names.join(", ") + "\\nValues remain in volatile extension memory and were not sent to the app.";
    else status.textContent = "Cleared " + response.cleared + " locally held cookie records.";
  });
}
document.getElementById("share").addEventListener("click", () => run("inspect-active-tab", undefined, "Inspecting active tab…"));
document.getElementById("capture").addEventListener("click", () => {
  if (!confirm("Capture session cookie values for the currently shared, authorised test tab? Values remain in this extension's volatile memory and are not sent to CyberLab's web app. Clear them when finished.")) return;
  run("capture-session-cookies", {confirmCapture:true}, "Capturing cookies locally…");
});
document.getElementById("clear").addEventListener("click", () => run("clear-session-cookies", undefined, "Clearing local session material…"));
