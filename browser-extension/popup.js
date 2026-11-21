const button = document.getElementById("share");
const status = document.getElementById("status");
button.addEventListener("click", () => {
  button.disabled = true;
  status.textContent = "Attaching to the active tab and collecting safe metadata…";
  chrome.runtime.sendMessage({ type: "inspect-active-tab" }, (result) => {
    button.disabled = false;
    if (chrome.runtime.lastError) { status.textContent = chrome.runtime.lastError.message; return; }
    status.textContent = result?.ok
      ? "Shared with CyberLab. " + result.title + "\n" + result.events + " network events · " + result.cookies + " cookie metadata records."
      : (result?.error || "Could not inspect this tab.");
  });
});