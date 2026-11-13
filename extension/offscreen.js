// Offscreen document used only to clear the clipboard after a password copy.
// It never receives a secret: it overwrites whatever is on the clipboard with an empty string.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.target !== "offscreen" || message.action !== "clear_clipboard" || sender.id !== chrome.runtime.id || sender.tab) return false;
  const onCopy = (event) => {
    event.clipboardData.setData("text/plain", "");
    event.preventDefault();
  };
  document.addEventListener("copy", onCopy, { once: true });
  let cleared = false;
  try { cleared = document.execCommand("copy"); } catch { cleared = false; }
  document.removeEventListener("copy", onCopy);
  sendResponse({ status: cleared ? "ok" : "error" });
  return false;
});
