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

// Draws an SVG icon (a data: URL) into a 64x64 PNG. An SVG in <img> cannot run scripts or load other
// files. The reply is base64 PNG only, never the original markup.
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.target !== "offscreen" || message.action !== "rasterize_icon" || sender.id !== chrome.runtime.id || sender.tab) return false;
  const svg = message.svg;
  if (typeof svg !== "string" || !svg.startsWith("data:image/svg+xml;base64,") || svg.length > 400000) { sendResponse({ png: null }); return false; }
  const image = new Image();
  image.onload = () => {
    try {
      const width = image.naturalWidth || 64, height = image.naturalHeight || 64;
      const scale = Math.min(64 / width, 64 / height);
      const w = Math.max(1, Math.round(width * scale)), h = Math.max(1, Math.round(height * scale));
      const canvas = document.createElement("canvas");
      canvas.width = 64; canvas.height = 64;
      canvas.getContext("2d").drawImage(image, Math.round((64 - w) / 2), Math.round((64 - h) / 2), w, h);
      sendResponse({ png: canvas.toDataURL("image/png").split(",")[1] || null });
    } catch { sendResponse({ png: null }); }
  };
  image.onerror = () => sendResponse({ png: null });
  image.src = svg;
  return true;
});
