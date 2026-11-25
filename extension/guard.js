// Nuvori content script, run at document_start in the top page, before any page script.
//
// Nuvori's list and cards live in a closed shadow root, but the browser still sends their keyboard,
// focus and pointer events through the page: to the page's window and document listeners, with the
// card's host element as the target. Keyboard-shortcut code then takes keys typed into the card's
// field ("t" opens a site's team search), and focus traps pull the focus back or swallow the click.
//
// A listener on window in the capture phase runs before every other listener on the page. It is
// registered here, first, so for an event aimed at one of Nuvori's hosts it hands the event to that
// surface (suggestions.js registers an owner per host) and then stops it: no page listener, in any
// phase, sees the keys typed or the clicks made in Nuvori's UI. The browser's default actions (typing,
// Tab, Enter on a button) still happen. Focus leaving a page element for a Nuvori host is hidden too,
// so a page's focus trap does not pull focus back out of the card's field.
(() => {
  if (globalThis.__nuvoriGuard) return;
  const owners = new WeakMap();
  const TYPES = ["keydown", "keyup", "keypress", "beforeinput", "input", "textInput", "compositionstart", "compositionupdate", "compositionend",
    "paste", "copy", "cut", "focusin", "focusout", "focus", "blur", "pointerdown", "pointerup", "mousedown", "mouseup", "click", "dblclick",
    "auxclick", "contextmenu", "touchstart", "touchend"];
  const handle = (event) => {
    const owner = owners.get(event.target);
    if (owner) {
      try { owner(event); } finally { event.stopImmediatePropagation(); }
      return;
    }
    // A page element losing focus to a Nuvori host: the page must not react (focus traps refocus).
    if ((event.type === "focusout" || event.type === "blur") && event.relatedTarget && owners.has(event.relatedTarget)) {
      event.stopImmediatePropagation();
    }
  };
  for (const type of TYPES) window.addEventListener(type, handle, { capture: true });
  Object.defineProperty(globalThis, "__nuvoriGuard", {
    value: Object.freeze({ own: (host, owner) => { owners.set(host, owner); }, types: Object.freeze([...TYPES]) }),
  });
})();
