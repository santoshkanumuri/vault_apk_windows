// Nuvori content script: inline account suggestions and save/update prompts.
// Runs in HTTPS pages, in the extension's isolated world. In a frame it only reports a focused
// card, address or code field and fills what the top page chose; it draws nothing there.
// All UI lives in closed shadow roots; every action needs a trusted user gesture
// on that UI after it has been visible and unobscured for ACTIVATION_DELAY_MS.
(() => {
  if (location.protocol !== "https:") return;
  const IN_FRAME = window !== window.top;
  if (typeof NuvoriFields === "undefined" || globalThis.__nuvoriInline) return;
  globalThis.__nuvoriInline = true;

  // Real DOM methods and getters, captured before the page can clobber them by name
  // (<img name="elementFromPoint">, <form name="body">, <input name="querySelectorAll"> in a form).
  // Always called with .call(); nothing below reads a method or getter off `document` or a form.
  const DOM = (() => {
    try {
      const getter = (proto, name) => {
        const read = Object.getOwnPropertyDescriptor(proto, name)?.get;
        if (typeof read !== "function") throw new Error(name);
        return read;
      };
      const method = (proto, name) => {
        const fn = proto[name];
        if (typeof fn !== "function") throw new Error(name);
        return fn;
      };
      return {
        documentElement: getter(Document.prototype, "documentElement"),
        body: getter(Document.prototype, "body"),
        activeElement: getter(Document.prototype, "activeElement"),
        visibilityState: getter(Document.prototype, "visibilityState"),
        elementFromPoint: method(Document.prototype, "elementFromPoint"),
        querySelector: method(Document.prototype, "querySelector"),
        querySelectorAll: method(Document.prototype, "querySelectorAll"),
        createElement: method(Document.prototype, "createElement"),
        createElementNS: method(Document.prototype, "createElementNS"),
        shadowElementFromPoint: method(ShadowRoot.prototype, "elementFromPoint"),
        shadowActiveElement: getter(ShadowRoot.prototype, "activeElement"),
        fragmentQuerySelectorAll: method(DocumentFragment.prototype, "querySelectorAll"),
        elementQuerySelectorAll: method(Element.prototype, "querySelectorAll"),
        getAttribute: method(Element.prototype, "getAttribute"),
        tagName: getter(Element.prototype, "tagName"),
        shadowRoot: getter(Element.prototype, "shadowRoot"),
        parentElement: getter(Node.prototype, "parentElement"),
        getRootNode: method(Node.prototype, "getRootNode"),
        addEventListener: method(EventTarget.prototype, "addEventListener"),
      };
    } catch {
      return null; // Never fall back to values a page could have replaced.
    }
  })();
  if (!DOM) return;
  const doc = document;
  const docRoot = () => DOM.documentElement.call(doc) || DOM.body.call(doc);
  const listen = (target, type, callback, options) => DOM.addEventListener.call(target, type, callback, options);
  const rootOf = (node) => DOM.getRootNode.call(node);
  const elementAt = (root, x, y) => (root === doc ? DOM.elementFromPoint.call(doc, x, y) : DOM.shadowElementFromPoint.call(root, x, y));
  const queryIn = (scope, selector) => [...(scope === doc ? DOM.querySelectorAll.call(doc, selector)
    : scope instanceof DocumentFragment ? DOM.fragmentQuerySelectorAll.call(scope, selector)
    : DOM.elementQuerySelectorAll.call(scope, selector))];
  const inputsIn = (scope) => queryIn(scope, "input");
  // Inputs, drop-downs and text areas: card expiry and country fields are often <select>.
  const controlsIn = (scope) => queryIn(scope, "input, select, textarea");
  const tagOf = (node) => (node instanceof Element ? DOM.tagName.call(node) : "");

  const F = NuvoriFields;
  const ACTIVATION_DELAY_MS = 400;
  const BLUR_CLOSE_MS = 150;
  const LOADING_DELAY_MS = 250;
  const FEEDBACK_MS = 2500;
  const SVG_NS = "http://www.w3.org/2000/svg";
  const now = () => performance.now();
  const send = async (message) => {
    try { return await chrome.runtime.sendMessage(message); }
    catch { return { status: "offline" }; } // Extension reloaded or service worker unavailable.
  };

  // ---------------------------------------------------------------------------
  // Small DOM helpers (no innerHTML: everything is text or static SVG geometry)

  const ICONS = {
    key: [["circle", { cx: "7.5", cy: "15.5", r: "5.5" }], ["path", { d: "m21 2-9.6 9.6" }], ["path", { d: "m15.5 7.5 3 3L22 7l-3-3" }]],
    lock: [["rect", { width: "18", height: "11", x: "3", y: "11", rx: "2" }], ["path", { d: "M7 11V7a5 5 0 0 1 10 0v4" }]],
    alert: [["circle", { cx: "12", cy: "12", r: "10" }], ["path", { d: "M12 8v4" }], ["path", { d: "M12 16h.01" }]],
    info: [["circle", { cx: "12", cy: "12", r: "10" }], ["path", { d: "M12 16v-4" }], ["path", { d: "M12 8h.01" }]],
    check: [["path", { d: "M20 6 9 17l-5-5" }]],
    clock: [["circle", { cx: "12", cy: "12", r: "10" }], ["path", { d: "M12 6v6l4 2" }]],
    loader: [["path", { d: "M21 12a9 9 0 1 1-6.219-8.56" }]],
    card: [["rect", { width: "20", height: "14", x: "2", y: "5", rx: "2" }], ["path", { d: "M2 10h20" }]],
    user: [["circle", { cx: "12", cy: "8", r: "4" }], ["path", { d: "M4 21a8 8 0 0 1 16 0" }]],
    list: [["path", { d: "M8 6h13" }], ["path", { d: "M8 12h13" }], ["path", { d: "M8 18h13" }], ["path", { d: "M3 6h.01" }], ["path", { d: "M3 12h.01" }], ["path", { d: "M3 18h.01" }]],
  };
  // What each list holds: icon, heading and the empty-list text.
  const KINDS = {
    login: { icon: "key", label: "Logins" },
    card: { icon: "card", label: "Cards", empty: "No saved cards. Pay with a new card and Nuvori will offer to save it." },
    profile: { icon: "user", label: "Addresses", empty: "No saved addresses yet." },
    code: { icon: "clock", label: "Authenticator codes", empty: "No code matches this site." },
  };
  const TONE_ICON = { success: "check", info: "info", progress: "loader", warning: "lock", error: "alert", neutral: "info" };

  function el(tag, props = {}, ...children) {
    const node = DOM.createElement.call(doc, tag);
    for (const [key, value] of Object.entries(props)) {
      if (value === undefined || value === null || value === false) continue;
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else node.setAttribute(key, value === true ? "" : String(value));
    }
    for (const child of children) if (child) node.append(child);
    return node;
  }

  function icon(name, extra = "") {
    const svg = DOM.createElementNS.call(doc, SVG_NS, "svg");
    for (const [key, value] of Object.entries({ viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": "2", "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", class: extra })) svg.setAttribute(key, value);
    for (const [tag, attrs] of ICONS[name] || []) {
      const shape = DOM.createElementNS.call(doc, SVG_NS, tag);
      for (const [key, value] of Object.entries(attrs)) shape.setAttribute(key, value);
      svg.append(shape);
    }
    return svg;
  }

  // ---------------------------------------------------------------------------
  // Styles (tokens shared with the Windows app and the Android app)

  const LIGHT = "--bg:#FFFFFF;--surface2:#E7EDE4;--hover:#DDE5DA;--text:#181D17;--muted:#424940;--hairline:#D3DBD0;--primary:#2E7034;--on-primary:#FFFFFF;--pc:#B9F3B9;--opc:#08210A;--s-c:#D7F5DB;--s-t:#0B3D16;--s-a:#1E7A33;--i-c:#DCEBFF;--i-t:#0F2F4F;--i-a:#225F99;--w-c:#FFF0CC;--w-t:#4A3000;--w-a:#8A5300;--e-c:#FFDAD6;--e-t:#410002;--e-a:#B3261E;--shadow:0 8px 24px rgba(10,20,10,.16);color-scheme:light;";
  const DARK = "--bg:#0C100C;--surface2:#192019;--hover:#202A20;--text:#F0F4ED;--muted:#BEC9BB;--hairline:#2A332A;--primary:#78D47B;--on-primary:#09210B;--pc:#173B1B;--opc:#B9F3B9;--s-c:#12321A;--s-t:#C8F5CF;--s-a:#7DDB86;--i-c:#152D43;--i-t:#DAEDFF;--i-a:#9DCEFF;--w-c:#3A2A00;--w-t:#FFE3A3;--w-a:#FFC94D;--e-c:#410E0B;--e-t:#FFDAD6;--e-a:#FFB4AB;--shadow:0 8px 24px rgba(0,0,0,.45);color-scheme:dark;";
  const STYLE = `
:host{all:initial}
*{box-sizing:border-box}
.nv{${LIGHT}font:400 13px/1.4 "Segoe UI Variable","Segoe UI",system-ui,sans-serif;color:var(--text);text-align:start;letter-spacing:normal;text-transform:none;-webkit-font-smoothing:antialiased}
.nv[data-theme="dark"]{${DARK}}
@media (prefers-color-scheme:dark){.nv[data-theme="system"]{${DARK}}}
.panel{background:var(--bg);border:1px solid var(--hairline);border-radius:12px;box-shadow:var(--shadow);overflow:hidden auto;max-height:calc(100vh - 32px);animation:nv-in 140ms ease-out}
@keyframes nv-in{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}
.head{display:flex;align-items:center;gap:8px;height:32px;padding:0 12px;border-bottom:1px solid var(--hairline);color:var(--muted);font-size:12px}
.brand{color:var(--text);font-weight:600}
.kind{padding:1px 8px;border-radius:999px;background:var(--surface2);color:var(--muted);font-size:11px;font-weight:600}
.kind:empty{display:none}
.foot .link+.link{margin-inline-start:auto}
.input.inline{min-height:28px;padding:4px 8px;max-width:60%;text-align:end}
.host{margin-inline-start:auto;max-width:60%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.mark,.avatar{display:inline-grid;place-items:center;flex:none;background:var(--pc);color:var(--opc)}
.mark{width:20px;height:20px;border-radius:6px}.mark svg{width:12px;height:12px}
.avatar{width:32px;height:32px;border-radius:8px}.avatar svg{width:16px;height:16px}
.list{list-style:none;margin:0;padding:4px 0;max-height:240px;overflow-y:auto}
.option{display:flex;align-items:center;gap:12px;min-height:52px;padding:8px 12px;cursor:pointer;outline:none}
.option:hover,.option[aria-selected="true"]{background:var(--hover)}
.option:focus-visible{box-shadow:inset 0 0 0 2px var(--primary)}
.text{display:grid;gap:2px;min-width:0}
.tag{margin-inline-start:auto;flex:none}
.title,.sub{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.title{font-size:13px;font-weight:600}.sub{font-size:12px;color:var(--muted)}
.state{display:flex;gap:10px;align-items:flex-start;margin:8px;padding:10px 12px;border-radius:8px;background:var(--c);color:var(--t);font-size:13px;line-height:1.4}
.state svg{width:16px;height:16px;flex:none;margin-top:1px;color:var(--a)}
.state .btn{margin-top:8px}
[data-tone="success"]{--c:var(--s-c);--t:var(--s-t);--a:var(--s-a)}
[data-tone="info"],[data-tone="progress"]{--c:var(--i-c);--t:var(--i-t);--a:var(--i-a)}
[data-tone="warning"]{--c:var(--w-c);--t:var(--w-t);--a:var(--w-a)}
[data-tone="error"]{--c:var(--e-c);--t:var(--e-t);--a:var(--e-a)}
[data-tone="neutral"]{--c:var(--surface2);--t:var(--text);--a:var(--muted)}
.spin{animation:nv-spin 900ms linear infinite}@keyframes nv-spin{to{transform:rotate(360deg)}}
.foot{display:flex;align-items:center;border-top:1px solid var(--hairline);padding:4px}
.link,.btn{all:unset;box-sizing:border-box;font:inherit;cursor:pointer}
.link{font-size:12px;color:var(--muted);padding:6px 8px;border-radius:8px}
.link:hover{background:var(--hover);color:var(--text)}
.link:focus-visible,.btn:focus-visible{outline:2px solid var(--primary);outline-offset:2px}
.card{padding:12px 16px 16px}
.card h2{margin:0;font-size:15px;font-weight:600;line-height:1.35;overflow-wrap:anywhere}
.desc{margin:4px 0 0;color:var(--muted);font-size:13px}
.fields{margin:12px 0 0;padding:0;border:1px solid var(--hairline);border-radius:8px}
.fields div{display:flex;justify-content:space-between;gap:12px;padding:8px 12px}
.fields div+div{border-top:1px solid var(--hairline)}
.fields dt{color:var(--muted);font-size:12px}.fields dd{margin:0;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.card .state{margin:12px 0 0}
.actions{display:flex;flex-wrap:wrap;align-items:center;gap:8px;margin-top:12px}
.name{display:grid;gap:4px;margin-top:12px;color:var(--muted);font-size:12px}
.name-row{display:flex;justify-content:space-between;gap:8px}
.name-host{color:var(--text);font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.input{all:unset;box-sizing:border-box;width:100%;min-height:32px;padding:6px 10px;border:1px solid var(--hairline);border-radius:8px;background:var(--surface2);color:var(--text);font:inherit;font-size:13px;cursor:text}
.input:focus-visible{outline:2px solid var(--primary);outline-offset:1px}
.choices{margin-top:12px;border:1px solid var(--hairline);border-radius:8px;overflow:hidden}
.choice{display:flex;align-items:center;gap:10px;padding:8px 12px;cursor:pointer;outline:none}
.choice+.choice{border-top:1px solid var(--hairline)}
.choice:hover{background:var(--hover)}
.choice:focus-visible{box-shadow:inset 0 0 0 2px var(--primary)}
.dot{width:14px;height:14px;flex:none;border:2px solid var(--muted);border-radius:999px}
.choice[aria-checked="true"] .dot{border-color:var(--primary);background:var(--primary);box-shadow:inset 0 0 0 2px var(--bg)}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:6px;min-height:32px;padding:6px 14px;border:1px solid var(--hairline);border-radius:8px;color:var(--text);font-size:13px;font-weight:600}
.btn:hover{background:var(--hover)}
.btn.primary{background:var(--primary);border-color:var(--primary);color:var(--on-primary)}
.btn.primary:hover{filter:brightness(1.06)}
.btn.quiet{border-color:transparent;color:var(--muted);margin-inline-start:auto}
.btn[aria-disabled="true"]{opacity:.55;cursor:default}
@media (prefers-reduced-motion:reduce){.panel,.spin{animation:none}}
@media (forced-colors:active){.panel{border-color:CanvasText}.btn{border-color:ButtonText}.option[aria-selected="true"]{outline:2px solid Highlight}}
`;

  // ---------------------------------------------------------------------------
  // A protected surface: a host the page cannot restyle, in a closed shadow root.

  const HOST_BASE = "all:initial !important;position:fixed !important;z-index:2147483647 !important;display:block !important;visibility:visible !important;opacity:1 !important;pointer-events:auto !important;transform:none !important;filter:none !important;clip-path:none !important;mask:none !important;mix-blend-mode:normal !important;margin:0 !important;padding:0 !important;border:0 !important;background:transparent !important;overflow:visible !important;inset:auto !important;height:auto !important;max-width:none !important;max-height:none !important;min-width:0 !important;min-height:0 !important;";

  const SURFACES = [];

  function createSurface(label) {
    const host = DOM.createElement.call(doc, "div");
    const root = host.attachShadow({ mode: "closed" });
    const style = DOM.createElement.call(doc, "style");
    style.textContent = STYLE;
    const frame = el("div", { class: "nv", "data-theme": "system", role: "presentation" });
    root.append(style, frame);
    let placement = "";
    let shownAt = Infinity;
    let focusEnteredAt = Infinity;
    let focusInside = false;
    // Activation needs a fresh IntersectionObserver v2 report that the host is fully visible.
    let unobscured = false;
    let shown = false;
    const wanted = () => HOST_BASE + placement;
    const repair = () => {
      let tampered = false;
      if (host.getAttribute("style") !== wanted()) { host.setAttribute("style", wanted()); tampered = true; }
      for (const name of host.getAttributeNames()) {
        if (name !== "style" && name !== "popover") { host.removeAttribute(name); tampered = true; }
      }
      return tampered;
    };
    // Any attempt to restyle the host restarts the activation delay.
    const guard = new MutationObserver(() => { if (repair()) shownAt = now(); });
    let io = null;
    try {
      io = new IntersectionObserver((entries) => {
        if (!shown) return;
        const visible = entries[entries.length - 1].isVisible === true;
        if (visible && !unobscured) shownAt = now();
        unobscured = visible;
      }, { trackVisibility: true, delay: 100, threshold: [1] });
    } catch { io = null; }
    // Keyboard use starts its own delay when focus first enters this surface.
    frame.addEventListener("focusin", () => {
      if (!focusInside) { focusInside = true; focusEnteredAt = now(); }
    });
    frame.addEventListener("focusout", (event) => {
      if (!event.relatedTarget || !frame.contains(event.relatedTarget)) focusInside = false;
    });

    const surface = {
      host, frame, label,
      get shown() { return shown && host.isConnected; },
      setTheme(theme) { frame.setAttribute("data-theme", ["light", "dark"].includes(theme) ? theme : "system"); },
      place(css) {
        if (css === placement) return;
        placement = css;
        host.setAttribute("style", wanted());
        shownAt = now(); // Moving under the pointer restarts the delay.
      },
      resetActivation() { shownAt = now(); },
      /** Something else may now cover us (a popover, dialog or fullscreen change): wait for a fresh report. */
      invalidate() {
        if (!shown) return;
        shownAt = now();
        unobscured = false;
        if (io) { io.unobserve(host); io.observe(host); }
      },
      show() {
        if (!host.isConnected) docRoot().append(host);
        repair();
        if (!shown) {
          shown = true;
          shownAt = now();
          focusEnteredAt = Infinity;
          focusInside = false;
          unobscured = false;
          io?.observe(host);
          guard.observe(host, { attributes: true });
          // The top layer keeps page stacking contexts, transforms and filters from covering us.
          try { host.setAttribute("popover", "manual"); host.showPopover(); } catch { /* still z-index on top */ }
        }
      },
      hide() {
        if (!shown) return;
        shown = false;
        shownAt = Infinity;
        unobscured = false;
        io?.unobserve(host);
        guard.disconnect();
        try { host.hidePopover(); } catch { /* not open */ }
        host.remove();
      },
      /**
       * A trusted event, after the delay, while the IntersectionObserver says we are fully visible
       * and a hit test finds our host. Keyboard activations (keydown, or click with detail 0) also
       * wait out the delay after focus first entered this surface.
       */
      canActivate(event, node) {
        if (!event?.isTrusted || !shown || !host.isConnected || !unobscured) return false;
        const time = now();
        if (time - shownAt < ACTIVATION_DELAY_MS) return false;
        const keyboard = event.type === "keydown" || (event.type === "click" && event.detail === 0);
        if (keyboard && !(time - focusEnteredAt >= ACTIVATION_DELAY_MS)) return false;
        if (DOM.visibilityState.call(doc) !== "visible") return false;
        let x = event.clientX;
        let y = event.clientY;
        if (keyboard) {
          const box = (node || host).getBoundingClientRect();
          x = box.left + box.width / 2;
          y = box.top + box.height / 2;
        }
        if (!Number.isFinite(x) || !Number.isFinite(y)) return false;
        return DOM.elementFromPoint.call(doc, x, y) === host;
      },
      contains(node) { return node === host; },
    };
    SURFACES.push(surface);
    return surface;
  }

  // Another popover, dialog or fullscreen element may now sit above us: until the
  // IntersectionObserver confirms we are visible again (and the delay passes), nothing activates.
  const ours = (node) => SURFACES.some((surface) => surface.host === node);
  const invalidateAll = () => { for (const surface of SURFACES) surface.invalidate(); };
  for (const type of ["beforetoggle", "toggle", "fullscreenchange"]) {
    listen(doc, type, (event) => { if (!ours(event.target)) invalidateAll(); }, true);
  }
  new MutationObserver((records) => {
    if (records.some((record) => !ours(record.target))) invalidateAll();
  }).observe(docRoot(), { attributes: true, attributeFilter: ["open", "popover"], subtree: true });

  // ---------------------------------------------------------------------------
  // Field helpers

  const eventTarget = (event) => event.composedPath()[0] || event.target;
  const isInput = (node) => node instanceof HTMLInputElement;
  const viewport = () => ({ width: window.innerWidth || 0, height: window.innerHeight || 0 });

  function usable(input) {
    if (!input || input.disabled || String(input.type).toLowerCase() === "hidden") return false;
    if (!input.getClientRects().length) return false;
    const style = getComputedStyle(input);
    return style.visibility !== "hidden" && style.display !== "none";
  }

  const onScreen = (rect, view) => {
    const x = rect.left + rect.width / 2;
    const y = rect.top + rect.height / 2;
    return F.boxIsUsable(rect, view) && x >= 0 && x <= view.width && y >= 0 && y <= view.height;
  };

  /** Visible, on screen and hit-testable. Off-screen fields are scrolled into view first when `scroll` is set. */
  function fillable(input, { scroll = false } = {}) {
    if (!input?.isConnected || !usable(input) || input.readOnly) return false;
    // Reject fields hidden by transparency on the field or its ancestors.
    for (let node = input, depth = 0; node && depth < 32; node = DOM.parentElement.call(node), depth++) {
      const opacity = Number.parseFloat(getComputedStyle(node).opacity);
      if (Number.isFinite(opacity) && opacity < 0.1) return false;
    }
    const view = viewport();
    let rect = input.getBoundingClientRect();
    if (!onScreen(rect, view)) {
      if (!scroll) return false;
      input.scrollIntoView({ block: "nearest", inline: "nearest" });
      rect = input.getBoundingClientRect();
      if (!onScreen(rect, view)) return false;
    }
    const hit = elementAt(rootOf(input), rect.left + rect.width / 2, rect.top + rect.height / 2);
    return hit === input || (hit instanceof HTMLLabelElement && hit.control === input);
  }

  // Every input of the field's document or shadow root: the classifier picks the
  // credential form itself, and with several such forms only the focused one counts.
  function scopeInputs(field) {
    const list = inputsIn(rootOf(field));
    return list.includes(field) ? list : [...list, field];
  }
  const CLASSIFY = { live: (input) => usable(input), groupOf: (input) => input.form || null };

  /** Label text for a field, for card, address and code detection. Never a value. */
  function labelOf(input) {
    try {
      const parts = [];
      for (const label of input.labels || []) parts.push(String(label.textContent || ""));
      return parts.join(" ").replace(/\s+/g, " ").trim().slice(0, 120);
    } catch { return ""; }
  }
  const DETAILS = { labelOf, live: (input) => usable(input) };

  /** The field's form controls, or the formless controls around it. */
  function controlsFor(field) {
    const form = field.form;
    if (form instanceof HTMLFormElement) {
      const list = controlsIn(form);
      return list.includes(field) ? list : [...list, field];
    }
    const list = controlsIn(rootOf(field)).filter((control) => !control.form);
    return list.includes(field) ? list : [...list, field];
  }

  function fillTargets(field) {
    const pair = F.pairFields(field, scopeInputs(field), CLASSIFY);
    return {
      username: pair.username && fillable(pair.username, { scroll: true }) ? pair.username : null,
      password: pair.password && fillable(pair.password, { scroll: true }) ? pair.password : null,
    };
  }

  const setterOf = (type) => {
    try { return typeof type === "function" ? Object.getOwnPropertyDescriptor(type.prototype, "value")?.set : undefined; } catch { return undefined; }
  };
  const valueSetter = setterOf(globalThis.HTMLInputElement);
  const selectSetter = setterOf(globalThis.HTMLSelectElement);
  const areaSetter = setterOf(globalThis.HTMLTextAreaElement);

  // Works with React/Vue-controlled inputs: use the native setter, then announce the change.
  let fillCount = 0;
  function setValue(input, value) {
    fillCount++;
    input.focus?.({ preventScroll: true });
    const setter = typeof HTMLSelectElement === "function" && input instanceof HTMLSelectElement ? selectSetter
      : typeof HTMLTextAreaElement === "function" && input instanceof HTMLTextAreaElement ? areaSetter : valueSetter;
    if (setter) setter.call(input, value);
    else input.value = value;
    input.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
    input.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
  }

  function deepActive() {
    let active = DOM.activeElement.call(doc);
    for (let depth = 0; active instanceof Element && depth < 32; depth++) {
      const shadow = DOM.shadowRoot.call(active);
      const inner = shadow ? DOM.shadowActiveElement.call(shadow) : null;
      if (!inner) break;
      active = inner;
    }
    return active;
  }

  // ---------------------------------------------------------------------------
  // Inline suggestions dropdown

  let theme = "system";
  let suggestionsOff = false;
  let filling = false;
  let focusedField = null;
  let dismissedField = null;

  const dropdown = {
    surface: null, panel: null, body: null, hostLabel: null, kindLabel: null, showAll: null, field: null, open: false,
    kind: "login", accounts: [], options: [], active: -1, requestId: 0, loadingTimer: 0, blurTimer: 0, frame: 0,
  };

  function ensureDropdown() {
    if (dropdown.surface) return;
    const surface = createSurface("Nuvori suggestions");
    dropdown.hostLabel = el("span", { class: "host" });
    dropdown.kindLabel = el("span", { class: "kind" });
    dropdown.body = el("div");
    // Codes: the list first shows codes that match this site; this lists every code.
    const showAll = el("button", { class: "link", type: "button", text: "Show all codes", hidden: true, onclick: (event) => {
      if (!surface.canActivate(event, showAll)) return;
      void openItems(dropdown.field, "code", { all: true, force: true });
    } });
    dropdown.showAll = showAll;
    const dontSuggest = el("button", { class: "link", type: "button", text: "Don't suggest on this site", onclick: (event) => {
      if (!surface.canActivate(event, dontSuggest)) return;
      suggestionsOff = true;
      closeDropdown();
      void send({ action: "inline_dont_suggest" });
    } });
    dropdown.panel = el("div", { class: "panel", role: "dialog", "aria-label": "Nuvori saved logins" },
      el("div", { class: "head" }, el("span", { class: "mark" }, icon("key")), el("span", { class: "brand", text: "Nuvori" }), dropdown.kindLabel, dropdown.hostLabel),
      dropdown.body,
      el("div", { class: "foot" }, dontSuggest, showAll));
    // Keep focus in the page field while the pointer is used on the list.
    dropdown.panel.addEventListener("mousedown", (event) => event.preventDefault());
    dropdown.panel.addEventListener("keydown", onListKey);
    surface.frame.append(dropdown.panel);
    dropdown.surface = surface;
  }

  function renderState(tone, text, action) {
    const box = el("div", { class: "state", "data-tone": tone, role: "status" }, icon(tone === "warning" ? "lock" : TONE_ICON[tone], tone === "progress" ? "spin" : ""));
    const copy = el("div", {}, el("div", { text }));
    if (action) copy.append(action);
    box.append(copy);
    dropdown.options = [];
    dropdown.accounts = [];
    dropdown.active = -1;
    dropdown.body.replaceChildren(box);
  }

  function renderAccounts(accounts) {
    const list = el("ul", { class: "list", role: "listbox", "aria-label": "Saved logins for this site" });
    dropdown.accounts = accounts;
    dropdown.options = accounts.map((account, index) => {
      const option = el("li", { class: "option", role: "option", tabindex: "-1", "aria-selected": "false", id: `nuvori-option-${index}` },
        el("span", { class: "avatar" }, icon("key")),
        el("span", { class: "text" },
          el("span", { class: "title", text: account.title || account.username || "Saved login" }),
          el("span", { class: "sub", text: account.username || "No username" })));
      // The account name used on the previous page of this sign-in.
      if (account.recent) option.append(el("span", { class: "kind tag", text: "Continue" }));
      // Saved for another page of this site, such as login.example.com on www.example.com.
      else if (account.related) option.append(el("span", { class: "kind tag", text: "Same site" }));
      option.addEventListener("click", (event) => {
        if (!dropdown.surface.canActivate(event, option)) return;
        void choose(account);
      });
      option.addEventListener("mousemove", () => highlight(index, false));
      list.append(option);
      return option;
    });
    dropdown.active = -1;
    dropdown.body.replaceChildren(list);
  }

  function renderItems(kind, items) {
    const list = el("ul", { class: "list", role: "listbox", "aria-label": `Saved ${KINDS[kind].label.toLowerCase()}` });
    dropdown.accounts = items;
    dropdown.options = items.map((item, index) => {
      const option = el("li", { class: "option", role: "option", tabindex: "-1", "aria-selected": "false", id: `nuvori-option-${index}` },
        el("span", { class: "avatar" }, icon(KINDS[kind].icon)),
        el("span", { class: "text" },
          el("span", { class: "title", text: item.title || item.subtitle || KINDS[kind].label }),
          el("span", { class: "sub", text: item.subtitle || "" })));
      option.addEventListener("click", (event) => {
        if (!dropdown.surface.canActivate(event, option)) return;
        void chooseItem(item);
      });
      option.addEventListener("mousemove", () => highlight(index, false));
      list.append(option);
      return option;
    });
    dropdown.active = -1;
    dropdown.body.replaceChildren(list);
  }

  function renderResponse(response) {
    const status = response?.status;
    const kind = dropdown.kind;
    if (kind !== "login" && status === "ok" && response.items?.length) return renderItems(kind, response.items);
    if (kind !== "login" && status === "ok") return renderState("info", KINDS[kind].empty);
    if (status === "ok" && response.accounts?.length) return renderAccounts(response.accounts);
    if (status === "ok") return renderState("info", "No saved login for this site. Sign in and Nuvori will offer to save it.");
    if (status === "locked") return renderState("warning", "Nuvori is locked. Unlock it to fill this site.", unlockButton("Unlock Nuvori"));
    if (status === "missing") return renderState("neutral", response.message || "This login is no longer available for this site.");
    if (status === "offline") return renderState("error", "Nuvori for Windows isn't running.", unlockButton("Start Nuvori"));
    if (status === "host_missing") {
      const help = el("button", { class: "btn", type: "button", text: "Setup help", onclick: async (event) => {
        if (!dropdown.surface.canActivate(event, help)) return;
        const result = await send({ action: "open_popup" });
        if (result?.status !== "ok") renderState("error", "Click the Nuvori icon in the browser toolbar for setup help.");
      } });
      return renderState("error", "Can't reach Nuvori for Windows. Open the app, or open the extension for setup help.", help);
    }
    return renderState("error", response?.message || "Nuvori couldn't finish that. Try again.");
  }

  /** Asks Nuvori to show its own unlock window. The password is typed there, never in the page. */
  function unlockButton(label) {
    const button = el("button", { class: "btn", type: "button", text: label, onclick: async (event) => {
      if (!dropdown.surface.canActivate(event, button)) return;
      const result = await send({ action: "inline_unlock" });
      if (["ok", "locked", "starting"].includes(result?.status)) {
        renderState("info", "Enter your master password in the Nuvori window, then click this field again.");
      } else {
        renderState("error", "Couldn't open Nuvori. Start it from the Windows Start menu, or open the extension for setup help.");
      }
    } });
    return button;
  }

  function highlight(index, focus) {
    dropdown.options.forEach((option, position) => option.setAttribute("aria-selected", String(position === index)));
    dropdown.active = index;
    if (focus) dropdown.options[index]?.focus({ preventScroll: false });
  }

  /** The field's box in this page when the field is inside a frame: the frame's box plus the field's. */
  function frameFieldRect(target) {
    const box = target.element.getBoundingClientRect();
    const left = box.left + (target.element.clientLeft || 0) + target.rect.left;
    const top = box.top + (target.element.clientTop || 0) + target.rect.top;
    return { left, top, width: target.rect.width, height: target.rect.height, right: left + target.rect.width, bottom: top + target.rect.height };
  }

  function position() {
    const field = dropdown.field;
    if (!dropdown.open || !field) return;
    const view = viewport();
    const rect = dropdown.frameTarget ? frameFieldRect(dropdown.frameTarget) : field.getBoundingClientRect();
    if (!field.isConnected || !F.boxIsUsable(rect, view) || rect.bottom < 0 || rect.top > view.height) { closeDropdown(); return; }
    const height = dropdown.panel.getBoundingClientRect?.().height || 160;
    const place = F.placeDropdown(rect, { height }, view);
    dropdown.surface.place(`top:${place.top}px !important;left:${place.left}px !important;width:${place.width}px !important;`);
  }

  function track() {
    if (!dropdown.open) return;
    position();
    if (typeof requestAnimationFrame === "function") dropdown.frame = requestAnimationFrame(track);
  }

  function showDropdown(field, render) {
    ensureDropdown();
    dropdown.field = field;
    dropdown.surface.setTheme(theme);
    dropdown.hostLabel.textContent = location.host;
    dropdown.kindLabel.textContent = dropdown.kind === "login" ? "" : KINDS[dropdown.kind].label;
    if (dropdown.kind === "code" && !dropdown.allCodes) dropdown.showAll.removeAttribute("hidden");
    else dropdown.showAll.setAttribute("hidden", "");
    render();
    dropdown.surface.show();
    if (!dropdown.open) {
      dropdown.open = true;
      track();
    } else position();
  }

  function closeDropdown({ refocus = false } = {}) {
    clearTimeout(dropdown.loadingTimer);
    clearTimeout(dropdown.blurTimer);
    dropdown.requestId++;
    if (typeof cancelAnimationFrame === "function") cancelAnimationFrame(dropdown.frame);
    const wasOpen = dropdown.open;
    dropdown.open = false;
    dropdown.options = [];
    dropdown.active = -1;
    dropdown.surface?.hide();
    if (refocus && wasOpen && dropdown.field?.isConnected) dropdown.field.focus({ preventScroll: true });
  }

  async function openFor(field, { force = false } = {}) {
    if (suggestionsOff || filling || !field?.isConnected) return;
    dropdown.frameTarget = null;
    const kind = F.suggestionKind(field, scopeInputs(field), CLASSIFY);
    if (!kind) {
      const detail = usable(field) ? F.detailKind(field, controlsFor(field), DETAILS) : null;
      if (detail) await openItems(field, detail, { force });
      return;
    }
    if (!usable(field)) return;
    dropdown.kind = "login";
    // An identifier-first page could just be a newsletter box: stay quiet unless there is a login to offer.
    const quiet = kind === "username-step";
    dropdown.field = field;
    const request = ++dropdown.requestId;
    clearTimeout(dropdown.loadingTimer);
    dropdown.loadingTimer = setTimeout(() => {
      if (!quiet && request === dropdown.requestId && focusedField === field) showDropdown(field, () => renderState("progress", "Checking Nuvori…"));
    }, LOADING_DELAY_MS);
    const response = await send({ action: "inline_query" });
    clearTimeout(dropdown.loadingTimer);
    if (request !== dropdown.requestId || dropdown.field !== field) return;
    if (!force && focusedField !== field) return;
    if (["light", "dark", "system"].includes(response?.theme)) theme = response.theme;
    if (response?.status === "disabled") { suggestionsOff = true; closeDropdown(); return; }
    // Nothing to offer is not worth a popup. An identifier-first page stays quiet in every state;
    // a sign-in form stays quiet when no login is saved, until the user asks (click or the Down key).
    const hasAccounts = response?.status === "ok" && response.accounts?.length > 0;
    if (!hasAccounts && (quiet || (!force && response?.status === "ok"))) { closeDropdown(); return; }
    showDropdown(field, () => renderResponse(response));
  }

  /**
   * Cards, addresses and codes. "profile" and "code-weak" (a code box without authenticator
   * wording) stay quiet unless there is something to offer; cards and codes also show
   * locked or offline states so the user can unlock from here.
   */
  async function openItems(field, detail, { all = false, force = false, frame = undefined } = {}) {
    const kind = detail === "code-weak" ? "code" : detail;
    const quiet = detail === "code-weak" || detail === "profile";
    if (frame !== undefined) dropdown.frameTarget = frame;
    dropdown.field = field;
    const request = ++dropdown.requestId;
    clearTimeout(dropdown.loadingTimer);
    const response = await send({ action: "inline_items", kind, all });
    if (request !== dropdown.requestId || dropdown.field !== field) return;
    if (!force && focusedField !== field) return;
    if (["light", "dark", "system"].includes(response?.theme)) theme = response.theme;
    if (response?.status === "disabled" || response?.status === "unsupported") { closeDropdown(); return; }
    const hasItems = response?.status === "ok" && response.items?.length > 0;
    if (!hasItems && (quiet || (kind === "card" && response?.status === "ok"))) { closeDropdown(); return; }
    dropdown.kind = kind;
    dropdown.allCodes = all;
    if (kind === "code" && response?.status === "ok" && !hasItems && !all) {
      showDropdown(field, () => renderState("info", "No code matches this site. Choose Show all codes to pick one."));
      return;
    }
    showDropdown(field, () => renderResponse(response));
  }

  /** Fill the picked card, address or code. Only visible, hit-testable fields of this form are filled. */
  async function chooseItem(item) {
    const field = dropdown.field;
    const kind = dropdown.kind;
    if (!field?.isConnected || !item) return;
    const frame = dropdown.frameTarget;
    closeDropdown(); // Remove our UI before checking what is visible on the page.
    if (frame) {
      const result = await send({ action: "inline_fill_frame", kind, id: item.id, frameId: frame.frameId });
      if (result?.status !== "ok") { showDropdown(field, () => renderResponse(result)); return; }
      notice("success", result.codeLeft ? "Card filled. Enter the security code yourself." : "Filled.");
      return;
    }
    const response = await send({ action: "inline_fill_item", kind, id: item.id });
    if (response?.status !== "ok") {
      showDropdown(field, () => renderResponse(response));
      return;
    }
    filling = true;
    let codeField = null;
    try {
      if (kind === "card" && response.card) codeField = fillCard(field, response.card);
      else if (kind === "profile" && response.profile) fillProfile(field, response.profile);
      else if (kind === "code" && response.code) fillCode(field, response.code);
      dismissedField = focusedField;
    } finally {
      for (const key of Object.keys(response)) response[key] = undefined;
      filling = false;
    }
    if (codeField) void fillCardCode(item.id, codeField);
  }

  const fillableControl = (control) => control && fillable(control, { scroll: true }) ? control : null;
  const isSelect = (control) => typeof HTMLSelectElement === "function" && control instanceof HTMLSelectElement;

  /** Choose a drop-down option by any of `choices`, or type the first choice into a text field. */
  function setChoice(control, choices) {
    if (!control) return;
    if (isSelect(control)) {
      const value = F.optionValue(control, choices);
      if (value !== null) setValue(control, value);
    } else if (choices[0]) setValue(control, choices[0]);
  }

  /** Fills number, name and expiry. Returns the security-code field when the card has a saved code. */
  function fillCard(field, card) {
    return fillCardInto(controlsFor(field), card);
  }

  function fillCardInto(controls, card) {
    const { card: parts } = F.detailFields(controls, DETAILS);
    const numbers = parts.number.map(fillableControl).filter(Boolean);
    if (numbers.length > 1) {
      // A number split across boxes: give each box as many digits as it takes (4 by default).
      let rest = card.number;
      for (const box of numbers) {
        const size = box.maxLength > 0 ? box.maxLength : 4;
        setValue(box, rest.slice(0, size));
        rest = rest.slice(size);
      }
    } else if (numbers[0]) setValue(numbers[0], card.number);
    const name = fillableControl(parts.name);
    if (name && card.name) setValue(name, card.name);
    const [month, year] = String(card.expiry || "").split("/");
    if (month && year) {
      const exp = fillableControl(parts.exp);
      if (exp) setValue(exp, F.expiryText(exp, card.expiry));
      const monthField = fillableControl(parts.expMonth);
      setChoice(monthField, F.monthChoices(month));
      const yearField = fillableControl(parts.expYear);
      if (yearField && !isSelect(yearField) && (yearField.maxLength === 2)) setValue(yearField, year);
      else setChoice(yearField, F.yearChoices(year));
    }
    card.number = "";
    return card.hasCode ? fillableControl(parts.cvv) : null;
  }

  function fillProfile(field, profile) {
    fillProfileInto(controlsFor(field), profile);
  }

  function fillProfileInto(controls, profile) {
    const { profile: parts } = F.detailFields(controls, DETAILS);
    const words = String(profile.name || "").trim().split(/\s+/).filter(Boolean);
    const values = {
      ...profile,
      given: words.length > 1 ? words.slice(0, -1).join(" ") : words[0] || "",
      family: words.length > 1 ? words[words.length - 1] : "",
    };
    for (const [role, control] of Object.entries(parts)) {
      const value = String(values[role] || "");
      const target = value && fillableControl(control);
      if (!target) continue;
      if (isSelect(target)) setChoice(target, [value]);
      else setValue(target, value);
    }
  }

  function fillCode(field, code) {
    const boxes = F.codeBoxes(field, controlsFor(field), (control) => usable(control)).map(fillableControl);
    if (boxes.length && boxes.every(Boolean) && boxes.length === code.value.length) {
      boxes.forEach((box, index) => setValue(box, code.value[index]));
    } else {
      const target = fillableControl(field);
      if (target) setValue(target, code.value);
    }
    const left = Number(code.secondsLeft) || 0;
    notice("success", left > 0 ? `Code filled. It changes in ${left} s.` : "Code filled.");
  }

  /** The security code waits for approval in a Nuvori window (Windows Hello or master password). */
  async function fillCardCode(id, codeField) {
    notice("progress", "Approve the security code in the Nuvori window.", undefined, { sticky: true });
    const result = await send({ action: "inline_card_code", id });
    if (result?.status === "ok" && typeof result.code === "string") {
      hideCard(); // Remove our notice before checking what is visible on the page.
      const target = fillableControl(codeField);
      filling = true;
      try { if (target) setValue(target, result.code); } finally { result.code = ""; filling = false; }
      notice(target ? "success" : "neutral", target ? "Security code filled." : "Couldn't find the security code field. Enter it yourself.");
    } else if (result?.status === "denied") {
      notice("neutral", "Security code not filled.");
    } else if (result?.status === "locked") {
      notice("warning", "Nuvori is locked. Unlock it, then choose the card again.");
    } else {
      notice("neutral", "Approval timed out. Choose the card again to fill the security code.");
    }
  }

  async function choose(account) {
    const field = dropdown.field;
    if (!field?.isConnected || !account) return;
    closeDropdown(); // Remove our UI before checking what is visible on the page.
    const before = fillTargets(field);
    if (!before.username && !before.password) {
      showDropdown(field, () => renderState("error", "No visible sign-in field to fill."));
      return;
    }
    const response = await send({ action: "inline_fill", credentialId: account.id, want: before.password ? "both" : "username" });
    if (response?.status !== "ok") {
      showDropdown(field, () => renderResponse(response));
      return;
    }
    let password = typeof response.password === "string" ? response.password : "";
    response.password = undefined;
    filling = true;
    try {
      const after = fillTargets(field);
      if (after.username && typeof response.username === "string" && response.username) setValue(after.username, response.username);
      if (after.password && password) setValue(after.password, password);
      (after.password || after.username)?.focus?.({ preventScroll: true });
      dismissedField = focusedField;
    } finally {
      password = "";
      filling = false;
    }
  }

  function onListKey(event) {
    if (!event.isTrusted) return;
    const count = dropdown.options.length;
    const field = dropdown.field;
    switch (event.key) {
      case "ArrowDown":
        if (count) highlight(Math.min(dropdown.active + 1, count - 1), true);
        break;
      case "ArrowUp":
        if (dropdown.active <= 0) { highlight(-1, false); field?.focus({ preventScroll: true }); }
        else highlight(dropdown.active - 1, true);
        break;
      case "Home": if (count) highlight(0, true); break;
      case "End": if (count) highlight(count - 1, true); break;
      case "Enter":
        if (dropdown.active >= 0 && dropdown.surface.canActivate(event, dropdown.options[dropdown.active])) {
          if (dropdown.kind === "login") void choose(dropdown.accounts[dropdown.active]);
          else void chooseItem(dropdown.accounts[dropdown.active]);
        }
        break;
      case "Escape":
      case "Tab":
        dismissedField = field;
        closeDropdown({ refocus: true });
        break;
      default:
        return;
    }
    event.preventDefault();
    event.stopPropagation();
  }

  // ---------------------------------------------------------------------------
  // Save / update card

  const card = { surface: null, prompt: null, busy: false, hideTimer: 0, body: null, nameInput: null, usernameInput: null, choice: null, updateButton: null };

  function ensureCard() {
    if (card.surface) return;
    const surface = createSurface("Nuvori save prompt");
    card.body = el("div", { class: "card" });
    const panel = el("div", { class: "panel", role: "dialog", "aria-label": "Nuvori" },
      el("div", { class: "head" }, el("span", { class: "mark" }, icon("key")), el("span", { class: "brand", text: "Nuvori" }), el("span", { class: "host", text: location.host })),
      card.body);
    panel.addEventListener("keydown", (event) => {
      if (event.isTrusted && event.key === "Escape") { event.stopPropagation(); hideCard(); }
    });
    surface.frame.append(panel);
    surface.place("top:16px !important;right:16px !important;width:min(352px, calc(100vw - 32px)) !important;");
    card.surface = surface;
  }

  function cardButton(text, decision, kind = "") {
    const button = el("button", { class: `btn ${kind}`.trim(), type: "button", text, "data-decision": decision, onclick: (event) => {
      if (card.busy || !card.surface.canActivate(event, button)) return;
      if (decision === "open") { void send({ action: "open_popup" }); return; }
      void decide(decision);
    } });
    return button;
  }

  function nameField(prompt) {
    // Shown only when the host supports "login_title". The page can't read the field's value
    // (closed shadow root), but keystrokes typed here still pass through the page's capture-phase
    // key listeners. That is acceptable for a name, which is not a secret.
    // The prefill (og:site_name or host) is only a hint; the real host is always shown beside it.
    const input = el("input", { class: "input", type: "text", maxlength: "200", autocomplete: "off", spellcheck: "false", "aria-label": `Name for ${prompt.host}` });
    input.value = prompt.title || prompt.host;
    input.addEventListener("keydown", (event) => {
      if (event.key !== "Enter") return;
      event.preventDefault();
      if (!card.busy && card.surface.canActivate(event, input)) void decide("save");
    });
    card.nameInput = input;
    return el("label", { class: "name" },
      el("span", { class: "name-row" }, el("span", { text: "Name" }), el("span", { class: "name-host", text: prompt.host })),
      input);
  }

  function choiceList(prompt) {
    const rows = prompt.choices.map((choice) => {
      const row = el("div", { class: "choice", role: "radio", tabindex: "0", "aria-checked": "false", "data-choice": choice.id },
        el("span", { class: "dot" }),
        el("span", { class: "text" },
          el("span", { class: "title", text: choice.title || prompt.host }),
          el("span", { class: "sub", text: choice.username || "No username" })));
      const pick = (event) => {
        if (card.busy || !card.surface.canActivate(event, row)) return;
        card.choice = choice.id;
        for (const other of rows) other.setAttribute("aria-checked", String(other === row));
        card.updateButton?.setAttribute("aria-disabled", "false");
        card.surface.resetActivation(); // Update needs its own deliberate click.
      };
      row.addEventListener("click", pick);
      row.addEventListener("keydown", (event) => {
        if (event.key !== " " && event.key !== "Enter") return;
        event.preventDefault();
        pick(event);
      });
      return row;
    });
    return el("div", { class: "choices", role: "radiogroup", "aria-label": "Saved accounts" }, ...rows);
  }

  /** "login_edit": the captured username, editable before saving. Like the name, not a secret. */
  function usernameField(prompt) {
    const input = el("input", { class: "input inline", type: "text", maxlength: "1024", autocomplete: "off", spellcheck: "false", "aria-label": "Username", placeholder: "No username" });
    input.value = prompt.username || "";
    input.addEventListener("keydown", (event) => {
      if (event.key !== "Enter") return;
      event.preventDefault();
      if (!card.busy && card.surface.canActivate(event, input)) void decide("save");
    });
    card.usernameInput = input;
    return input;
  }

  function renderCard(note) {
    const prompt = card.prompt;
    const nodes = [];
    card.nameInput = null;
    card.usernameInput = null;
    card.choice = null;
    card.updateButton = null;
    if (prompt.kind === "save_card" || prompt.kind === "save_profile") {
      const isCard = prompt.kind === "save_card";
      nodes.push(el("h2", { text: isCard ? "Save this card to Nuvori?" : "Save this address to Nuvori?" }));
      if (prompt.canTitle) nodes.push(nameField(prompt));
      const rows = (Array.isArray(prompt.summary) ? prompt.summary : []).slice(0, 5);
      if (rows.length) nodes.push(el("dl", { class: "fields" }, ...rows.map(([label, value]) => el("div", {}, el("dt", { text: String(label) }), el("dd", { text: String(value) })))));
      if (isCard) nodes.push(el("p", { class: "desc", text: "The security code is never saved from a page." }));
      if (prompt.locked) nodes.push(stateBox("warning", "Nuvori is locked. Save opens its unlock window."));
      nodes.push(el("div", { class: "actions" }, cardButton("Save", "save", "primary"), cardButton("Not now", "dismiss"), cardButton("Never for this site", "never", "quiet")));
    } else if (prompt.kind === "save") {
      nodes.push(el("h2", { text: `Save login for ${prompt.host}?` }));
      if (prompt.canTitle) nodes.push(nameField(prompt));
      nodes.push(el("dl", { class: "fields" },
        el("div", {}, el("dt", { text: "Username" }), prompt.canEditUsername ? el("dd", {}, usernameField(prompt)) : el("dd", { text: prompt.username || "No username" })),
        el("div", {}, el("dt", { text: "Password" }), el("dd", { text: "••••••••" }))));
      if (prompt.locked) nodes.push(stateBox("warning", "Nuvori is locked. Saving finishes after you unlock it on Windows."));
      nodes.push(el("div", { class: "actions" }, cardButton("Save", "save", "primary"), cardButton("Not now", "dismiss"), cardButton("Never for this site", "never", "quiet")));
    } else if (prompt.kind === "update") {
      const choices = Array.isArray(prompt.choices) ? prompt.choices : [];
      const many = choices.length > 1;
      const who = prompt.username || "No username";
      nodes.push(el("h2", { text: many ? `Update a password on ${prompt.host}?` : `Update password for ${who}?` }),
        el("p", { class: "desc", text: many ? "Choose which saved account to update." : `A different password is saved for this account on ${prompt.host}.` }));
      if (many) nodes.push(choiceList(prompt));
      const update = cardButton("Update", "update", "primary");
      if (many) update.setAttribute("aria-disabled", "true");
      card.updateButton = update;
      nodes.push(el("div", { class: "actions" }, update, cardButton("Not now", "dismiss")));
    } else {
      nodes.push(el("h2", { text: `A different password is saved for ${prompt.host}` }),
        el("p", { class: "desc", text: "Open Nuvori to choose which account to update." }));
      nodes.push(el("div", { class: "actions" }, cardButton("Review in Nuvori", "open", "primary"), cardButton("Not now", "dismiss")));
    }
    if (note) nodes.splice(1, 0, stateBox("info", note));
    card.body.replaceChildren(...nodes);
  }

  function stateBox(tone, text) {
    return el("div", { class: "state", "data-tone": tone, role: "status" }, icon(TONE_ICON[tone], tone === "progress" ? "spin" : ""), el("div", { text }));
  }

  function showCard(prompt, nextTheme) {
    if (!prompt || typeof prompt.id !== "string") return;
    if (["light", "dark", "system"].includes(nextTheme)) theme = nextTheme;
    ensureCard();
    clearTimeout(card.hideTimer);
    card.prompt = prompt;
    card.busy = false;
    card.surface.setTheme(theme);
    renderCard();
    card.surface.show();
    card.surface.resetActivation();
  }

  function hideCard() {
    clearTimeout(card.hideTimer);
    card.prompt = null;
    card.surface?.hide();
  }

  /** A brief card that carries no decision, e.g. "Already saved". `sticky` keeps it until replaced. */
  function notice(tone, text, nextTheme, { sticky = false } = {}) {
    if (["light", "dark", "system"].includes(nextTheme)) theme = nextTheme;
    if (card.prompt) return; // Never replace an open save or update prompt.
    ensureCard();
    card.busy = false;
    card.surface.setTheme(theme);
    card.body.replaceChildren(stateBox(tone, text));
    card.surface.show();
    clearTimeout(card.hideTimer);
    if (!sticky) card.hideTimer = setTimeout(hideCard, FEEDBACK_MS);
  }

  function feedback(tone, text, delay = FEEDBACK_MS) {
    card.body.replaceChildren(stateBox(tone, text));
    clearTimeout(card.hideTimer);
    card.hideTimer = setTimeout(hideCard, delay);
  }

  async function decide(decision) {
    const prompt = card.prompt;
    if (!prompt) return;
    const message = { action: "inline_approve", id: prompt.id, decision };
    if (decision === "save" && prompt.canTitle && card.nameInput) message.title = String(card.nameInput.value || "").slice(0, 256);
    if (decision === "save" && prompt.canEditUsername && card.usernameInput) message.username = String(card.usernameInput.value || "").slice(0, 1024);
    if (decision === "update" && prompt.choices?.length > 1) {
      if (!card.choice) return; // Pick an account first.
      message.credentialId = card.choice;
    }
    card.busy = true;
    for (const button of card.body.querySelectorAll?.("button") || []) button.setAttribute("aria-disabled", "true");
    const result = await send(message);
    card.busy = false;
    if (card.prompt !== prompt) return;
    switch (result?.status) {
      case "saved": return feedback("success", "Saved ✓");
      case "updated": return feedback("success", "Updated ✓");
      case "queued": return feedback("warning", "Saved for later. Unlock Nuvori on Windows to finish.", 5000);
      case "dismissed": return hideCard();
      case "never": return feedback("neutral", `Nuvori won't offer to save logins on ${prompt.host}.`);
      case "review":
        if (result.prompt) {
          card.prompt = result.prompt;
          renderCard(result.message);
          card.surface.resetActivation(); // New buttons must not take a double-click.
          return;
        }
        return feedback("error", result.message || "Open Nuvori to review this login.", 5000);
      case "queued_update": return feedback("warning", "Saved for later. Unlock Nuvori on Windows, then finish the update in the extension.", 5000);
      case "locked_details":
        renderCard(result.message);
        card.surface.resetActivation();
        return;
      case "choose":
        renderCard(result.message);
        card.surface.resetActivation();
        return;
      case "offline": return feedback("error", "Can't reach Nuvori. Open the extension to finish.", 5000);
      default: return feedback("error", result?.message || "Something went wrong. Open Nuvori to review.", 5000);
    }
  }

  // ---------------------------------------------------------------------------
  // Capturing a submitted login (trusted submits only; never stores a password here)

  let lastCapture = "";
  let capturing = false;
  // Pages can submit forms from script with isTrusted === true (form.requestSubmit()), so a
  // capture also needs live user activation, and each activation allows one capture at most.
  let activation = 0;
  let consumedActivation = -1;
  for (const type of ["keydown", "mousedown", "pointerdown", "pointerup", "touchend"]) {
    listen(doc, type, (event) => { if (event.isTrusted) activation++; }, true);
  }
  function takeActivation() {
    if (navigator.userActivation?.isActive !== true || activation === consumedActivation) return false;
    consumedActivation = activation;
    return true;
  }

  let lastDetails = "";

  /** A card or address the user just submitted ("save_details"). Never a security code. */
  async function captureDetails(controls) {
    const options = { labelOf, live: (input) => input.getClientRects().length > 0 };
    const cardFields = F.pickCardCapture(controls, options);
    const profile = cardFields ? null : F.pickProfileCapture(controls, options);
    if (!cardFields && !profile) return;
    const key = cardFields ? `card:${cardFields.number}` : `profile:${JSON.stringify(profile)}`;
    if (key === lastDetails || !takeActivation()) return;
    lastDetails = key;
    capturing = true;
    try {
      const result = await send(cardFields ? { action: "capture_details", kind: "card", card: { ...cardFields } } : { action: "capture_details", kind: "profile", profile });
      if (cardFields) cardFields.number = "";
      if (result?.status === "review" && result.prompt) showCard(result.prompt, result.theme);
      else if (result?.status === "already_saved") notice("success", "Already saved in Nuvori.", result.theme);
      else if (result?.status === "error" || result?.status === "offline") lastDetails = "";
    } finally {
      capturing = false;
    }
  }

  async function capture(inputs, controls) {
    if (capturing) return;
    const login = F.pickCaptureFields(inputs, (input) => input.getClientRects().length > 0, { allowPasswordOnly: true });
    if (!login) {
      if (controls) await captureDetails(controls);
      return;
    }
    const key = `${login.username}\u0000${login.password}`;
    if (key === lastCapture || !takeActivation()) return;
    lastCapture = key;
    capturing = true;
    try {
      const result = await send({ action: "capture_submitted_login", username: login.username, password: login.password, titleHint: siteName() });
      login.password = "";
      if (result?.status === "review" && result.prompt) showCard(result.prompt, result.theme);
      // The same kind of brief card a dismissed prompt leaves, so "already saved" is not silent.
      else if (result?.status === "already_saved") notice("success", "Already saved in Nuvori.", result.theme);
      else if (result?.status === "error" || result?.status === "offline") lastCapture = "";
    } finally {
      capturing = false;
    }
  }

  let lastStep = "";

  /**
   * An identifier-first page: tell the background which account name was entered, so the next
   * page lists that login and its code first, and a password page without an account field can
   * still be saved under the right name. Needs a real user gesture, like a capture.
   */
  function rememberStep(inputs) {
    const name = F.pickUsernameStep(inputs, (input) => input.getClientRects().length > 0);
    if (!name || name === lastStep || navigator.userActivation?.isActive !== true) return;
    lastStep = name;
    void send({ action: "remember_username", username: name });
  }

  /** A short default name for a new login: the site's declared name, or its host. */
  function siteName() {
    const meta = DOM.querySelector.call(doc, 'meta[property="og:site_name"], meta[name="application-name"]');
    const declared = String((meta && DOM.getAttribute.call(meta, "content")) || "").trim();
    return declared && declared.length <= 60 ? declared : location.host.replace(/^www\./, "");
  }

  function formlessInputs(node) {
    return inputsIn(rootOf(node)).filter((input) => !input.form);
  }

  // ---------------------------------------------------------------------------
  // Frames

  if (IN_FRAME) {
    let frameField = null;
    listen(doc, "focusin", (event) => {
      const target = eventTarget(event);
      if (!isInput(target) || !usable(target)) return;
      const detail = F.detailKind(target, controlsFor(target), DETAILS);
      if (!["card", "profile", "code"].includes(detail)) return;
      frameField = target;
      const rect = target.getBoundingClientRect();
      void send({ action: "frame_field", detail, rect: { left: rect.left, top: rect.top, width: rect.width, height: rect.height } });
    }, true);
    // Only the extension's background sends this; a page cannot message a content script.
    chrome.runtime.onMessage?.addListener((message, sender, sendResponse) => {
      if (message?.target !== "nuvori-frame" || message.action !== "fill_item" || sender?.id !== chrome.runtime.id) return false;
      const field = frameField?.isConnected ? frameField : null;
      const controls = field ? controlsFor(field) : controlsIn(doc);
      const before = fillCount;
      filling = true;
      try {
        if (message.kind === "card" && message.card) fillCardInto(controls, { ...message.card, hasCode: false });
        else if (message.kind === "profile" && message.profile) fillProfileInto(controls, message.profile);
        else if (message.kind === "code" && message.code && field) fillCode(field, message.code);
      } finally {
        filling = false;
        for (const key of Object.keys(message)) message[key] = undefined;
      }
      sendResponse({ status: "ok", filled: fillCount - before });
      return false;
    });
    return;
  }

  // The top page shows the list for a field a frame reported, next to that frame.
  chrome.runtime.onMessage?.addListener((message, sender, sendResponse) => {
    if (message?.target !== "nuvori-top" || message.action !== "frame_field" || sender?.id !== chrome.runtime.id) return false;
    const element = queryIn(doc, "iframe, frame").find((frame) => {
      try { return chrome.runtime.getFrameId(frame) === message.frameId; } catch { return false; }
    });
    if (!element || !usable(element) || suggestionsOff) { sendResponse({ status: "none" }); return false; }
    const target = { frameId: message.frameId, element, rect: message.rect };
    void openItems(element, message.detail, { force: true, frame: target });
    sendResponse({ status: "ok" });
    return false;
  });

  // ---------------------------------------------------------------------------
  // Page listeners

  listen(doc, "focusin", (event) => {
    const target = eventTarget(event);
    if (dropdown.surface?.contains(target) || card.surface?.contains(target)) return;
    focusedField = isInput(target) ? target : null;
    clearTimeout(dropdown.blurTimer);
    if (!focusedField || filling) return;
    if (dropdown.open && dropdown.field === focusedField) return;
    if (dismissedField === focusedField) return;
    dismissedField = null;
    if (dropdown.open) closeDropdown();
    void openFor(focusedField);
  }, true);

  listen(doc, "focusout", (event) => {
    const target = eventTarget(event);
    if (target !== focusedField) return;
    focusedField = null;
    clearTimeout(dropdown.blurTimer);
    dropdown.blurTimer = setTimeout(() => {
      const active = deepActive();
      if (active && (active === dropdown.field || dropdown.surface?.contains(active))) return;
      dismissedField = null;
      closeDropdown();
    }, BLUR_CLOSE_MS);
  }, true);

  listen(doc, "pointerdown", (event) => {
    if (!dropdown.open) return;
    const path = event.composedPath();
    if (path.includes(dropdown.surface.host) || path[0] === dropdown.field) return;
    closeDropdown();
  }, true);

  listen(doc, "click", (event) => {
    if (!event.isTrusted) return;
    const target = eventTarget(event);
    // Clicking a focused login field reopens the list after Esc or a fill.
    if (isInput(target) && target === focusedField && !dropdown.open && dismissedField === target) {
      dismissedField = null;
      void openFor(target, { force: true });
      return;
    }
    // Sign-in buttons outside a <form> (single-page apps) never fire "submit".
    const button = event.composedPath().find((node) => node instanceof Element && (tagOf(node) === "BUTTON" ||
      DOM.getAttribute.call(node, "role") === "button" ||
      (tagOf(node) === "INPUT" && ["submit", "button"].includes(String(node.type).toLowerCase()))));
    if (!button || button.form) return;
    const inputs = formlessInputs(button);
    rememberStep(inputs);
    if (inputs.some((input) => F.isPasswordField(input) && input.value)) void capture(inputs);
    // Single-page checkouts: a Pay / Save / Continue button outside a form.
    else if (/pay|place\s*order|save|continue|submit|confirm|proceed|checkout|next|add/i.test(String(button.textContent || button.value || "").slice(0, 80))) {
      void captureDetails(controlsIn(rootOf(button)).filter((control) => !control.form));
    }
  }, true);

  listen(doc, "keydown", (event) => {
    if (!event.isTrusted) return;
    const target = eventTarget(event);
    if (dropdown.open && target === dropdown.field) {
      if (event.key === "ArrowDown" && dropdown.options.length) {
        event.preventDefault(); event.stopPropagation();
        highlight(0, true);
      } else if (event.key === "Escape") {
        event.preventDefault(); event.stopPropagation();
        dismissedField = target;
        closeDropdown();
      } else if (event.key === "Tab") {
        closeDropdown();
      }
      return;
    }
    if (event.key === "ArrowDown" && isInput(target) && target === focusedField && !dropdown.open && !event.altKey) {
      dismissedField = null;
      void openFor(target, { force: true });
      return;
    }
    if (event.key === "Enter" && isInput(target) && !target.form) {
      if (F.isPasswordField(target) && target.value) void capture(formlessInputs(target));
      else rememberStep(formlessInputs(target));
    }
  }, true);

  listen(doc, "submit", (event) => {
    if (!event.isTrusted || !(event.target instanceof HTMLFormElement)) return;
    rememberStep(inputsIn(event.target));
    void capture(inputsIn(event.target), controlsIn(event.target));
  }, true);

  window.addEventListener?.("resize", () => position(), { passive: true });
  window.addEventListener?.("scroll", () => position(), { passive: true, capture: true });

  // A page that opens with a login field already focused still gets suggestions.
  const initial = deepActive();
  if (isInput(initial)) { focusedField = initial; void openFor(initial); }

  // Pages usually navigate after a sign-in; the background keeps the prompt for this tab and site.
  void send({ action: "inline_pending" }).then((result) => {
    if (result?.status === "ok" && result.prompt && !card.prompt) showCard(result.prompt, result.theme);
  });
})();
