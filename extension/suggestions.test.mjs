import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const fieldsSource = readFileSync(new URL("./fields.js", import.meta.url), "utf8");
const source = readFileSync(new URL("./suggestions.js", import.meta.url), "utf8");

// --- A tiny DOM with real prototype chains (EventTarget > Node > Element / Document /
// DocumentFragment > ShadowRoot), so the script's captured prototype methods work and
// own-property "clobbering" on document or a form can be simulated.

function makeDom() {
  let doc;
  const silent = (node, event) => { for (const callback of node.listeners[event.type] || []) callback(event); };
  class EventTargetF {
    constructor() { this.listeners = {}; }
    addEventListener(type, callback) { (this.listeners[type] ||= []).push(callback); }
    dispatchEvent(event) {
      (this.dispatched ||= []).push(event.type);
      event.composedPath ||= () => [this];
      silent(this, event);
      return true;
    }
  }
  class NodeF extends EventTargetF {
    constructor() { super(); this.children = []; this.parent = null; this.nodeType = 1; this._text = ""; }
    get parentElement() { return this.parent instanceof ElementF ? this.parent : null; }
    get isConnected() {
      let node = this;
      while (node) {
        if (node === doc._root) return true;
        node = node instanceof ShadowRootF ? node.host : node.parent;
      }
      return false;
    }
    get textContent() { return this._text + this.children.map((child) => child.textContent).join(""); }
    set textContent(value) { this._text = String(value); this.children = []; }
    getRootNode() { let node = this; while (node.parent) node = node.parent; return node instanceof ShadowRootF ? node : doc; }
    append(...nodes) { for (const node of nodes) { if (node.parent) node.remove(); node.parent = this; this.children.push(node); } }
    replaceChildren(...nodes) { for (const child of this.children) child.parent = null; this.children = []; this.append(...nodes); }
    remove() { if (!this.parent) return; this.parent.children.splice(this.parent.children.indexOf(this), 1); this.parent = null; }
    contains(node) { for (; node; node = node.parent) if (node === this) return true; return false; }
    querySelectorAll(selector) {
      const tags = selector.split(",").map((part) => part.trim().toUpperCase());
      return [...this.descendants()].filter((node) => tags.includes(node._tag));
    }
    *descendants() { for (const child of this.children) { yield child; yield* child.descendants(); } }
  }
  class ElementF extends NodeF {
    constructor(tag = "div") {
      super();
      this._tag = tag.toUpperCase();
      this.attrs = {};
      this.className = "";
      this.style = {};
      this.computed = { visibility: "visible", display: "block", opacity: "1" };
    }
    get tagName() { return this._tag; }
    get shadowRoot() { return null; }
    setAttribute(name, value) { this.attrs[name] = String(value); this.mutated?.(name); }
    getAttribute(name) { return name in this.attrs ? this.attrs[name] : null; }
    removeAttribute(name) { delete this.attrs[name]; }
    getAttributeNames() { return Object.keys(this.attrs); }
    attachShadow() { return new ShadowRootF(this); }
    getBoundingClientRect() { return this.rect || { left: 0, top: 0, right: 0, bottom: 0, width: 0, height: 0 }; }
    focus() { doc.focusNode(this); }
    showPopover() { this.popoverOpen = true; }
    hidePopover() { this.popoverOpen = false; }
  }
  class DocumentFragmentF extends NodeF {
    querySelectorAll(selector) { return NodeF.prototype.querySelectorAll.call(this, selector); }
  }
  class ShadowRootF extends DocumentFragmentF {
    constructor(host) { super(); this.host = host; host.closedRoot = this; }
    get activeElement() { return null; }
    elementFromPoint(x, y) { return doc.hit(x, y); }
  }
  class DocumentF extends NodeF {
    constructor() { super(); this._root = new ElementF("html"); this._body = new ElementF("body"); this._root.append(this._body); this._active = null; this._visibility = "visible"; }
    get documentElement() { return this._root; }
    get body() { return this._body; }
    get activeElement() { return this._active; }
    get visibilityState() { return this._visibility; }
    createElement(tag) { const node = new (tag === "input" ? Input : ElementF)(tag); this.created?.push(node); return node; }
    createElementNS(_ns, tag) { return new ElementF(tag); }
    querySelector() { return null; }
    querySelectorAll(selector) { return this._root.querySelectorAll(selector); }
    elementFromPoint(x, y) { return this.hit(x, y); }
    hit(x, y) {
      if (this.cover) return this.cover;
      const hosts = this._root.children.filter((child) => child.closedRoot);
      if (hosts.length) return hosts[hosts.length - 1];
      return [...this._root.descendants()].find((node) => node instanceof Input && node.rect.width &&
        x >= node.rect.left && x <= node.rect.right && y >= node.rect.top && y <= node.rect.bottom) || null;
    }
    fire(type, init = {}) {
      const event = { type, isTrusted: true, defaultPrevented: false, detail: 0, preventDefault() { this.defaultPrevented = true; }, stopPropagation() {}, ...init };
      event.composedPath ||= () => [event.target];
      silent(this, event);
      return event;
    }
    outer(node) {
      let root = node;
      while (root.parent) root = root.parent;
      return root instanceof ShadowRootF ? this.outer(root.host) : node;
    }
    bubble(node, type, relatedTarget) {
      for (let current = node; current && !(current instanceof DocumentF); current = current.parent) {
        silent(current, { type, target: node, relatedTarget, isTrusted: true });
      }
    }
    focusNode(node) {
      const previousInner = this.focused;
      const previousOuter = this._active;
      const outer = this.outer(node);
      this.focused = node;
      if (previousInner && previousInner !== node) this.bubble(previousInner, "focusout", node);
      if (previousOuter && previousOuter !== outer) this.fire("focusout", { target: previousOuter });
      this._active = outer;
      this.bubble(node, "focusin", previousInner);
      this.fire("focusin", { target: outer });
    }
  }
  class Input extends ElementF {
    constructor(type, attrs = {}, value = "") {
      super("input");
      if (typeof type === "string" && type !== "input") this.type = type; else this.type = "text";
      this._value = value;
      this.disabled = false;
      this.readOnly = false;
      this.form = null;
      this.nativeSets = 0;
      Object.assign(this.attrs, attrs);
      this.rect = { left: 100, top: 100, right: 400, bottom: 130, width: 300, height: 30 };
    }
    getClientRects() { return this.rect.width ? [this.rect] : []; }
    scrollIntoView() { this.scrolled = (this.scrolled || 0) + 1; if (this.scrollTo) this.rect = this.scrollTo; }
  }
  Object.defineProperty(Input.prototype, "value", {
    get() { return this._value; },
    set(value) { this.nativeSets++; this._value = value; },
    configurable: true,
  });
  class Form extends ElementF {
    constructor() { super("form"); this.submitted = 0; }
    submit() { this.submitted++; }
  }
  class Label extends ElementF {}
  doc = new DocumentF();
  return { doc, Node: NodeF, Element: ElementF, Input, Form, Label, ShadowRoot: ShadowRootF, DocumentFragment: DocumentFragmentF, Document: DocumentF, EventTarget: EventTargetF };
}

async function page({ protocol = "https:", reply = () => ({ status: "none" }), build, before, intersection = true } = {}) {
  const dom = makeDom();
  const { doc, Input, Form } = dom;
  const form = new Form();
  const username = new Input("email", { name: "email" }, "");
  const password = new Input("password", { name: "password" }, "");
  username.form = form;
  password.form = form;
  username.rect = { left: 100, top: 100, right: 400, bottom: 130, width: 300, height: 30 };
  password.rect = { left: 100, top: 140, right: 400, bottom: 170, width: 300, height: 30 };
  form.append(username, password);
  doc.body.append(form);
  build?.(dom, { form, username, password });
  const requests = [];
  const timers = [];
  const clock = { now: 1000 };
  const created = [];
  doc.created = created;
  const visibility = { visible: true };
  const observers = [];
  const userActivation = { isActive: true };
  const window = { innerWidth: 1200, innerHeight: 800, addEventListener() {} };
  window.top = window;
  const context = vm.createContext({
    window, document: doc, location: { protocol, host: "example.com" },
    navigator: { userActivation },
    Document: dom.Document, ShadowRoot: dom.ShadowRoot, DocumentFragment: dom.DocumentFragment, Element: dom.Element,
    Node: dom.Node, EventTarget: dom.EventTarget,
    HTMLInputElement: Input, HTMLFormElement: Form, HTMLLabelElement: dom.Label,
    getComputedStyle: (node) => node.computed,
    performance: { now: () => clock.now },
    setTimeout: (callback, delay) => { timers.push({ callback, delay }); return timers.length; },
    clearTimeout: (id) => { if (timers[id - 1]) timers[id - 1].cancelled = true; },
    MutationObserver: class { constructor(callback) { this.callback = callback; observers.push(this); } observe(node) { node.mutated = (name) => this.active && this.callback([{ target: node, attributeName: name }]); this.active = true; } disconnect() { this.active = false; } },
    ...(intersection ? { IntersectionObserver: class {
      constructor(callback) { this.callback = callback; }
      observe(target) { queueMicrotask(() => this.callback([{ target, isVisible: visibility.visible, isIntersecting: true }])); }
      unobserve() {}
    } } : {}),
    Event: class { constructor(type, init = {}) { this.type = type; Object.assign(this, init); } },
    chrome: { runtime: { sendMessage: async (message) => { requests.push(message); return reply(message); } } },
  });
  before?.(dom, { form, username, password, context });
  vm.runInContext(fieldsSource, context);
  vm.runInContext(source, context);
  await settle();
  const hosts = () => doc._root.children.filter((child) => child.closedRoot);
  const inside = (host) => [...host.closedRoot.descendants()];
  return {
    ...dom, doc, form, username, password, requests, timers, clock, created, hosts, inside, visibility, userActivation,
    // A real submit follows a key press or click: that is the user activation a capture consumes.
    submit: async (isTrusted, { activate = true } = {}) => {
      if (activate) doc.fire("keydown", { key: "Enter", target: password });
      doc.fire("submit", { isTrusted, target: form });
      await settle();
    },
    focus: async (node) => { node.focus(); await settle(); },
    runTimers: async () => { for (const timer of timers.splice(0)) if (!timer.cancelled) timer.callback(); await settle(); },
    find: (host, predicate) => inside(host).find(predicate),
    click: async (node, init = {}) => { node.dispatchEvent({ type: "click", isTrusted: true, detail: 1, clientX: 10, clientY: 10, preventDefault() {}, stopPropagation() {}, ...init }); await settle(); },
    key: async (node, key, init = {}) => { node.dispatchEvent({ type: "keydown", key, isTrusted: true, preventDefault() {}, stopPropagation() {}, ...init }); await settle(); },
  };
}

const settle = () => new Promise(setImmediate);
const textOf = (node) => node.textContent;

test("HTTP pages do not suggest or capture accounts", async () => {
  const state = await page({ protocol: "http:" });
  assert.equal(state.requests.length, 0);
  assert.equal(state.created.length, 0);
});

test("capture rejects scripted submits and mismatched confirmation passwords", async () => {
  const state = await page({ reply: (message) => message.action === "capture_submitted_login" ? { status: "already_saved" } : { status: "none" } });
  state.username._value = "synthetic-user";
  state.password._value = "synthetic-password";
  await state.submit(false);
  assert.equal(state.requests.some(request => request.action === "capture_submitted_login"), false);
  const newPassword = new state.Input("password", { autocomplete: "new-password" }, "new-synthetic-password");
  const confirmation = new state.Input("password", { autocomplete: "new-password" }, "different-password");
  state.form.append(newPassword, confirmation);
  await state.submit(true);
  assert.equal(state.requests.some(request => request.action === "capture_submitted_login"), false);
  confirmation._value = newPassword._value;
  await state.submit(true);
  const captures = state.requests.filter(request => request.action === "capture_submitted_login");
  assert.equal(captures.length, 1);
  assert.equal(captures[0].password, "new-synthetic-password");
  assert.equal(captures[0].username, "synthetic-user");
  assert.equal(captures[0].origin, undefined, "the page never names its own origin");
  await state.submit(true);
  assert.equal(state.requests.filter(request => request.action === "capture_submitted_login").length, 1, "the same submit is captured once");
  assert.equal(state.form.submitted, 0);
});

const savePrompt = { id: "item-1", kind: "save", host: "example.com", username: "synthetic-user", locked: false };

test("a submitted login shows a save card that stays after the form disappears", async () => {
  const state = await page({ reply: (message) => message.action === "capture_submitted_login" ? { status: "review", prompt: savePrompt, theme: "dark" } : { status: "none" } });
  state.username._value = "synthetic-user";
  state.password._value = "synthetic-password";
  await state.submit(true);
  const [card] = state.hosts();
  assert.ok(card, "card shown");
  const text = textOf(card.closedRoot);
  assert.match(text, /Save login for example\.com\?/);
  assert.match(text, /synthetic-user/);
  assert.equal(text.includes("synthetic-password"), false, "the password is masked");
  assert.match(card.getAttribute("style"), /opacity:1 !important/);
  state.form.remove();
  await state.runTimers();
  assert.equal(card.isConnected, true);
});

test("the save card is re-shown after navigation and needs a trusted, delayed click", async () => {
  const state = await page({ reply: (message) => message.action === "inline_pending" ? { status: "ok", prompt: savePrompt }
    : message.action === "inline_approve" ? { status: "saved" } : { status: "none" } });
  assert.equal(state.requests[0].action, "inline_pending");
  const [card] = state.hosts();
  const save = state.find(card, (node) => node.attrs["data-decision"] === "save");
  await state.click(save, { isTrusted: false });
  await state.click(save);
  assert.equal(state.requests.some((request) => request.action === "inline_approve"), false, "too soon and untrusted clicks are ignored");
  state.clock.now += 450;
  await state.click(save, { isTrusted: false });
  assert.equal(state.requests.some((request) => request.action === "inline_approve"), false, "synthetic clicks never count");
  state.doc.cover = { id: "page-overlay" };
  await state.click(save, { detail: 1, clientX: 10, clientY: 10 });
  assert.equal(state.requests.some((request) => request.action === "inline_approve"), false, "a covered card is not clickable");
  state.doc.cover = null;
  await state.click(save);
  const approvals = state.requests.filter((request) => request.action === "inline_approve");
  assert.deepEqual(approvals.map(({ id, decision }) => ({ id, decision })), [{ id: "item-1", decision: "save" }]);
  assert.match(textOf(card.closedRoot), /Saved ✓/);
  await state.runTimers();
  assert.equal(card.isConnected, false, "feedback hides itself");
});

test("restyling the card from the page restarts the activation delay", async () => {
  const state = await page({ reply: (message) => message.action === "inline_pending" ? { status: "ok", prompt: savePrompt } : { status: "saved" } });
  const [card] = state.hosts();
  state.clock.now += 450;
  card.setAttribute("style", "opacity:0");
  assert.match(card.getAttribute("style"), /opacity:1 !important/, "style is repaired");
  await state.click(state.find(card, (node) => node.attrs["data-decision"] === "save"));
  assert.equal(state.requests.some((request) => request.action === "inline_approve"), false);
});

test("an update prompt offers Update and switches to a fresh review when approval expires", async () => {
  let approvals = 0;
  const state = await page({ reply: (message) => message.action === "inline_pending" ? { status: "ok", prompt: { ...savePrompt, kind: "update" } }
    : message.action === "inline_approve" ? (++approvals === 1 ? { status: "review", message: "Approval expired.", prompt: { ...savePrompt, kind: "update" } } : { status: "updated" })
    : { status: "none" } });
  const [card] = state.hosts();
  assert.match(textOf(card.closedRoot), /Update password for synthetic-user\?/);
  state.clock.now += 450;
  await state.click(state.find(card, (node) => node.attrs["data-decision"] === "update"));
  assert.match(textOf(card.closedRoot), /Approval expired/);
  await state.click(state.find(card, (node) => node.attrs["data-decision"] === "update"));
  assert.equal(approvals, 1, "the new button needs its own delay");
  state.clock.now += 450;
  await state.click(state.find(card, (node) => node.attrs["data-decision"] === "update"));
  assert.match(textOf(card.closedRoot), /Updated ✓/);
});

const accounts = { status: "ok", theme: "system", accounts: [{ id: "a", title: "Work", username: "alice@example.com" }, { id: "b", title: "Home", username: "bob" }] };

test("focusing a password field shows matching accounts under it and fills on a trusted, delayed click", async () => {
  const state = await page({ reply: (message) => message.action === "inline_query" ? accounts
    : message.action === "inline_fill" ? { status: "ok", username: "alice@example.com", password: "synthetic-secret" } : { status: "none" } });
  await state.focus(state.password);
  assert.ok(state.requests.some((request) => request.action === "inline_query"));
  const [dropdown] = state.hosts();
  assert.match(dropdown.getAttribute("style"), /top:174px !important;left:100px !important;width:300px/);
  const options = state.inside(dropdown).filter((node) => node.attrs.role === "option");
  assert.equal(options.length, 2);
  assert.match(textOf(options[0]), /Work.*alice@example\.com/);
  assert.equal(state.find(dropdown, (node) => node.attrs.role === "listbox") !== undefined, true);
  await state.click(options[0], { isTrusted: false });
  await state.click(options[0]);
  assert.equal(state.requests.some((request) => request.action === "inline_fill"), false);
  state.clock.now += 450;
  await state.click(options[0], { isTrusted: false });
  assert.equal(state.requests.some((request) => request.action === "inline_fill"), false, "synthetic clicks never fill");
  await state.click(options[0]);
  assert.deepEqual(state.requests.filter((request) => request.action === "inline_fill").map(({ credentialId, want }) => ({ credentialId, want })), [{ credentialId: "a", want: "both" }]);
  assert.equal(state.username.value, "alice@example.com");
  assert.equal(state.password.value, "synthetic-secret");
  assert.ok(state.password.nativeSets > 0, "native value setter used");
  assert.deepEqual(state.password.dispatched, ["input", "change"]);
  assert.equal(state.form.submitted, 0, "never submits");
  assert.equal(dropdown.isConnected, false, "closes after filling");
});

test("keyboard: ArrowDown enters the list, Enter selects, Escape returns to the field", async () => {
  const state = await page({ reply: (message) => message.action === "inline_query" ? accounts
    : message.action === "inline_fill" ? { status: "ok", username: "bob", password: "synthetic-secret" } : { status: "none" } });
  await state.focus(state.username);
  const [dropdown] = state.hosts();
  state.doc.fire("keydown", { key: "ArrowDown", target: state.username });
  await settle();
  const options = state.inside(dropdown).filter((node) => node.attrs.role === "option");
  assert.equal(options[0].attrs["aria-selected"], "true");
  assert.equal(state.doc.focused, options[0]);
  await state.runTimers();
  assert.equal(dropdown.isConnected, true, "moving focus into the list keeps it open");
  const panel = state.find(dropdown, (node) => node.className === "panel");
  await state.key(panel, "ArrowDown");
  assert.equal(options[1].attrs["aria-selected"], "true");
  await state.key(panel, "Escape");
  assert.equal(dropdown.isConnected, false);
  assert.equal(state.doc.focused, state.username);
  state.doc.fire("keydown", { key: "ArrowDown", target: state.username });
  await settle();
  const [reopened] = state.hosts();
  state.doc.fire("keydown", { key: "ArrowDown", target: state.username });
  await settle();
  const reopenedPanel = state.find(reopened, (node) => node.className === "panel");
  await state.key(reopenedPanel, "Enter");
  assert.equal(state.requests.some((request) => request.action === "inline_fill"), false, "Enter right after opening is ignored");
  state.clock.now += 450;
  await state.key(reopenedPanel, "Enter", { isTrusted: false });
  assert.equal(state.requests.some((request) => request.action === "inline_fill"), false);
  await state.key(reopenedPanel, "Enter");
  assert.equal(state.requests.filter((request) => request.action === "inline_fill")[0].credentialId, "a");
  assert.equal(state.password.value, "synthetic-secret");
});

test("locked, offline and empty states are shown with their own message", async () => {
  for (const [reply, pattern] of [
    [{ status: "locked" }, /Nuvori is locked\. Unlock it to fill this site\./],
    [{ status: "offline" }, /Nuvori for Windows isn't running\./],
    [{ status: "host_missing" }, /Can't reach Nuvori for Windows/],
  ]) {
    const state = await page({ reply: (message) => message.action === "inline_query" ? reply : { status: "none" } });
    await state.focus(state.password);
    const [dropdown] = state.hosts();
    assert.match(textOf(dropdown.closedRoot), pattern);
    assert.equal(state.find(dropdown, (node) => node.attrs.role === "status").attrs.role, "status");
  }
});

test("a site with no saved login gets no popup on focus; the Down key asks for the list", async () => {
  const state = await page({ reply: (message) => message.action === "inline_query" ? { status: "ok", accounts: [] } : { status: "none" } });
  await state.focus(state.password);
  assert.ok(state.hosts().every((host) => !host.popoverOpen), "nothing to offer is not worth a popup");
  state.doc.fire("keydown", { key: "ArrowDown", target: state.password });
  await settle();
  const [dropdown] = state.hosts();
  assert.equal(dropdown.popoverOpen, true);
  assert.match(textOf(dropdown.closedRoot), /No saved login for this site/);
});

test("the account used on the previous page is marked, and an identifier-first submit is remembered", async () => {
  const state = await page({ reply: (message) => message.action === "inline_query"
    ? { status: "ok", accounts: [{ id: "b", title: "Home", username: "bob", recent: true }, { id: "a", title: "Work", username: "alice" }] }
    : { status: "none" } });
  await state.focus(state.password);
  const [dropdown] = state.hosts();
  const options = state.inside(dropdown).filter((node) => node.attrs.role === "option");
  assert.match(textOf(options[0]), /Continue/);
  assert.doesNotMatch(textOf(options[1]), /Continue/);
  const related = await page({ reply: (message) => message.action === "inline_query"
    ? { status: "ok", accounts: [{ id: "c", title: "Login", username: "carol", related: true }] } : { status: "none" } });
  await related.focus(related.password);
  const [relatedList] = related.hosts();
  assert.match(textOf(relatedList.closedRoot), /Same site/);

  // An identifier-first page: only the account field is there.
  const first = await page({ before: (dom, { password }) => password.remove() });
  first.username.value = "bob@example.com";
  await first.submit(true);
  const remembered = first.requests.filter((message) => message.action === "remember_username");
  assert.deepEqual(remembered.map((message) => message.username), ["bob@example.com"]);
  assert.equal(first.requests.some((message) => message.action === "capture_submitted_login"), false);

  // A script submit without a user gesture is not remembered.
  const scripted = await page({ before: (dom, { password }) => password.remove() });
  scripted.username.value = "mallory";
  scripted.userActivation.isActive = false;
  await scripted.submit(true, { activate: false });
  assert.equal(scripted.requests.some((message) => message.action === "remember_username"), false);
});

test("turned-off suggestions stay quiet, and Don't suggest needs a trusted click", async () => {
  const off = await page({ reply: (message) => message.action === "inline_query" ? { status: "disabled" } : { status: "none" } });
  await off.focus(off.password);
  assert.equal(off.hosts().length, 0);
  const state = await page({ reply: (message) => message.action === "inline_query" ? accounts : { status: "ok" } });
  await state.focus(state.password);
  const [dropdown] = state.hosts();
  const button = state.find(dropdown, (node) => node.tagName === "BUTTON" && node.textContent === "Don't suggest on this site");
  await state.click(button, { isTrusted: false });
  assert.equal(state.requests.some((request) => request.action === "inline_dont_suggest"), false);
  state.clock.now += 450;
  await state.click(button);
  assert.equal(state.requests.some((request) => request.action === "inline_dont_suggest"), true);
  assert.equal(dropdown.isConnected, false);
});

test("hidden fields are never filled and no password is requested without a visible target", async () => {
  const state = await page({ reply: (message) => message.action === "inline_query" ? accounts
    : message.action === "inline_fill" ? { status: "ok", username: "alice", password: "synthetic-secret" } : { status: "none" } });
  await state.focus(state.username);
  const [dropdown] = state.hosts();
  state.form.computed = { visibility: "visible", display: "block", opacity: "0" };
  state.clock.now += 450;
  await state.click(state.inside(dropdown).find((node) => node.attrs.role === "option"));
  assert.equal(state.requests.some((request) => request.action === "inline_fill"), false);
  assert.equal(state.password.value, "");
  assert.match(textOf(state.hosts()[0].closedRoot), /No visible sign-in field/);
});

test("a sign-up form gets no suggestions", async () => {
  const state = await page({
    reply: (message) => message.action === "inline_query" ? accounts : { status: "none" },
    build: (_dom, { password }) => { password.attrs.autocomplete = "new-password"; },
  });
  await state.focus(state.password);
  assert.equal(state.requests.some((request) => request.action === "inline_query"), false);
  assert.equal(state.hosts().length, 0);
});

// --- Additive host features ---------------------------------------------------

test("a password-only form is offered with an empty username; the card shows No username and an editable name", async () => {
  const prompt = { id: "item-2", kind: "save", host: "router.example", username: "", title: "Router", canTitle: true, choices: [], locked: false };
  const state = await page({
    reply: (message) => message.action === "capture_submitted_login" ? { status: "review", prompt } : message.action === "inline_approve" ? { status: "saved" } : { status: "none" },
    build: (_dom, { form, username }) => { form.children.splice(form.children.indexOf(username), 1); username.parent = null; },
  });
  state.password._value = "synthetic-password";
  await state.submit(true);
  const capture = state.requests.find((request) => request.action === "capture_submitted_login");
  assert.equal(capture.username, "");
  assert.equal(capture.titleHint, "example.com");
  const [card] = state.hosts();
  assert.match(textOf(card.closedRoot), /No username/);
  const name = state.find(card, (node) => node.tagName === "INPUT");
  assert.equal(name.value, "Router");
  name.value = "Home router";
  state.clock.now += 450;
  await state.click(state.find(card, (node) => node.attrs["data-decision"] === "save"));
  const approve = state.requests.find((request) => request.action === "inline_approve");
  assert.equal(approve.title, "Home router");
});

test("without login_title the card has no name field and sends no title", async () => {
  const state = await page({ reply: (message) => message.action === "inline_pending" ? { status: "ok", prompt: { ...savePrompt, canTitle: false } } : { status: "saved" } });
  const [card] = state.hosts();
  assert.equal(state.find(card, (node) => node.tagName === "INPUT"), undefined);
  state.clock.now += 450;
  await state.click(state.find(card, (node) => node.attrs["data-decision"] === "save"));
  assert.equal("title" in state.requests.find((request) => request.action === "inline_approve"), false);
});

test("a numeric PIN with no account field is never captured", async () => {
  const state = await page({ build: (_dom, { form, username, password }) => {
    form.children.splice(form.children.indexOf(username), 1); username.parent = null; password.attrs.inputmode = "numeric";
  } });
  state.password._value = "1234";
  await state.submit(true);
  assert.equal(state.requests.some((request) => request.action === "capture_submitted_login"), false);
});

test("several saved accounts: Update waits until one is picked with a trusted click", async () => {
  const choices = [{ id: "a", title: "Personal", username: "u" }, { id: "b", title: "Work", username: "u" }];
  const state = await page({ reply: (message) => message.action === "inline_pending" ? { status: "ok", prompt: { ...savePrompt, kind: "update", choices } }
    : message.action === "inline_approve" ? { status: "updated" } : { status: "none" } });
  const [card] = state.hosts();
  assert.match(textOf(card.closedRoot), /Choose which saved account to update/);
  const rows = state.inside(card).filter((node) => node.attrs.role === "radio");
  assert.equal(rows.length, 2);
  assert.match(textOf(rows[1]), /Work/);
  const update = state.find(card, (node) => node.attrs["data-decision"] === "update");
  state.clock.now += 450;
  await state.click(update);
  assert.equal(state.requests.some((request) => request.action === "inline_approve"), false, "no account picked yet");
  await state.click(rows[1], { isTrusted: false });
  assert.equal(rows[1].attrs["aria-checked"], "false");
  await state.click(rows[1]);
  assert.equal(rows[1].attrs["aria-checked"], "true");
  await state.click(update);
  assert.equal(state.requests.some((request) => request.action === "inline_approve"), false, "picking restarts the delay");
  state.clock.now += 450;
  await state.click(update);
  const approve = state.requests.find((request) => request.action === "inline_approve");
  assert.deepEqual({ decision: approve.decision, credentialId: approve.credentialId }, { decision: "update", credentialId: "b" });
  assert.match(textOf(card.closedRoot), /Updated ✓/);
});

// --- Security review regressions ----------------------------------------------

const captureReply = (status = "review") => (message) => message.action === "capture_submitted_login"
  ? (status === "review" ? { status, prompt: savePrompt } : { status }) : { status: "none" };

test("M1: a script submit without live user activation is never captured", async () => {
  const state = await page({ reply: captureReply() });
  state.username._value = "alice";
  state.password._value = "guess-1";
  state.userActivation.isActive = false;
  await state.submit(true);
  assert.equal(state.requests.some((request) => request.action === "capture_submitted_login"), false);
});

test("M1: one capture per user activation, on every capture path", async () => {
  const state = await page({ reply: captureReply("already_saved") });
  state.username._value = "alice";
  state.password._value = "guess-1";
  await state.submit(true);
  state.password._value = "guess-2";
  await state.submit(true, { activate: false }); // e.g. form.requestSubmit() in the same gesture
  const captures = () => state.requests.filter((request) => request.action === "capture_submitted_login");
  assert.equal(captures().length, 1);
  await state.submit(true);
  assert.equal(captures().length, 2, "a new key press allows the next capture");
  // Formless Enter and button paths need activation too.
  const loose = new state.Input("password", {}, "guess-3");
  state.doc.body.append(loose);
  state.doc.fire("keydown", { key: "Enter", target: loose, isTrusted: true });
  await settle();
  assert.equal(captures().length, 3);
  state.userActivation.isActive = false;
  loose._value = "guess-4";
  state.doc.fire("keydown", { key: "Enter", target: loose, isTrusted: true });
  const button = new state.Element("button");
  state.doc.body.append(button);
  state.doc.fire("click", { target: button, isTrusted: true, detail: 1 });
  await settle();
  assert.equal(captures().length, 3);
});

test("M1: an already-saved login shows the same kind of brief card as other outcomes", async () => {
  const state = await page({ reply: captureReply("already_saved") });
  state.username._value = "alice";
  state.password._value = "right-password";
  await state.submit(true);
  const [card] = state.hosts();
  assert.ok(card, "a card appears");
  assert.match(textOf(card.closedRoot), /Already saved/);
  await state.runTimers();
  assert.equal(card.isConnected, false);
});

test("P1: another popover, dialog or fullscreen change resets activation until visibility is re-confirmed", async () => {
  const state = await page({ reply: (message) => message.action === "inline_pending" ? { status: "ok", prompt: savePrompt } : { status: "saved" } });
  const [card] = state.hosts();
  const save = state.find(card, (node) => node.attrs["data-decision"] === "save");
  for (const type of ["beforetoggle", "toggle", "fullscreenchange"]) {
    state.clock.now += 450;
    state.visibility.visible = false;
    state.doc.fire(type, { target: new state.Element("div") });
    await settle(); // the observer re-reports: now covered
    await state.click(save);
    assert.equal(state.requests.some((request) => request.action === "inline_approve"), false, `${type} blocks activation`);
    state.visibility.visible = true;
  }
  state.doc.fire("toggle", { target: new state.Element("div") });
  await settle();
  await state.click(save);
  assert.equal(state.requests.some((request) => request.action === "inline_approve"), false, "the delay restarts");
  state.clock.now += 450;
  await state.click(save);
  assert.equal(state.requests.filter((request) => request.action === "inline_approve").length, 1);
});

test("P1: without an IntersectionObserver report, or with a failing hit test, nothing activates", async () => {
  const state = await page({ intersection: false, reply: (message) => message.action === "inline_pending" ? { status: "ok", prompt: savePrompt } : { status: "saved" } });
  const [card] = state.hosts();
  state.clock.now += 1000;
  await state.click(state.find(card, (node) => node.attrs["data-decision"] === "save"));
  assert.equal(state.requests.some((request) => request.action === "inline_approve"), false);
  const covered = await page({ reply: (message) => message.action === "inline_pending" ? { status: "ok", prompt: savePrompt } : { status: "saved" } });
  const [other] = covered.hosts();
  covered.clock.now += 1000;
  covered.doc.cover = { id: "overlay" };
  const button = covered.find(other, (node) => node.attrs["data-decision"] === "save");
  await covered.click(button, { detail: 0 }); // keyboard-style activation is hit-tested too
  button.focus();
  covered.clock.now += 1000;
  await covered.click(button, { detail: 0 });
  assert.equal(covered.requests.some((request) => request.action === "inline_approve"), false);
});

test("L1: clobbered document and form properties don't change what the script sees", async () => {
  const state = await page({
    reply: (message) => message.action === "inline_query" ? accounts
      : message.action === "inline_fill" ? { status: "ok", username: "alice", password: "synthetic-secret" }
      : message.action === "capture_submitted_login" ? { status: "review", prompt: savePrompt } : { status: "none" },
    before: ({ doc, Element, Form }, { form }) => {
      const decoyForm = new Form();
      for (const [name, value] of Object.entries({ elementFromPoint: new Element("img"), documentElement: decoyForm, body: decoyForm,
        visibilityState: new Element("img"), activeElement: new Element("img"), querySelectorAll: new Element("img"),
        querySelector: new Element("img"), createElement: new Element("img"), addEventListener: new Element("img") })) {
        Object.defineProperty(doc, name, { value, configurable: true });
      }
      Object.defineProperty(form, "querySelectorAll", { value: new Element("input"), configurable: true });
    },
  });
  await state.focus(state.password);
  const host = state.doc._root.children.find((child) => child.closedRoot);
  assert.ok(host, "the dropdown is attached to the real document element");
  state.clock.now += 450;
  await state.click(state.inside(host).find((node) => node.attrs.role === "option"));
  assert.equal(state.password.value, "synthetic-secret");
  state.username._value = "alice";
  state.password._value = "new-password";
  await state.submit(true);
  assert.equal(state.requests.filter((request) => request.action === "capture_submitted_login").length, 1);
});

test("L3: off-screen fields are scrolled into view and hit-tested before filling", async () => {
  const fill = (message) => message.action === "inline_query" ? accounts
    : message.action === "inline_fill" ? { status: "ok", username: "alice", password: "synthetic-secret" } : { status: "none" };
  const state = await page({ reply: fill });
  state.password.rect = { left: 100, top: 2000, right: 400, bottom: 2030, width: 300, height: 30 };
  state.password.scrollTo = { left: 100, top: 600, right: 400, bottom: 630, width: 300, height: 30 };
  await state.focus(state.username);
  state.clock.now += 450;
  await state.click(state.inside(state.hosts()[0]).find((node) => node.attrs.role === "option"));
  assert.ok(state.password.scrolled >= 1);
  assert.equal(state.password.value, "synthetic-secret");
  const stuck = await page({ reply: fill });
  stuck.password.rect = { left: 100, top: 2000, right: 400, bottom: 2030, width: 300, height: 30 };
  await stuck.focus(stuck.username);
  stuck.clock.now += 450;
  await stuck.click(stuck.inside(stuck.hosts()[0]).find((node) => node.attrs.role === "option"));
  assert.equal(stuck.password.value, "", "a field that stays off screen is never filled");
  assert.equal(stuck.requests.find((request) => request.action === "inline_fill").want, "username");
});

test("P2: Space never chooses; keyboard activation waits after focus enters the list or card", async () => {
  const state = await page({ reply: (message) => message.action === "inline_query" ? accounts
    : message.action === "inline_fill" ? { status: "ok", username: "alice", password: "synthetic-secret" } : { status: "none" } });
  await state.focus(state.username);
  const [dropdown] = state.hosts();
  state.clock.now += 1000;
  state.doc.fire("keydown", { key: "ArrowDown", target: state.username });
  await settle();
  const panel = state.find(dropdown, (node) => node.className === "panel");
  await state.key(panel, " ");
  await state.key(panel, "Enter");
  assert.equal(state.requests.some((request) => request.action === "inline_fill"), false, "Enter right after focus entered the list waits");
  state.clock.now += 450;
  await state.key(panel, " ");
  assert.equal(state.requests.some((request) => request.action === "inline_fill"), false, "Space never chooses");
  await state.key(panel, "Enter");
  assert.equal(state.requests.some((request) => request.action === "inline_fill"), true);

  const cardPage = await page({ reply: (message) => message.action === "inline_pending" ? { status: "ok", prompt: savePrompt } : { status: "saved" } });
  const [card] = cardPage.hosts();
  cardPage.clock.now += 1000;
  const save = cardPage.find(card, (node) => node.attrs["data-decision"] === "save");
  save.focus();
  await cardPage.click(save, { detail: 0 });
  assert.equal(cardPage.requests.some((request) => request.action === "inline_approve"), false, "keyboard activation right after focus entry waits");
  cardPage.clock.now += 450;
  await cardPage.click(save, { detail: 0 });
  assert.equal(cardPage.requests.filter((request) => request.action === "inline_approve").length, 1);
});

test("L4: the card shows the real host next to the suggested name", async () => {
  const state = await page({ reply: (message) => message.action === "inline_pending"
    ? { status: "ok", prompt: { ...savePrompt, host: "evil.example", title: "PayPal", canTitle: true } } : { status: "none" } });
  const [card] = state.hosts();
  const label = state.find(card, (node) => node.className === "name");
  assert.match(textOf(label), /Name.*evil\.example/);
  assert.equal(state.find(card, (node) => node.tagName === "INPUT").value, "PayPal");
});

// --- Cards, addresses and codes ------------------------------------------------

/** A page whose form holds `fields` (built from the Input class) instead of the login pair. */
const detailPage = (fields, options = {}) => page({
  ...options,
  build: (dom, parts) => {
    parts.form.replaceChildren();
    const built = fields(dom.Input);
    built.forEach((input, index) => { input.form = parts.form; input.rect = { left: 100, top: 100 + index * 40, right: 400, bottom: 130 + index * 40, width: 300, height: 30 }; });
    parts.form.append(...built);
  },
});

test("frames: a card frame reports its field and draws nothing; the top page lists cards next to the frame", async () => {
  // Inside a payment frame.
  const listeners = [];
  let number; let expiry;
  const inFrame = await detailPage((Input) => [
    number = new Input("tel", { autocomplete: "cc-number" }),
    expiry = new Input("text", { autocomplete: "cc-exp", placeholder: "MM / YY" }),
  ], { before: (dom, { context }) => {
    context.window.top = {};
    context.chrome.runtime.id = "nuvori";
    context.chrome.runtime.onMessage = { addListener: (callback) => listeners.push(callback) };
  } });
  await inFrame.focus(number);
  const report = inFrame.requests.find((message) => message.action === "frame_field");
  assert.deepEqual([report.detail, report.rect.top, report.rect.width], ["card", 100, 300]);
  assert.equal(inFrame.hosts().length, 0, "no Nuvori UI inside a frame");
  assert.equal(inFrame.requests.some((message) => message.action === "inline_items" || message.action === "inline_pending"), false);
  const reply = (message, sender) => new Promise((resolve) => { for (const listener of listeners) listener(message, sender, resolve); });
  const ignored = await Promise.race([reply({ target: "nuvori-frame", action: "fill_item", kind: "card", card: { number: "4111111111111111", expiry: "07/29" } }, { id: "someone-else" }), settle().then(() => "none")]);
  assert.equal(ignored, "none", "only the extension itself can fill");
  assert.equal(number.value, "");
  const result = await reply({ target: "nuvori-frame", action: "fill_item", kind: "card", card: { number: "4111111111111111", name: "", expiry: "07/29" } }, { id: "nuvori" });
  assert.deepEqual([result.status, result.filled], ["ok", 2]);
  assert.equal(number.value, "4111111111111111");
  assert.equal(expiry.value, "07 / 29");

  // The top page: the list opens next to the frame and the pick goes back through the worker.
  const topListeners = [];
  let frameElement;
  const topPage = await page({
    reply: (message) => message.action === "inline_items" ? { status: "ok", items: [{ id: "c1", title: "Travel", subtitle: "Visa · •••• 1111" }] }
      : message.action === "inline_fill_frame" ? { status: "ok", filled: 2, codeLeft: true } : { status: "none" },
    before: (dom, { context }) => {
      frameElement = new dom.Element("iframe");
      frameElement.rect = { left: 50, top: 300, right: 450, bottom: 400, width: 400, height: 100 };
      frameElement.getClientRects = () => [frameElement.rect];
      dom.doc.body.append(frameElement);
      context.chrome.runtime.id = "nuvori";
      context.chrome.runtime.getFrameId = (element) => element === frameElement ? 3 : -1;
      context.chrome.runtime.onMessage = { addListener: (callback) => topListeners.push(callback) };
    },
  });
  const shown = await new Promise((resolve) => topListeners[0]({ target: "nuvori-top", action: "frame_field", frameId: 3, detail: "card", rect: { left: 10, top: 20, width: 200, height: 30 } }, { id: "nuvori" }, resolve));
  assert.equal(shown.status, "ok");
  await settle();
  const [dropdown] = topPage.hosts();
  assert.match(textOf(dropdown.closedRoot), /Travel/);
  assert.match(dropdown.getAttribute("style"), /top:354px !important;left:60px !important/, "under the field inside the frame");
  const option = topPage.find(dropdown, (node) => node.attrs.role === "option");
  topPage.clock.now += 450;
  await topPage.click(option);
  await settle();
  const fill = topPage.requests.find((message) => message.action === "inline_fill_frame");
  assert.deepEqual([fill.kind, fill.id, fill.frameId], ["card", "c1", 3]);
  assert.equal(topPage.requests.some((message) => message.action === "inline_fill_item"), false, "the top page never receives the card");
});

test("card form: the card list fills number and expiry, then the security code only after approval", async () => {
  let number; let expiry; let code;
  const state = await detailPage((Input) => [
    number = new Input("tel", { autocomplete: "cc-number" }),
    expiry = new Input("text", { autocomplete: "cc-exp", placeholder: "MM / YY" }),
    code = new Input("text", { autocomplete: "cc-csc" }),
  ], { reply: (message) => message.action === "inline_items" ? { status: "ok", items: [{ id: "c1", title: "Travel", subtitle: "Visa · •••• 1111" }] }
    : message.action === "inline_fill_item" ? { status: "ok", card: { number: "4111111111111111", name: "", expiry: "07/29", hasCode: true } }
    : message.action === "inline_card_code" ? { status: "ok", code: "123" } : { status: "none" } });
  await state.focus(number);
  const query = state.requests.find((request) => request.action === "inline_items");
  assert.deepEqual([query.kind, query.all], ["card", false]);
  const [dropdown] = state.hosts();
  assert.match(textOf(dropdown.closedRoot), /Cards.*Travel.*Visa · •••• 1111/);
  const option = state.find(dropdown, (node) => node.attrs.role === "option");
  await state.click(option);
  assert.equal(state.requests.some((request) => request.action === "inline_fill_item"), false, "waits for the activation delay");
  state.clock.now += 450;
  await state.click(option);
  await settle();
  assert.equal(number.value, "4111111111111111");
  assert.equal(expiry.value, "07 / 29");
  assert.equal(code.value, "123", "filled after Nuvori approved it");
  const ask = state.requests.find((request) => request.action === "inline_card_code");
  assert.equal(ask.id, "c1");
  assert.equal(state.requests.some((request) => "cvv" in request || "code" in request), false, "the page never sends a code");
});

test("a declined security code leaves the field empty", async () => {
  let number; let code;
  const state = await detailPage((Input) => [number = new Input("tel", { autocomplete: "cc-number" }), code = new Input("text", { autocomplete: "cc-csc" })], {
    reply: (message) => message.action === "inline_items" ? { status: "ok", items: [{ id: "c1", title: "Travel", subtitle: "" }] }
      : message.action === "inline_fill_item" ? { status: "ok", card: { number: "4111111111111111", expiry: "", hasCode: true } }
      : message.action === "inline_card_code" ? { status: "denied" } : { status: "none" } });
  await state.focus(number);
  state.clock.now += 450;
  await state.click(state.find(state.hosts()[0], (node) => node.attrs.role === "option"));
  await settle();
  assert.equal(code.value, "");
  assert.ok(state.hosts().some((host) => /Security code not filled/.test(textOf(host.closedRoot))));
});

test("authenticator code: Show all codes on demand, and the picked code fills the field", async () => {
  let totp;
  const state = await detailPage((Input) => [totp = new Input("text", { name: "totp" })], {
    reply: (message) => message.action === "inline_items" ? (message.all ? { status: "ok", items: [{ id: "k2", title: "Bank", subtitle: "me" }] } : { status: "ok", items: [] })
      : message.action === "inline_fill_item" ? { status: "ok", code: { value: "287082", secondsLeft: 12 } } : { status: "none" } });
  await state.focus(totp);
  const [dropdown] = state.hosts();
  assert.match(textOf(dropdown.closedRoot), /No code matches this site/);
  const showAll = state.find(dropdown, (node) => node.tagName === "BUTTON" && /Show all codes/.test(textOf(node)));
  state.clock.now += 450;
  await state.click(showAll);
  assert.ok(state.requests.some((request) => request.action === "inline_items" && request.all === true));
  const option = state.find(state.hosts()[0], (node) => node.attrs.role === "option");
  assert.match(textOf(option), /Bank/);
  state.clock.now += 450;
  await state.click(option);
  assert.equal(totp.value, "287082");
});

test("a code box without authenticator wording stays quiet when nothing matches", async () => {
  let box;
  const state = await detailPage((Input) => [box = new Input("text", { name: "verification_code" })], {
    reply: (message) => message.action === "inline_items" ? { status: "ok", items: [] } : { status: "none" } });
  await state.focus(box);
  assert.ok(state.requests.some((request) => request.action === "inline_items" && request.kind === "code"));
  assert.equal(state.hosts().length, 0);
});

test("a submitted address offers Save with an editable name; a card capture never carries a code", async () => {
  const prompt = { id: "d1", kind: "save_profile", host: "example.com", title: "A Person", summary: [["Address", "1 Main Road, Pune"]], canTitle: true, locked: false };
  const state = await detailPage((Input) => [
    new Input("text", { autocomplete: "name" }, "A Person"),
    new Input("text", { autocomplete: "address-line1" }, "1 Main Road"),
    new Input("text", { autocomplete: "address-level2" }, "Pune"),
  ], { reply: (message) => message.action === "capture_details" ? { status: "review", prompt } : message.action === "inline_approve" ? { status: "saved" } : { status: "none" } });
  await state.submit(true);
  const capture = state.requests.find((request) => request.action === "capture_details");
  assert.equal(capture.kind, "profile");
  assert.equal(capture.profile.address1, "1 Main Road");
  assert.equal(capture.profile.city, "Pune");
  const [card] = state.hosts();
  assert.match(textOf(card.closedRoot), /Save this address to Nuvori\?.*1 Main Road, Pune/);
  const name = state.find(card, (node) => node.tagName === "INPUT");
  name.value = "Home";
  state.clock.now += 450;
  await state.click(state.find(card, (node) => node.attrs["data-decision"] === "save"));
  const approve = state.requests.find((request) => request.action === "inline_approve");
  assert.deepEqual([approve.id, approve.decision, approve.title], ["d1", "save", "Home"]);

  const cardState = await detailPage((Input) => [
    new Input("tel", { autocomplete: "cc-number" }, "4111 1111 1111 1111"),
    new Input("text", { autocomplete: "cc-exp" }, "07/29"),
    new Input("text", { autocomplete: "cc-csc" }, "123"),
  ], { reply: () => ({ status: "none" }) });
  await cardState.submit(true);
  const cardCapture = cardState.requests.find((request) => request.action === "capture_details");
  assert.deepEqual([cardCapture.card.number, cardCapture.card.name, cardCapture.card.expiry], ["4111111111111111", "", "07/29"]);
  assert.equal(JSON.stringify(cardCapture).includes("123"), false);
});

test("login_edit: the save card's username can be corrected before saving", async () => {
  const state = await page({ reply: (message) => message.action === "inline_pending" ? { status: "ok", prompt: { ...savePrompt, canTitle: false, canEditUsername: true } } : { status: "saved" } });
  const [card] = state.hosts();
  const username = state.find(card, (node) => node.tagName === "INPUT");
  assert.equal(username.value, "synthetic-user");
  username.value = "fixed-user";
  state.clock.now += 450;
  await state.click(state.find(card, (node) => node.attrs["data-decision"] === "save"));
  assert.equal(state.requests.find((request) => request.action === "inline_approve").username, "fixed-user");
});
