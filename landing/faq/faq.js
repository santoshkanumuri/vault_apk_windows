/* Nuvori FAQ: instant search, category filter, deep links and "Copy link". No dependencies.
   Generic: it reads every <details class="qa" id="..."> inside a [data-faq-category] section.
   Adding a question needs no change here. See landing/README.md, "FAQ page". */
(() => {
  "use strict";

  const list = document.querySelector("[data-faq]");
  if (!list) return;

  const $$ = (sel, el = document) => Array.from(el.querySelectorAll(sel));
  const input = document.getElementById("faq-search");
  const searchBox = input && input.closest(".search");
  const clearButton = document.getElementById("faq-clear");
  const status = document.getElementById("faq-status");
  const empty = document.getElementById("faq-empty");
  const emptyQuery = document.getElementById("faq-empty-query");
  const chips = $$("[data-faq-filter]");
  const sections = $$("[data-faq-category]", list);
  const items = $$("details.qa[id]", list);
  const AUTO_OPEN_MAX = 6;

  /* ---------- Text folding: lower case, no accents, hyphens joined ---------- */
  const DASHES = /['’‐-―-]/g;
  function fold(text) {
    return text.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase();
  }
  function normalize(text) {
    return fold(text).replace(DASHES, "").replace(/[^a-z0-9]+/g, " ").trim();
  }

  /* Small words that should not have to appear in an answer. */
  const STOP = new Set(("a an and are as at be but by can could do does doing for from get got had has have how i if in into is it its " +
    "me my of on or our should so than that the their them then there these this to was we what when where which who why will " +
    "with would you your im ive dont cant").split(" "));

  /* Words that mean the same thing here. A query word matches any word of its group. */
  const SYNONYMS = [
    ["lost", "lose", "losing", "stolen", "steal", "theft", "missing", "broken", "broke"],
    ["phone", "mobile", "android", "tablet", "smartphone", "cellphone", "cell"],
    ["pc", "computer", "windows", "laptop", "desktop"],
    ["delete", "deleted", "remove", "removed", "erase", "wipe", "clear"],
    ["restore", "recover", "recovery", "undo"],
    ["backup", "backups", "export"],
    ["new", "replacement", "replace", "another", "second", "upgrade", "switch"],
    ["icon", "icons", "logo", "logos", "favicon"],
    ["log", "logs", "history", "activity"],
    ["drive", "cloud", "google"],
    ["wifi", "lan", "network", "router", "hotspot"],
    ["autofill", "fill", "filling", "fills"],
    ["extension", "browser", "chrome", "edge", "brave", "firefox", "addon"],
    ["free", "price", "cost", "paid", "subscription"],
    ["storage", "space", "size", "full", "grow", "grows"],
    ["stuck", "broken", "fails", "failed", "error", "problem", "working"],
    ["password", "passwords", "login", "logins"],
    ["forgot", "forgotten", "forget", "reset"],
    ["pair", "pairing", "add", "connect", "join"],
    ["leave", "quit", "stop", "separate"],
    ["passkey", "passkeys", "webauthn", "fido"],
    ["code", "codes", "totp", "authenticator", "2fa", "otp"],
    ["sync", "syncing", "synced", "synchronize"],
  ];
  const groupsByWord = new Map();
  for (const group of SYNONYMS) for (const word of group) {
    if (!groupsByWord.has(word)) groupsByWord.set(word, new Set());
    for (const other of group) groupsByWord.get(word).add(other);
  }

  /* Each query word becomes a list of forms. The typed word matches the start of a word ("sync" finds
     "syncing"). A synonym must match a whole word (or its plural), unless it has 5 letters or more. */
  function parseQuery(query) {
    const words = normalize(query).split(" ").filter(Boolean);
    const meaningful = words.filter((w) => !STOP.has(w));
    const used = meaningful.length ? meaningful : words;
    return [...new Set(used)].map((word) => {
      const forms = [{ f: word, prefix: true }];
      groupsByWord.get(word)?.forEach((f) => { if (f !== word) forms.push({ f, prefix: f.length >= 5 }); });
      return forms;
    });
  }

  function formMatches(word, form) {
    return form.prefix ? word.startsWith(form.f) : word === form.f || word === `${form.f}s`;
  }

  /* ---------- Index ---------- */
  const index = items.map((item) => {
    const section = item.closest("[data-faq-category]");
    const heading = section?.querySelector("h2")?.textContent || "";
    const text = [item.querySelector("summary")?.textContent, item.querySelector(".faq__body")?.textContent,
      item.dataset.keywords, heading].join(" ");
    return { item, section, category: section?.dataset.faqCategory || "", words: normalize(text).split(" ") };
  });
  const categoryNames = new Map(sections.map((s) => [s.dataset.faqCategory, s.querySelector("h2")?.textContent.trim() || ""]));

  function matches(entry, terms) {
    return terms.every((forms) => forms.some((form) => entry.words.some((word) => formMatches(word, form))));
  }

  /* ---------- Highlight ---------- */
  function clearHighlights() {
    const parents = new Set();
    $$("mark.faq-hit", list).forEach((mark) => {
      parents.add(mark.parentNode);
      mark.replaceWith(document.createTextNode(mark.textContent));
    });
    parents.forEach((p) => p.normalize());
  }

  function escapeRegExp(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }

  function highlight(item, terms) {
    const forms = terms.flat().sort((a, b) => b.f.length - a.f.length);
    if (!forms.length) return;
    // A hyphen or apostrophe may sit between any two letters ("wifi" finds "Wi-Fi").
    const pattern = forms.map(({ f, prefix }) => f.split("").map(escapeRegExp).join("['’\\u2010-\\u2015-]?") +
      (prefix ? "" : "s?(?![a-z0-9])")).join("|");
    const re = new RegExp(`(^|[^a-z0-9])(${pattern})`, "g");
    const roots = [item.querySelector(".qa__q"), item.querySelector(".faq__body")].filter(Boolean);
    for (const rootEl of roots) {
      const walker = document.createTreeWalker(rootEl, NodeFilter.SHOW_TEXT, {
        acceptNode: (node) => node.parentElement.closest(".qa__tools, script, style") ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT,
      });
      const nodes = [];
      while (walker.nextNode()) nodes.push(walker.currentNode);
      for (const node of nodes) {
        const original = node.nodeValue;
        // Fold character by character and remember where each folded character came from.
        let folded = "";
        const from = [];
        for (let i = 0; i < original.length; i++) {
          for (const c of fold(original[i])) { folded += c; from.push(i); }
        }
        const ranges = [];
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(folded))) {
          const start = m.index + m[1].length;
          const end = start + m[2].length;
          ranges.push([from[start], from[end - 1] + 1]);
          if (re.lastIndex === m.index) re.lastIndex++;
        }
        if (!ranges.length) continue;
        const fragment = document.createDocumentFragment();
        let at = 0;
        for (const [start, end] of ranges) {
          if (start < at) continue;
          if (start > at) fragment.append(original.slice(at, start));
          const mark = document.createElement("mark");
          mark.className = "faq-hit";
          mark.textContent = original.slice(start, end);
          fragment.append(mark);
          at = end;
        }
        if (at < original.length) fragment.append(original.slice(at));
        node.replaceWith(fragment);
      }
    }
  }

  /* ---------- State ---------- */
  let query = "";
  let category = "all";

  function plural(n, word) { return `${n} ${word}${n === 1 ? "" : "s"}`; }

  function render() {
    const terms = parseQuery(query);
    const searching = terms.length > 0;
    clearHighlights();
    items.forEach((item) => { if (item.dataset.autoOpen) { item.open = false; delete item.dataset.autoOpen; } });

    const shown = [];
    for (const entry of index) {
      const visible = (category === "all" || entry.category === category) && (!searching || matches(entry, terms));
      entry.item.hidden = !visible;
      if (visible) shown.push(entry);
    }
    sections.forEach((section) => { section.hidden = !shown.some((e) => e.section === section); });

    if (searching) {
      shown.forEach((e) => highlight(e.item, terms));
      if (shown.length <= AUTO_OPEN_MAX) shown.forEach((e) => {
        if (!e.item.open) { e.item.open = true; e.item.dataset.autoOpen = "1"; }
      });
    }

    const where = category === "all" ? "" : ` in ${categoryNames.get(category)}`;
    if (status) status.textContent = searching
      ? `${plural(shown.length, "answer")} for “${query.trim()}”${where}`
      : `${plural(shown.length, "answer")}${where}`;
    if (empty) {
      empty.hidden = shown.length > 0;
      if (emptyQuery) emptyQuery.textContent = query.trim();
    }
    if (searchBox) searchBox.classList.toggle("has-value", query.length > 0);
    if (clearButton) clearButton.hidden = query.length === 0;
    chips.forEach((chip) => chip.setAttribute("aria-current", String(chip.dataset.faqFilter === category)));
  }

  let urlTimer;
  function syncUrl() {
    clearTimeout(urlTimer);
    urlTimer = setTimeout(() => {
      const params = new URLSearchParams(location.search);
      const q = query.trim();
      if (q) params.set("q", q); else params.delete("q");
      if (category !== "all") params.set("cat", category); else params.delete("cat");
      const search = params.toString();
      const hash = q || category !== "all" ? "" : location.hash;
      history.replaceState(null, "", `${location.pathname}${search ? `?${search}` : ""}${hash}`);
    }, 250);
  }

  function setQuery(value) {
    query = value;
    if (input && input.value !== value) input.value = value;
    render();
    syncUrl();
  }

  function setCategory(value) {
    category = categoryNames.has(value) ? value : "all";
    render();
    syncUrl();
  }

  /* ---------- Deep links ---------- */
  function openFromHash(scroll) {
    let id = "";
    try { id = decodeURIComponent(location.hash.slice(1)); } catch { return; }
    if (!id) return;
    const target = document.getElementById(id);
    if (!target || !target.matches("details.qa")) return;
    if (target.hidden) { query = ""; category = "all"; if (input) input.value = ""; render(); }
    target.open = true;
    if (scroll) requestAnimationFrame(() => target.scrollIntoView({ block: "start" }));
  }

  /* ---------- Copy link ---------- */
  const snack = document.getElementById("snack");
  let snackTimer;
  function toast(message) {
    if (!snack) return;
    snack.textContent = message;
    snack.classList.add("is-on");
    clearTimeout(snackTimer);
    snackTimer = setTimeout(() => snack.classList.remove("is-on"), 2200);
  }
  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); return true; } catch {
      const area = document.createElement("textarea");
      area.value = text;
      area.setAttribute("readonly", "");
      area.style.cssText = "position:fixed;opacity:0;pointer-events:none";
      document.body.append(area);
      area.select();
      let ok = false;
      try { ok = document.execCommand("copy"); } catch { ok = false; }
      area.remove();
      return ok;
    }
  }
  const LINK_ICON = '<svg class="i" viewBox="0 0 24 24" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>';
  items.forEach((item) => {
    const body = item.querySelector(".faq__body");
    if (!body) return;
    const tools = document.createElement("p");
    tools.className = "qa__tools";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "qa__copy";
    button.innerHTML = `${LINK_ICON}<span>Copy link</span>`;
    button.setAttribute("aria-label", `Copy link to: ${item.querySelector("summary")?.textContent.trim() || item.id}`);
    const label = button.querySelector("span");
    button.addEventListener("click", async () => {
      const url = `${location.origin}${location.pathname}#${item.id}`;
      if (await copyText(url)) {
        button.classList.add("is-done");
        label.textContent = "Copied";
        toast("Link copied");
        setTimeout(() => { button.classList.remove("is-done"); label.textContent = "Copy link"; }, 1800);
      } else toast("Copy failed. Copy the address from the address bar.");
    });
    tools.append(button);
    body.append(tools);
  });

  /* ---------- Events ---------- */
  input?.addEventListener("input", () => setQuery(input.value));
  input?.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (input.value) { e.preventDefault(); setQuery(""); } else input.blur();
    }
  });
  clearButton?.addEventListener("click", () => { setQuery(""); input?.focus(); });
  $$("[data-faq-reset]").forEach((b) => b.addEventListener("click", () => {
    category = "all";
    setQuery("");
    input?.focus();
  }));
  chips.forEach((chip) => chip.addEventListener("click", (e) => {
    e.preventDefault();
    setCategory(chip.dataset.faqFilter === category && category !== "all" ? "all" : chip.dataset.faqFilter);
  }));
  addEventListener("keydown", (e) => {
    if (e.defaultPrevented || e.ctrlKey || e.metaKey || e.altKey) return;
    const el = document.activeElement;
    const typing = el && (el.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(el.tagName));
    if (e.key === "/" && !typing && input) { e.preventDefault(); input.focus(); input.select(); }
    else if (e.key === "Escape" && !typing && query) setQuery("");
  });
  addEventListener("hashchange", () => openFromHash(true));

  /* ---------- Start ---------- */
  const params = new URLSearchParams(location.search);
  query = params.get("q") || "";
  if (input) input.value = query;
  const startCategory = params.get("cat");
  category = startCategory && categoryNames.has(startCategory) ? startCategory : "all";
  render();
  openFromHash(true);
})();
