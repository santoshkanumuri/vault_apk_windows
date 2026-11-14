/* Nuvori landing page interactions. No dependencies. palette.js (generated from the app's
   shared palette) must load first; the page still works without it. */
(() => {
  "use strict";

  const root = document.documentElement;
  const $ = (sel, el = document) => el.querySelector(sel);
  const $$ = (sel, el = document) => Array.from(el.querySelectorAll(sel));
  const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)");
  const prefersLight = matchMedia("(prefers-color-scheme: light)");
  const store = {
    get(key) { try { return localStorage.getItem(key); } catch { return null; } },
    set(key, value) { try { localStorage.setItem(key, value); } catch { /* private mode: keep it in memory */ } },
    remove(key) { try { localStorage.removeItem(key); } catch { /* ignore */ } },
  };

  /* ---------- Snack bar ---------- */
  const snack = $("#snack");
  let snackTimer;
  function toast(message) {
    snack.textContent = message;
    snack.classList.add("is-on");
    clearTimeout(snackTimer);
    snackTimer = setTimeout(() => snack.classList.remove("is-on"), 2200);
  }

  /* ---------- Theme (light / dark) ---------- */
  const themeToggle = $("#themeToggle");
  const mode = () => root.dataset.theme || (prefersLight.matches ? "light" : "dark");
  function syncThemeLabel() {
    themeToggle.setAttribute("aria-label", mode() === "dark" ? "Switch to light theme" : "Switch to dark theme");
  }
  themeToggle.addEventListener("click", () => {
    const next = mode() === "dark" ? "light" : "dark";
    root.dataset.theme = next;
    store.set("nuvori.site.theme", next);
    syncThemeLabel();
    applyAppearance();
  });
  prefersLight.addEventListener("change", () => { syncThemeLabel(); applyAppearance(); });
  syncThemeLabel();

  /* ---------- Appearance (accent + background), same palette as the apps ---------- */
  const palette = globalThis.NuvoriAppearancePalette;
  const DEFAULT = { accent: "green", surface: "sage" };
  let appearance = { ...DEFAULT };
  try { appearance = { ...DEFAULT, ...JSON.parse(store.get("nuvori.site.appearance") || "{}") }; } catch { /* keep default */ }
  if (!palette || !palette.accents[appearance.accent]) appearance.accent = DEFAULT.accent;
  if (!palette || !palette.surfaces[appearance.surface]) appearance.surface = DEFAULT.surface;

  const ACCENT_VARS = { "--accent": "primary", "--on-accent": "onPrimary", "--accent-soft": "primaryContainer", "--on-accent-soft": "onPrimaryContainer" };
  const SURFACE_VARS = { "--bg": "background", "--bg-2": "containerLow", "--surface": "container", "--surface-2": "containerHigh",
    "--surface-3": "containerHighest", "--line": "hairline", "--text": "text", "--muted": "muted", "--subtle": "subtle" };

  function applyAppearance() {
    if (!palette) return;
    const accent = palette.accents[appearance.accent] || palette.accents[DEFAULT.accent];
    const surface = palette.surfaces[appearance.surface] || palette.surfaces[DEFAULT.surface];
    const isDefault = appearance.accent === DEFAULT.accent && appearance.surface === DEFAULT.surface;
    for (const name of [...Object.keys(ACCENT_VARS), ...Object.keys(SURFACE_VARS)]) root.style.removeProperty(name);
    if (!isDefault) {
      const m = mode();
      for (const [name, key] of Object.entries(ACCENT_VARS)) root.style.setProperty(name, accent[m][key]);
      for (const [name, key] of Object.entries(SURFACE_VARS)) root.style.setProperty(name, surface[m][key]);
    }
    const now = $("[data-now]");
    if (now) now.textContent = `${accent.name} on ${surface.name}`;
    $$(".swatch[data-accent]").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.accent === appearance.accent)));
    $$(".swatch[data-surface]").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.surface === appearance.surface)));
    $$('meta[name="theme-color"]').forEach((meta) => meta.setAttribute("content", getComputedStyle(root).getPropertyValue("--bg").trim() || meta.content));
  }

  function setAppearance(next) {
    appearance = { ...appearance, ...next };
    const isDefault = appearance.accent === DEFAULT.accent && appearance.surface === DEFAULT.surface;
    if (isDefault) store.remove("nuvori.site.appearance"); else store.set("nuvori.site.appearance", JSON.stringify(appearance));
    applyAppearance();
  }

  function buildSwatches(container, items, kind) {
    if (!container || !items) return;
    container.setAttribute("role", "radiogroup");
    container.setAttribute("aria-label", kind === "accent" ? "Accent color" : "Background");
    for (const [id, item] of Object.entries(items)) {
      const b = document.createElement("button");
      b.type = "button";
      b.className = "swatch";
      b.dataset[kind] = id;
      b.setAttribute("role", "radio");
      b.setAttribute("aria-label", item.name);
      b.title = item.name;
      if (kind === "accent") b.style.setProperty("--c", item.swatch);
      else { b.style.setProperty("--c", item.swatch); b.style.setProperty("--c2", item.dark.background); }
      b.addEventListener("click", () => setAppearance({ [kind]: id }));
      container.append(b);
    }
    // Arrow keys move through a radio group, as the platform does.
    container.addEventListener("keydown", (e) => {
      const keys = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 };
      if (!(e.key in keys)) return;
      e.preventDefault();
      const buttons = $$(".swatch", container);
      const i = buttons.indexOf(document.activeElement);
      const next = buttons[(i + keys[e.key] + buttons.length) % buttons.length];
      next.focus();
      next.click();
    });
  }

  if (palette) {
    buildSwatches($("#accentSwatches"), palette.accents, "accent");
    buildSwatches($("#surfaceSwatches"), palette.surfaces, "surface");
  } else {
    const colors = $("#colors .picker-card");
    if (colors) colors.hidden = true;
  }
  $("#resetColors")?.addEventListener("click", () => { setAppearance({ ...DEFAULT }); toast("Back to Nuvori green"); });
  applyAppearance();

  /* ---------- Nav: background on scroll, active section ---------- */
  const nav = $("#nav");
  const onScroll = () => nav.classList.toggle("is-scrolled", scrollY > 8);
  addEventListener("scroll", onScroll, { passive: true });
  onScroll();

  const navLinks = new Map($$(".nav__links a").map((a) => [a.getAttribute("href").slice(1), a]));
  const sectionObserver = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      navLinks.forEach((a, id) => a.classList.toggle("is-active", id === entry.target.id));
    }
  }, { rootMargin: "-45% 0px -50% 0px" });
  navLinks.forEach((_, id) => { const s = document.getElementById(id); if (s) sectionObserver.observe(s); });

  /* ---------- Reveal on scroll, with a small stagger between siblings ---------- */
  const revealObserver = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      entry.target.classList.add("is-in");
      revealObserver.unobserve(entry.target);
    }
  }, { rootMargin: "0px 0px -8% 0px", threshold: 0.08 });
  $$(".reveal").forEach((el) => {
    const siblings = $$(":scope > .reveal", el.parentElement);
    const index = siblings.indexOf(el);
    if (index > 0) el.style.setProperty("--d", `${Math.min(index, 6) * 70}ms`);
    revealObserver.observe(el);
  });

  /* ---------- Hero parallax ---------- */
  const stage = $("#stage");
  const layers = stage ? $$("[data-depth]", stage) : [];
  if (stage && matchMedia("(pointer: fine)").matches) {
    let frame = 0;
    const hero = stage.closest(".hero");
    hero.addEventListener("pointermove", (e) => {
      if (reduceMotion.matches) return;
      cancelAnimationFrame(frame);
      frame = requestAnimationFrame(() => {
        const r = stage.getBoundingClientRect();
        const x = (e.clientX - (r.left + r.width / 2)) / r.width;
        const y = (e.clientY - (r.top + r.height / 2)) / r.height;
        for (const layer of layers) {
          const d = Number(layer.dataset.depth);
          layer.style.transform = `translate3d(${(-x * d).toFixed(1)}px, ${(-y * d).toFixed(1)}px, 0) rotateY(${(x * 4).toFixed(2)}deg) rotateX(${(-y * 4).toFixed(2)}deg)`;
        }
      });
    });
    hero.addEventListener("pointerleave", () => layers.forEach((l) => { l.style.transform = ""; }));
  }

  /* ---------- Spotlight that follows the pointer ---------- */
  $$("[data-spot]").forEach((el) => {
    el.addEventListener("pointermove", (e) => {
      const r = el.getBoundingClientRect();
      el.style.setProperty("--mx", `${e.clientX - r.left}px`);
      el.style.setProperty("--my", `${e.clientY - r.top}px`);
    });
  });

  /* ---------- Demo authenticator codes (not real codes) ---------- */
  const PERIOD = 30;
  const RING = 339.3;
  function demoCode(key, step) {
    let h = 2166136261;
    for (const ch of `${key}:${step}`) { h ^= ch.charCodeAt(0); h = Math.imul(h, 16777619); }
    const n = String((h >>> 0) % 1000000).padStart(6, "0");
    return `${n.slice(0, 3)} ${n.slice(3)}`;
  }
  let lastStep = -1;
  function tick() {
    const now = Date.now() / 1000;
    const step = Math.floor(now / PERIOD);
    const left = PERIOD - (now % PERIOD);
    $$("[data-ring]").forEach((c) => {
      c.style.strokeDashoffset = String(RING * (1 - left / PERIOD));
      c.closest(".ring")?.classList.toggle("is-low", left <= 5);
    });
    $$("[data-seconds]").forEach((el) => { el.textContent = `${Math.ceil(left)}s`; });
    if (step !== lastStep) {
      const first = lastStep === -1;
      lastStep = step;
      $$("[data-code]").forEach((el) => {
        const value = demoCode(el.dataset.code, step);
        if (first || reduceMotion.matches) { el.textContent = value; return; }
        el.classList.add("is-swapping");
        setTimeout(() => { el.textContent = value; el.classList.remove("is-swapping"); }, 250);
      });
    }
  }
  tick();
  setInterval(tick, 1000);

  /* ---------- Autofill picker demo ---------- */
  const list = $("[data-list]");
  const queryEl = $("[data-query]");
  const siteEl = $("[data-site]");
  const DEMO = [
    { site: "github.com", query: "git", key: "github" },
    { site: "online.bank.example", query: "bank", key: "bank" },
    { site: "portal.contoso.example", query: "con", key: "contoso" },
  ];
  const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  function filter(query, key) {
    $$("li", list).forEach((li) => {
      const name = li.querySelector("b").textContent.toLowerCase();
      const shown = !query || name.includes(query);
      li.classList.toggle("is-hidden", !shown);
      li.classList.toggle("is-match", Boolean(query) && li.dataset.key === key);
    });
  }
  let pickerVisible = false;
  let pickerRunning = false;
  async function runPicker() {
    if (pickerRunning) return;
    pickerRunning = true;
    let i = 0;
    while (pickerVisible) {
      const demo = DEMO[i % DEMO.length];
      siteEl.textContent = demo.site;
      for (let n = 1; n <= demo.query.length && pickerVisible; n++) {
        queryEl.textContent = demo.query.slice(0, n);
        filter(demo.query.slice(0, n), demo.key);
        await sleep(170);
      }
      await sleep(2300);
      for (let n = demo.query.length - 1; n >= 0 && pickerVisible; n--) {
        queryEl.textContent = demo.query.slice(0, n);
        filter(demo.query.slice(0, n), demo.key);
        await sleep(70);
      }
      await sleep(700);
      i++;
    }
    pickerRunning = false;
  }
  if (list) {
    if (reduceMotion.matches) {
      queryEl.textContent = DEMO[0].query;
      filter(DEMO[0].query, DEMO[0].key);
    } else {
      new IntersectionObserver(([entry]) => {
        pickerVisible = entry.isIntersecting;
        if (pickerVisible) runPicker();
      }, { threshold: 0.3 }).observe(list);
    }
  }

  /* ---------- Sync art: stop the moving dots for reduced motion ---------- */
  const syncArt = $("#syncArt");
  if (syncArt && reduceMotion.matches && syncArt.pauseAnimations) syncArt.pauseAnimations();

  /* ---------- Counters ---------- */
  const counterObserver = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      counterObserver.unobserve(entry.target);
      const el = entry.target;
      const target = Number(el.dataset.count);
      if (reduceMotion.matches || target === 0) { el.textContent = String(target); continue; }
      const start = performance.now();
      const duration = 1400;
      const step = (t) => {
        const p = Math.min(1, (t - start) / duration);
        el.textContent = String(Math.round(target * (1 - Math.pow(1 - p, 3))));
        if (p < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    }
  }, { threshold: 0.6 });
  $$("[data-count]").forEach((el) => counterObserver.observe(el));

  /* ---------- Device tabs ---------- */
  const tabs = $$('[role="tab"]');
  const ink = $(".tabs__ink");
  function placeInk(tab) {
    if (!ink || !tab) return;
    ink.style.width = `${tab.offsetWidth}px`;
    ink.style.transform = `translateX(${tab.offsetLeft}px)`;
  }
  function selectTab(tab, focus) {
    for (const t of tabs) {
      const selected = t === tab;
      t.setAttribute("aria-selected", String(selected));
      t.tabIndex = selected ? 0 : -1;
      const panel = document.getElementById(t.getAttribute("aria-controls"));
      panel.hidden = !selected;
      panel.classList.toggle("is-active", selected);
    }
    placeInk(tab);
    if (focus) tab.focus();
  }
  tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => selectTab(tab));
    tab.addEventListener("keydown", (e) => {
      const map = { ArrowRight: i + 1, ArrowLeft: i - 1, Home: 0, End: tabs.length - 1 };
      if (!(e.key in map)) return;
      e.preventDefault();
      selectTab(tabs[(map[e.key] + tabs.length) % tabs.length], true);
    });
  });
  const placeSelected = () => placeInk(tabs.find((t) => t.getAttribute("aria-selected") === "true"));
  addEventListener("resize", placeSelected);
  document.fonts?.ready.then(placeSelected);
  placeSelected();

  /* ---------- Windows screenshot slides ---------- */
  const slides = $("[data-slides]");
  if (slides) {
    const images = $$("img", slides);
    const dots = $("[data-dots]");
    let current = 0;
    let timer;
    const buttons = images.map((img, i) => {
      const b = document.createElement("button");
      b.type = "button";
      b.setAttribute("aria-label", img.alt);
      b.addEventListener("click", () => { show(i); restart(); });
      dots.append(b);
      return b;
    });
    function show(i) {
      current = (i + images.length) % images.length;
      images.forEach((img, n) => img.classList.toggle("is-active", n === current));
      buttons.forEach((b, n) => b.setAttribute("aria-current", String(n === current)));
    }
    function restart() {
      clearInterval(timer);
      if (!reduceMotion.matches) timer = setInterval(() => show(current + 1), 4500);
    }
    show(0);
    new IntersectionObserver(([entry]) => { if (entry.isIntersecting) restart(); else clearInterval(timer); }).observe(slides);
  }

  /* ---------- Download cards: flip to the QR code ---------- */
  function setFlipped(card, flipped) {
    card.classList.toggle("is-flipped", flipped);
    const front = $(".dl__front", card);
    const back = $(".dl__back", card);
    front.setAttribute("aria-hidden", String(flipped));
    back.setAttribute("aria-hidden", String(!flipped));
    $$("a, button", front).forEach((el) => { if (!el.disabled) el.tabIndex = flipped ? -1 : 0; });
    $$("button", back).forEach((el) => { el.tabIndex = flipped ? 0 : -1; });
    $("[data-flip]", card)?.setAttribute("aria-expanded", String(flipped));
  }
  $$("[data-flip]").forEach((button) => {
    const card = button.closest(".dl");
    button.addEventListener("click", () => {
      setFlipped(card, true);
      setTimeout(() => $("[data-unflip]", card)?.focus({ preventScroll: true }), reduceMotion.matches ? 0 : 400);
    });
  });
  $$("[data-unflip]").forEach((button) => {
    const card = button.closest(".dl");
    button.addEventListener("click", () => {
      setFlipped(card, false);
      $("[data-flip]", card)?.focus({ preventScroll: true });
    });
  });
  addEventListener("keydown", (e) => {
    if (e.key !== "Escape") return;
    $$(".dl.is-flipped").forEach((card) => { setFlipped(card, false); $("[data-flip]", card)?.focus({ preventScroll: true }); });
  });

  /* ---------- Copy link ---------- */
  async function copyText(text) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
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
  $$("[data-copy]").forEach((button) => {
    const label = $("span", button);
    const original = label.textContent;
    button.addEventListener("click", async () => {
      const ok = await copyText(button.dataset.copy);
      if (ok) {
        button.classList.add("is-done");
        label.textContent = "Copied";
        toast("Link copied");
        setTimeout(() => { button.classList.remove("is-done"); label.textContent = original; }, 1800);
      } else {
        toast("Copy failed. Long-press the store button to copy the link.");
      }
    });
  });

  /* ---------- FAQ: smooth open and close ---------- */
  $$("details").forEach((details) => {
    const summary = $("summary", details);
    const body = $(".faq__body", details);
    summary.addEventListener("click", (e) => {
      if (reduceMotion.matches || !body.animate) return;
      e.preventDefault();
      if (details.open) {
        const anim = body.animate({ height: [`${body.offsetHeight}px`, "0px"], opacity: [1, 0] }, { duration: 260, easing: "ease-in" });
        anim.onfinish = () => { details.open = false; };
      } else {
        details.open = true;
        body.animate({ height: ["0px", `${body.offsetHeight}px`], opacity: [0, 1] }, { duration: 340, easing: "cubic-bezier(.2,.8,.2,1)" });
      }
    });
  });

  /* ---------- Footer year ---------- */
  const year = $("[data-year]");
  if (year) year.textContent = String(new Date().getFullYear());
})();
