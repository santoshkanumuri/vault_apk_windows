import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";

const read = (path) => readFileSync(new URL(path, import.meta.url), "utf8");
const palette = JSON.parse(read("../src/appearance/nuvori-appearance-v1.json"));
const css = read("../src/appearance/palette.css");

const blocks = (kind, id, mode) =>
  [...css.matchAll(new RegExp(String.raw`^:root\[data-theme="${mode}"\]\[data-${kind}="${id}"\] \{ ([^}]*) \}\r?$`, "gm"))]
    .map((match) => Object.fromEntries(match[1].split(";").map((part) => part.trim()).filter(Boolean).map((part) => part.split(/:\s*/))));

test("palette.css has one block per accent and surface per mode with the JSON values", () => {
  assert.equal(palette.accents.length, 16);
  assert.equal(palette.surfaces.length, 8);
  for (const mode of ["dark", "light"]) {
    for (const accent of palette.accents) {
      const found = blocks("accent", accent.id, mode);
      assert.equal(found.length, 1, `${accent.id} ${mode}`);
      const v = accent[mode];
      assert.deepEqual(found[0], { "--primary": v.primary, "--on-primary": v.onPrimary, "--primary-container": v.primaryContainer, "--on-primary-container": v.onPrimaryContainer, "--focus": v.primary });
    }
    for (const surface of palette.surfaces) {
      const found = blocks("surface", surface.id, mode);
      assert.equal(found.length, 1, `${surface.id} ${mode}`);
      const v = surface[mode];
      assert.deepEqual(found[0], { "--bg": v.background, "--surface": v.container, "--surface-2": v.containerHighest, "--hover": v.hover, "--text": v.text, "--muted": v.muted, "--subtle": v.subtle, "--outline": v.outline, "--hairline": v.hairline });
    }
  }
  assert.equal((css.match(/^:root\[/gm) || []).length, 2 * (16 + 8));
});

function load(path) {
  const context = vm.createContext({});
  vm.runInContext(read(path), context);
  return context;
}

test("extension/appearance-palette.js equals the JSON", () => {
  const exposed = load("./appearance-palette.js").NuvoriAppearancePalette;
  assert.equal(exposed.version, palette.version);
  assert.deepEqual(JSON.parse(JSON.stringify(exposed.defaults)), palette.defaults);
  assert.deepEqual(Object.keys(exposed.accents), palette.accents.map((item) => item.id));
  assert.deepEqual(Object.keys(exposed.surfaces), palette.surfaces.map((item) => item.id));
  for (const item of palette.accents) {
    const { id, ...rest } = item;
    assert.deepEqual(JSON.parse(JSON.stringify(exposed.accents[id])), rest);
  }
  for (const item of palette.surfaces) {
    const { id, ...rest } = item;
    assert.deepEqual(JSON.parse(JSON.stringify(exposed.surfaces[id])), rest);
  }
});

test("resolveAppearance returns the variables for ids, defaults and modes", () => {
  const context = load("./appearance-palette.js");
  vm.runInContext(read("./appearance.js"), context);
  const { resolveAppearance } = context.NuvoriAppearance;
  const p = context.NuvoriAppearancePalette;
  const second = palette.accents[3];
  const surface = palette.surfaces[2];

  const dark = resolveAppearance(p, { accent: second.id, surface: surface.id }, "dark", false);
  assert.equal(dark.mode, "dark");
  assert.equal(dark.vars["--primary"], second.dark.primary);
  assert.equal(dark.vars["--focus"], second.dark.primary);
  assert.equal(dark.vars["--on-primary"], second.dark.onPrimary);
  assert.equal(dark.vars["--pc"], second.dark.primaryContainer);
  assert.equal(dark.vars["--opc"], second.dark.onPrimaryContainer);
  assert.equal(dark.vars["--bg"], surface.dark.background);
  assert.equal(dark.vars["--surface"], surface.dark.container);
  assert.equal(dark.vars["--surface-2"], surface.dark.containerHighest);
  assert.equal(dark.vars["--hairline"], surface.dark.hairline);

  const light = resolveAppearance(p, { accent: second.id, surface: surface.id }, "light", true);
  assert.equal(light.mode, "light");
  assert.equal(light.vars["--primary"], second.light.primary);
  assert.equal(light.vars["--bg"], surface.light.background);

  assert.equal(resolveAppearance(p, null, "system", true).mode, "dark");
  assert.equal(resolveAppearance(p, null, "system", false).mode, "light");

  const green = palette.accents.find((item) => item.id === palette.defaults.accent);
  const sage = palette.surfaces.find((item) => item.id === palette.defaults.surface);
  for (const bad of [null, {}, { accent: "nope", surface: "nope" }, { accent: "../x", surface: 5 }, { accent: "constructor", surface: "__proto__" }]) {
    const result = resolveAppearance(p, bad, "dark", false);
    assert.equal(result.vars["--primary"], green.dark.primary);
    assert.equal(result.vars["--bg"], sage.dark.background);
  }
});
