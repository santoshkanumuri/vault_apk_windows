// For each visible input/select on a page: its attributes, and what Nuvori lists when it is focused.
import * as d from "./driver.mjs";
export async function probe(page, { limit = 40 } = {}) {
  const fields = await page.evaluate(() => {
    const out = [];
    const all = [...document.querySelectorAll("input, select, textarea")];
    all.forEach((el, i) => {
      const r = el.getBoundingClientRect();
      const s = getComputedStyle(el);
      if (el.type === "hidden" || el.type === "submit" || el.type === "button" || el.type === "checkbox" || el.type === "radio" || r.width < 4 || r.height < 4 || s.visibility === "hidden" || s.display === "none") return;
      el.setAttribute("data-probe", String(i));
      const label = (el.labels && el.labels[0] && el.labels[0].textContent || "").trim().slice(0, 40);
      out.push({ i, tag: el.tagName.toLowerCase(), type: el.type, name: el.name, id: el.id, ac: el.getAttribute("autocomplete") || "", ph: el.placeholder || "", label });
    });
    return out;
  });
  const rows = [];
  for (const f of fields.slice(0, limit)) {
    const loc = page.locator(`[data-probe="${f.i}"]`);
    let offer = "-";
    if (f.tag === "input") {
      try {
        await page.keyboard.press("Escape").catch(() => {});
        await loc.scrollIntoViewIfNeeded({ timeout: 2000 });
        await loc.click({ timeout: 3000 });
        let list = await d.waitForSurface(page, (s) => s.kind === "list", { timeout: 1800 });
        if (!list) { await page.keyboard.press("ArrowDown"); list = await d.waitForSurface(page, (s) => s.kind === "list", { timeout: 1500 }); }
        offer = list ? list.text.split("\n")[0].replace(/\s+/g, " ").trim() + " :: " + list.options.map((o) => o.text).join(" | ") : "none";
      } catch (e) { offer = "ERR " + e.message.split("\n")[0].slice(0, 60); }
    }
    rows.push({ ...f, offer });
  }
  await page.keyboard.press("Escape").catch(() => {});
  return rows;
}
export function printRows(title, rows) {
  console.log(`\n=== ${title} (${rows.length} fields)`);
  for (const r of rows) console.log(`#${r.i} ${r.tag}[${r.type}] name=${r.name} id=${r.id} ac=${r.ac} ph="${r.ph}" label="${r.label}"  =>  ${r.offer}`);
}
