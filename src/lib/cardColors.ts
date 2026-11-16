/**
 * Card colors. A card's color is stored and synced as an opaque ARGB number (0xFFRRGGBB), the field
 * every Nuvori version reads, so any color picked here shows on the phone without a format change.
 * The same rules as the Android app (CardColorMath.kt).
 */

/** Green, the color a card had before anyone picked one. */
export const DEFAULT_CARD_COLOR = 0xff08704a;

/**
 * Starting colors for a new card, as on Android: a new card takes the least-used one, so a wallet
 * stays varied. Any other color can be picked afterwards.
 */
const SUGGESTED = [
  0xffffffff, 0xfff5ebdd, 0xfff2765e, 0xff315b8c, 0xff413333, 0xffff7f50, 0xffffd166, 0xff06d6a0,
  0xff118ab2, 0xff9564dd, 0xffe4da72, 0xffeeeeee, 0xff722f99, 0xffc5c1c1, 0xfffee7c8, 0xffff9292,
  0xffdf301c, 0xffff9100, 0xfffff1d1, 0xff00b7cd, 0xff007dcc, 0xffffb900, 0xffd10056, 0xffffea93,
  0xff8db355, 0xff0b1849, 0xff124d1c, 0xffe4b028, 0xffebede3, 0xff215e61, 0xff000000, 0xff202020,
  0xff484848, 0xff808080,
];

const opaque = (color: number) => (0xff000000 + (color % 0x1000000 + 0x1000000) % 0x1000000);

/** "#1A2B3C", "1a2b3c" or the short "#ABC". Null for anything else. */
export function parseHex(text: string): number | null {
  const digits = text.trim().replace(/^#/, "");
  const full = digits.length === 3 ? [...digits].map((c) => c + c).join("") : digits;
  if (!/^[0-9a-fA-F]{6}$/.test(full)) return null;
  return 0xff000000 + parseInt(full, 16);
}

export function toHex(color: number): string {
  return "#" + (opaque(color) % 0x1000000).toString(16).padStart(6, "0").toUpperCase();
}

/** CSS color for an ARGB card color. */
export const css = (color: number) => toHex(color);

/** Hue in degrees (0..360), saturation and value in 0..1, to an opaque ARGB color. */
export function hsvToArgb(hue: number, saturation: number, value: number): number {
  const h = ((((hue % 360) + 360) % 360) / 60);
  const s = Math.min(1, Math.max(0, saturation));
  const v = Math.min(1, Math.max(0, value));
  const c = v * s;
  const x = c * (1 - Math.abs((h % 2) - 1));
  const [r, g, b] = h < 1 ? [c, x, 0] : h < 2 ? [x, c, 0] : h < 3 ? [0, c, x] : h < 4 ? [0, x, c] : h < 5 ? [x, 0, c] : [c, 0, x];
  const m = v - c;
  const channel = (part: number) => Math.min(255, Math.max(0, Math.round((part + m) * 255)));
  return 0xff000000 + channel(r) * 0x10000 + channel(g) * 0x100 + channel(b);
}

/** [hue 0..360, saturation 0..1, value 0..1]. A gray has hue 0. */
export function argbToHsv(color: number): [number, number, number] {
  const rgb = opaque(color) % 0x1000000;
  const r = Math.floor(rgb / 0x10000) / 255;
  const g = (Math.floor(rgb / 0x100) % 0x100) / 255;
  const b = (rgb % 0x100) / 255;
  const max = Math.max(r, g, b);
  const delta = max - Math.min(r, g, b);
  let hue = delta === 0 ? 0 : max === r ? 60 * (((g - b) / delta) % 6) : max === g ? 60 * ((b - r) / delta + 2) : 60 * ((r - g) / delta + 4);
  if (hue < 0) hue += 360;
  return [hue, max === 0 ? 0 : delta / max, max];
}

function luminance(color: number): number {
  const rgb = opaque(color) % 0x1000000;
  const lin = (c: number) => { const v = c / 255; return v <= 0.04045 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4; };
  return 0.2126 * lin(Math.floor(rgb / 0x10000)) + 0.7152 * lin(Math.floor(rgb / 0x100) % 0x100) + 0.0722 * lin(rgb % 0x100);
}

/** Black or white text, whichever reads better on the card; the same rule as the phone. */
export function inkFor(color: number): "#000000" | "#ffffff" {
  const l = luminance(color);
  return (l + 0.05) / 0.05 >= 1.05 / (l + 0.05) ? "#000000" : "#ffffff";
}

/** Very light or very dark cards get a hairline so they do not melt into the page. */
export const needsOutline = (color: number) => { const l = luminance(color); return l > 0.9 || l < 0.03; };

/** Colors on the user's other cards, most used first, for one-click reuse. */
export function usedColors(colors: number[], limit = 10): number[] {
  const counts = new Map<number, number>();
  for (const color of colors) counts.set(opaque(color), (counts.get(opaque(color)) ?? 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0] - b[0]).map(([color]) => color).slice(0, limit);
}

/** The starting color for a new card: the least-used suggestion. */
export function defaultCardColor(colors: number[]): number {
  const counts = new Map<number, number>();
  for (const color of colors) counts.set(opaque(color), (counts.get(opaque(color)) ?? 0) + 1);
  return [...SUGGESTED].sort((a, b) => (counts.get(a) ?? 0) - (counts.get(b) ?? 0))[0];
}
