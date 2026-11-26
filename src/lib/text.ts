// Matching text the way a person expects: accents and case ignored, and a match mapped back onto
// the original characters so it can be shown. Used by the vault's search (search.ts) and by the
// Help page (help.ts), and kept free of imports so either can be tested on its own.

/** Lowercase and strip accents so "Café" matches "cafe". */
export function fold(value: string): string {
  return value.normalize("NFD").replace(/\p{M}/gu, "").toLocaleLowerCase();
}

/** Folded text plus a map from each folded char back to its index in the original string. */
function foldWithMap(value: string): { text: string; map: number[] } {
  let text = "";
  const map: number[] = [];
  let index = 0;
  for (const char of value) {
    const folded = fold(char);
    for (let k = 0; k < folded.length; k++) { text += folded[k]; map.push(index); }
    index += char.length;
  }
  map.push(index);
  return { text, map };
}

export function tokenize(query: string): string[] {
  return fold(query).split(/\s+/).map((token) => token.trim()).filter(Boolean);
}

export type Segment = { text: string; match: boolean };

/** Splits `text` into highlighted and plain segments for every query token. */
export function highlight(text: string, tokens: string[]): Segment[] {
  if (!text || !tokens.length) return [{ text, match: false }];
  const { text: folded, map } = foldWithMap(text);
  const marks = new Array<boolean>(text.length).fill(false);
  for (const token of tokens) {
    let from = 0;
    while (from <= folded.length - token.length) {
      const at = folded.indexOf(token, from);
      if (at < 0) break;
      for (let i = map[at]; i < map[at + token.length]; i++) marks[i] = true;
      from = at + Math.max(1, token.length);
    }
  }
  const segments: Segment[] = [];
  for (let i = 0; i < text.length; i++) {
    const last = segments[segments.length - 1];
    if (last && last.match === marks[i]) last.text += text[i];
    else segments.push({ text: text[i], match: marks[i] });
  }
  return segments;
}
