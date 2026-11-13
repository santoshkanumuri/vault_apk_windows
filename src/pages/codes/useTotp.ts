import { useEffect, useRef, useState } from "react";
import type { VaultEntry } from "../../lib/api";
import { totpAt } from "../../lib/totp";

export type LiveCode = { value: string | null; next: string | null; seconds: number; period: number };

function periodOf(entry: VaultEntry) { return Math.max(1, entry.totpPeriod || 30); }

/** Live TOTP codes for a list of authenticator entries. Recomputes only when a time step changes. */
export function useTotpCodes(entries: VaultEntry[], now: number): Map<string, LiveCode> {
  const [codes, setCodes] = useState(() => new Map<string, { counter: number; value: string | null; next: string | null; key: string }>());
  const pending = useRef(0);
  const nowSeconds = Math.floor(now / 1000);
  const signature = entries.map((entry) => `${entry.id}:${Math.floor(nowSeconds / periodOf(entry))}:${entry.updatedAt}`).join("|");

  useEffect(() => {
    const token = ++pending.current;
    let cancelled = false;
    void (async () => {
      const next = new Map<string, { counter: number; value: string | null; next: string | null; key: string }>();
      for (const entry of entries) {
        const counter = Math.floor(nowSeconds / periodOf(entry));
        const key = `${counter}:${entry.updatedAt}:${entry.totpAlgorithm}:${entry.totpDigits}`;
        const cached = codes.get(entry.id);
        if (cached && cached.key === key) { next.set(entry.id, cached); continue; }
        const [current, upcoming] = await Promise.all([totpAt(entry, nowSeconds * 1000, 0), totpAt(entry, nowSeconds * 1000, 1)]);
        next.set(entry.id, { counter, value: current?.value ?? null, next: upcoming?.value ?? null, key });
      }
      if (!cancelled && token === pending.current) setCodes(next);
    })();
    return () => { cancelled = true; };
    // Recompute when the set of entries or any time step changes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [signature]);

  const result = new Map<string, LiveCode>();
  for (const entry of entries) {
    const period = periodOf(entry);
    const cached = codes.get(entry.id);
    const counter = Math.floor(nowSeconds / period);
    const fresh = cached && cached.counter === counter;
    // Right after a step change, the precomputed "next" code is already the current one.
    const rolled = cached && cached.counter === counter - 1;
    result.set(entry.id, { value: fresh ? cached.value : rolled ? cached.next : null, next: fresh ? cached.next : null, seconds: period - (nowSeconds % period), period });
  }
  return result;
}
