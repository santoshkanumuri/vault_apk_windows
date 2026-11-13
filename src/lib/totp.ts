export type TotpEntry = {
  secondaryValue: string;
  totpAlgorithm: string;
  totpDigits: number;
  totpPeriod: number;
};

export type TotpCode = { value: string; seconds: number; period: number; counter: number };

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const HASHES: Record<string, string> = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };

function decodeBase32(secret: string): Uint8Array | null {
  let bits = 0;
  let buffer = 0;
  const bytes: number[] = [];
  for (const char of secret.replace(/[=\s-]/g, "").toUpperCase()) {
    const digit = ALPHABET.indexOf(char);
    if (digit < 0) return null;
    buffer = ((buffer << 5) | digit) & 0xffff;
    bits += 5;
    if (bits >= 8) { bits -= 8; bytes.push((buffer >> bits) & 0xff); }
  }
  return bytes.length ? new Uint8Array(bytes) : null;
}

export function isValidSecret(secret: string): boolean {
  return /^[A-Z2-7]+=*$/.test(secret) && decodeBase32(secret) !== null;
}

/** Code for the time step that contains `nowMillis`, shifted by `stepOffset` steps (1 = next code). */
export async function totpAt(entry: TotpEntry, nowMillis = Date.now(), stepOffset = 0): Promise<TotpCode | null> {
  try {
    const bytes = decodeBase32(entry.secondaryValue);
    if (!bytes) return null;
    const period = Math.max(1, entry.totpPeriod || 30);
    const nowSeconds = Math.floor(nowMillis / 1000);
    const counter = Math.floor(nowSeconds / period) + stepOffset;
    const message = new Uint8Array(8);
    new DataView(message.buffer).setBigUint64(0, BigInt(counter));
    const key = await crypto.subtle.importKey("raw", bytes as BufferSource, { name: "HMAC", hash: HASHES[entry.totpAlgorithm] ?? "SHA-1" }, false, ["sign"]);
    const hash = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
    const offset = hash[hash.length - 1] & 0x0f;
    const binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
    const digits = Math.min(8, Math.max(6, entry.totpDigits || 6));
    return { value: String(binary % 10 ** digits).padStart(digits, "0"), seconds: period - (nowSeconds % period), period, counter };
  } catch {
    return null;
  }
}

export async function currentTotp(entry: TotpEntry, nowMillis = Date.now()) {
  return totpAt(entry, nowMillis, 0);
}
