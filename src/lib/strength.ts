import { codeText } from "../strings.ts";
export type Strength = { score: 0 | 1 | 2 | 3 | 4; label: string; hint: string };

const common = ["password", "123456", "qwerty", "letmein", "welcome", "admin", "iloveyou", "monkey", "dragon", "abc123", "nuvori"];

/** Rough, offline strength estimate. Good enough to steer people away from weak master passwords. */
export function passwordStrength(password: string): Strength {
  if (!password) return { score: 0, label: "", hint: "" };
  const lower = password.toLowerCase();
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/\d/.test(password)) pool += 10;
  if (/[^A-Za-z0-9]/.test(password)) pool += 33;
  const unique = new Set(password).size;
  let bits = Math.log2(Math.max(pool, 1)) * password.length * Math.min(1, unique / Math.max(4, password.length * 0.6));
  if (common.some((word) => lower.includes(word))) bits -= 25;
  if (/(.)\1{2,}/.test(password)) bits -= 10;
  if (/^(?:[a-z]+|\d+)$/i.test(password)) bits -= 8;
  const score = (bits < 35 ? 0 : bits < 50 ? 1 : bits < 65 ? 2 : bits < 85 ? 3 : 4) as Strength["score"];
  const label = ["Weak", "Fair", "Good", "Strong", codeText.veryStrong][score];
  const hint = password.length < 12 ? codeText.useAtLeast12Characters
    : score < 2 ? codeText.addMoreWordsNumbersOrSymbols
    : score < 3 ? codeText.aLongerPassphraseIsEvenBetter
    : "";
  return { score, label, hint };
}
