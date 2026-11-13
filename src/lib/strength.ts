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
  const label = ["Weak", "Fair", "Good", "Strong", "Very strong"][score];
  const hint = password.length < 12 ? "Use at least 12 characters."
    : score < 2 ? "Add more words, numbers, or symbols."
    : score < 3 ? "A longer passphrase is even better."
    : "";
  return { score, label, hint };
}

export function generatePassword(length = 20): string {
  const sets = ["abcdefghijkmnopqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "!@#$%^&*-_=+?"];
  const all = sets.join("");
  const random = new Uint32Array(length + sets.length);
  crypto.getRandomValues(random);
  const chars = sets.map((set, i) => set[random[i] % set.length]);
  for (let i = sets.length; i < length; i++) chars.push(all[random[i] % all.length]);
  // Shuffle so the guaranteed characters are not always first.
  const order = new Uint32Array(chars.length);
  crypto.getRandomValues(order);
  for (let i = chars.length - 1; i > 0; i--) {
    const j = order[i] % (i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}
