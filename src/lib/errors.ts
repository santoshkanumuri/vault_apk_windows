/** Turns a raw Rust/IPC error into a short, human sentence. Never includes secret input. */
export function humanError(error: unknown, fallback = "Something went wrong. Try again."): string {
  const raw = typeof error === "string" ? error : error instanceof Error ? error.message : error && typeof error === "object" && "message" in error ? String((error as { message: unknown }).message) : "";
  const text = raw.trim();
  if (!text) return fallback;
  const lower = text.toLowerCase();

  if (lower.includes("__tauri_internals__") || lower.includes("reading 'invoke'") || lower.includes("ipc") && lower.includes("not available") || lower.includes("window.__tauri")) {
    return "Nuvori's desktop service isn't available.";
  }
  if (lower.includes("command") && lower.includes("not found")) return "This feature needs a newer version of Nuvori.";
  if (lower.includes("wrong password")) return "That password didn't work. Check it and try again.";
  if (lower.includes("unlock the vault first") || lower.includes("vault is locked")) return "Unlock the vault first.";
  if (lower.includes("connection refused") || lower.includes("actively refused") || lower.includes("os error 10061")) {
    return "Couldn't reach your phone. Open Nuvori on the phone and check it's on the same Wi-Fi.";
  }
  if (lower.includes("timed out") || lower.includes("os error 10060") || lower.includes("timeout")) {
    return "Your phone didn't answer in time. Check that it's awake and on the same Wi-Fi.";
  }
  if (lower.includes("no route to host") || lower.includes("network is unreachable") || lower.includes("os error 10065") || lower.includes("os error 10051")) {
    return "This PC can't reach your phone's network. Check the Wi-Fi connection.";
  }
  if (lower.includes("invalid ip") || lower.includes("invalid socket address") || lower.includes("invalid address")) {
    return "Enter the phone's Wi-Fi address, like 192.168.1.24.";
  }
  if (lower.includes("already running")) return "A sync is already running.";
  if (lower.includes("canceled") || lower.includes("cancelled")) return "Canceled.";
  if (lower.includes("notallowederror") || lower.includes("permission denied")) return "Permission was denied.";

  // Rust messages are already plain sentences; tidy them up.
  const cleaned = text.replace(/^error:\s*/i, "").replace(/\s+/g, " ");
  const capitalized = cleaned.charAt(0).toUpperCase() + cleaned.slice(1);
  return /[.!?]$/.test(capitalized) ? capitalized : `${capitalized}.`;
}

export function isUnavailable(error: unknown): boolean {
  const text = String(error ?? "").toLowerCase();
  return text.includes("not found") || text.includes("unknown command") || text.includes("__tauri") || text.includes("invoke");
}
