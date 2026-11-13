import { useCallback, useEffect, useRef, useState } from "react";
import { api, type BrowserStatus, type BuildStatus, type MembershipStatus, type PhotoSyncStatus, type SyncConflict, type SyncStatus } from "../lib/api";
import { clearClipboardNow } from "./clipboard";
import { useRouter } from "./router";
import { useToast } from "./toast";
import { useVault } from "./vault";

/** Current time, ticking on the second boundary. */
export function useNow(intervalMs = 1000, enabled = true): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!enabled) return;
    let timer: number;
    const tick = () => {
      setNow(Date.now());
      timer = window.setTimeout(tick, intervalMs - (Date.now() % intervalMs) + 5);
    };
    timer = window.setTimeout(tick, intervalMs - (Date.now() % intervalMs) + 5);
    return () => window.clearTimeout(timer);
  }, [intervalMs, enabled]);
  return now;
}

/** Polls an async loader while mounted and the window is visible. */
export function usePolling<T>(load: () => Promise<T>, intervalMs: number, enabled = true): { data: T | null; error: unknown; loading: boolean; reload: () => Promise<void> } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(enabled);
  const loader = useRef(load);
  loader.current = load;
  const active = useRef(true);

  const reload = useCallback(async () => {
    try {
      const next = await loader.current();
      if (!active.current) return;
      setData(next);
      setError(null);
    } catch (failure) {
      if (active.current) setError(failure ?? "error");
    } finally {
      if (active.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    active.current = true;
    if (!enabled) return () => { active.current = false; };
    void reload();
    const timer = window.setInterval(() => { if (document.visibilityState !== "hidden") void reload(); }, intervalMs);
    return () => { active.current = false; window.clearInterval(timer); };
  }, [enabled, intervalMs, reload]);

  return { data, error, loading, reload };
}

export function useSyncStatus(intervalMs = 3000) {
  const { unlocked } = useVault();
  return usePolling<SyncStatus>(api.syncStatus, intervalMs, unlocked);
}

/** Conflicts waiting for a decision. `data` stays null and `error` is set when the command is unavailable. */
export function useConflicts(intervalMs = 10000) {
  const { unlocked, snapshot } = useVault();
  const result = usePolling<SyncConflict[]>(api.listConflicts, intervalMs, unlocked && snapshot.enrolled);
  const { reload } = result;
  // Re-check right away when the vault changes (sync, resolution).
  useEffect(() => { if (unlocked && snapshot.enrolled) void reload(); }, [snapshot.revision, unlocked, snapshot.enrolled, reload]);
  return result;
}

/** Sync-group membership. Also polled when not paired, so a removal notice or pending leave still shows. */
export function useMembership(intervalMs = 8000) {
  const { unlocked, snapshot } = useVault();
  const result = usePolling<MembershipStatus>(api.membershipStatus, intervalMs, unlocked);
  const { reload } = result;
  useEffect(() => { if (unlocked) void reload(); }, [snapshot.enrolled, snapshot.revision, unlocked, reload]);
  return result;
}

export function usePhotoSyncStatus(intervalMs = 3000) {
  const { unlocked, snapshot } = useVault();
  return usePolling<PhotoSyncStatus>(api.photoSyncStatus, intervalMs, unlocked && snapshot.enrolled);
}

export function useHelloAvailable(): boolean | null {
  const [available, setAvailable] = useState<boolean | null>(null);
  useEffect(() => { api.helloAvailable().then(setAvailable).catch(() => setAvailable(false)); }, []);
  return available;
}

export function useBrowserStatus(intervalMs = 5000) {
  return usePolling<BrowserStatus>(api.browserStatus, intervalMs, true);
}

/** Build type and passkey provider state. Polled, so turning Nuvori on in Windows Settings shows up. */
export function useBuildStatus(intervalMs = 4000) {
  return usePolling<BuildStatus>(api.buildStatus, intervalMs, true);
}

/** Lock the vault, clear any copied secret, and return to the start. */
export function useLock() {
  const { setSnapshot, unlocked } = useVault();
  const router = useRouter();
  const toast = useToast();
  return useCallback(async (options?: { force?: boolean; reason?: string }) => {
    if (!unlocked) return;
    if (!options?.force && !(await router.root({ page: "home" }))) return;
    try {
      const next = await api.lockVault();
      clearClipboardNow();
      router.reset();
      setSnapshot(next);
      toast.info(options?.reason ?? "Vault locked");
    } catch (error) {
      toast.error(error, "Couldn't lock the vault.");
    }
  }, [router, setSnapshot, toast, unlocked]);
}

export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => window.matchMedia(query).matches);
  useEffect(() => {
    const media = window.matchMedia(query);
    const update = () => setMatches(media.matches);
    update();
    media.addEventListener("change", update);
    return () => media.removeEventListener("change", update);
  }, [query]);
  return matches;
}
