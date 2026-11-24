// One sync status over Wi-Fi and Google Drive (lib/syncOverview.ts), for the Sync page and Home.
import { useMemo } from "react";
import type { MembershipStatus, SyncStatus } from "../lib/api";
import { overviewText, syncFacts, syncOverview, type OverviewText, type SyncFacts, type SyncOverview } from "../lib/syncOverview";
import { useCloudStatus, useNow } from "./hooks";

export type SyncOverviewState = { facts: SyncFacts; overview: SyncOverview; text: OverviewText };

/**
 * Combines the Wi-Fi status, Google Drive status and each device's verified progress. `membership`
 * is the caller's own poll; without it the status rests on the transports alone.
 */
export function useSyncOverview(sync: SyncStatus | null, membership: MembershipStatus | null, conflicts: number): SyncOverviewState | null {
  const cloud = useCloudStatus(5000);
  const now = useNow(30_000);
  return useMemo(() => {
    if (!sync) return null;
    const facts = syncFacts(sync, cloud.data, membership, conflicts, now);
    const overview = syncOverview(facts);
    return { facts, overview, text: overviewText(facts, overview) };
  }, [sync, cloud.data, membership, conflicts, now]);
}
