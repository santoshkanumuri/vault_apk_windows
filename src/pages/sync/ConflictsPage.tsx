import { useState } from "react";
import { CircleCheck, FileText, Fingerprint, Folder, Image, KeyRound, Laptop, Smartphone, type LucideIcon } from "lucide-react";
import { Button } from "../../components/Button";
import { EmptyState } from "../../components/Display";
import { Spinner } from "../../components/Spinner";
import { StatusBanner } from "../../components/Status";
import { useConfirm } from "../../app/confirm";
import { useConflicts } from "../../app/hooks";
import { useRouter } from "../../app/router";
import { useToast } from "../../app/toast";
import { useVault } from "../../app/vault";
import { api, type SyncConflict } from "../../lib/api";
import { formatDateTime, plural, relativeTime, toMillis } from "../../lib/format";

const typeInfo: Record<SyncConflict["entityType"], { label: string; icon: LucideIcon }> = {
  entry: { label: "Item", icon: KeyRound },
  note: { label: "Note", icon: FileText },
  folder: { label: "Folder", icon: Folder },
  passkey: { label: "Passkey", icon: Fingerprint },
  photo: { label: "Photo", icon: Image }
};

export function ConflictsPage() {
  const conflicts = useConflicts(8000);
  const { setSnapshot, refresh } = useVault();
  const router = useRouter();
  const toast = useToast();
  const confirm = useConfirm();
  const [busy, setBusy] = useState("");
  const [resolved, setResolved] = useState<string[]>([]);
  const list = (conflicts.data ?? []).filter((conflict) => !resolved.includes(conflict.id));

  const resolve = async (conflict: SyncConflict, keep: "local" | "remote") => {
    const device = conflict.remoteDevice || "your phone";
    const ok = await confirm({
      title: keep === "local" ? "Keep this PC's version?" : `Keep the version from ${device}?`,
      message: `"${conflict.title || typeInfo[conflict.entityType]?.label || "This item"}" will match this choice on every device after the next sync.`,
      confirmLabel: keep === "local" ? "Keep this PC's version" : "Keep phone version"
    });
    if (!ok) return;
    setBusy(conflict.id);
    try {
      setSnapshot(await api.resolveConflict(conflict.id, keep));
      setResolved((current) => [...current, conflict.id]);
      toast.success(keep === "local" ? "Kept this PC's version" : `Kept the version from ${device}`);
      void refresh();
      await conflicts.reload();
    } catch (failure) {
      toast.error(failure, "Couldn't resolve this conflict.");
    } finally {
      setBusy("");
    }
  };

  return (
    <div className="page page-narrow">
      {conflicts.loading && !conflicts.data ? <div className="card card-padded center"><Spinner label="Loading" /></div>
        : conflicts.error && !conflicts.data ? (
          <StatusBanner kind="warning" title="Conflict review isn't available">This version of Nuvori can't list conflicts yet. Review them on your phone under Devices.</StatusBanner>
        ) : list.length === 0 ? (
          <div className="card"><EmptyState icon={CircleCheck} title="Nothing to review" body="Changes made on both devices will appear here." action={<Button onClick={() => void router.back()}>Back</Button>} /></div>
        ) : (
          <>
            <StatusBanner kind="warning" title={`${plural(list.length, "change")} edited on both devices`}>
              Both versions are kept until you choose. Your choice syncs to every device.
            </StatusBanner>
            <ul className="conflict-list">
              {list.map((conflict) => {
                const info = typeInfo[conflict.entityType] ?? typeInfo.entry;
                const Icon = info.icon;
                const localNewer = toMillis(conflict.localUpdatedAt) >= toMillis(conflict.remoteUpdatedAt);
                return (
                  <li key={conflict.id} className="card card-padded conflict">
                    <div className="conflict-head">
                      <span className="row-icon" aria-hidden="true"><Icon /></span>
                      <div className="conflict-title">
                        <strong>{conflict.title || info.label}</strong>
                        <span className="muted small">{info.label}{conflict.summary ? ` · ${conflict.summary}` : ""}</span>
                      </div>
                    </div>
                    <div className="conflict-sides">
                      <div className="conflict-side">
                        <span className="conflict-side-label"><Laptop aria-hidden="true" />This PC{localNewer && <span className="newer">Newer</span>}</span>
                        <span title={formatDateTime(conflict.localUpdatedAt)}>Updated {relativeTime(conflict.localUpdatedAt).toLowerCase()}</span>
                        <Button variant={localNewer ? "primary" : "secondary"} block busy={busy === conflict.id} disabled={busy !== ""} onClick={() => void resolve(conflict, "local")}>Keep this PC's version</Button>
                      </div>
                      <div className="conflict-side">
                        <span className="conflict-side-label"><Smartphone aria-hidden="true" />{conflict.remoteDevice || "Phone"}{!localNewer && <span className="newer">Newer</span>}</span>
                        <span title={formatDateTime(conflict.remoteUpdatedAt)}>Updated {relativeTime(conflict.remoteUpdatedAt).toLowerCase()}</span>
                        <Button variant={!localNewer ? "primary" : "secondary"} block busy={busy === conflict.id} disabled={busy !== ""} onClick={() => void resolve(conflict, "remote")}>Keep phone version</Button>
                      </div>
                    </div>
                  </li>
                );
              })}
            </ul>
          </>
        )}
    </div>
  );
}
