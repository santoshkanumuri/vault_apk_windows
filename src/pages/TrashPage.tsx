import { ArchiveRestore, Trash2 } from "lucide-react";
import { Button } from "../components/Button";
import { Avatar, EmptyState } from "../components/Display";
import { Spinner } from "../components/Spinner";
import { useConfirm } from "../app/confirm";
import { useNow, usePolling } from "../app/hooks";
import { useRouter } from "../app/router";
import { useToast } from "../app/toast";
import { useVault } from "../app/vault";
import { api, type TrashedItem } from "../lib/api";
import { typeLabel } from "../lib/entries";
import { formatDateTime, relativeTime } from "../lib/format";
import { TRASH_DAYS } from "../lib/trash";

function label(item: TrashedItem): string {
  return item.itemType === "NOTE" ? "Note" : typeLabel(item.itemType);
}

function daysLeft(item: TrashedItem, now: number): string {
  const days = Math.max(0, Math.ceil((item.expiresAt - now) / 86_400_000));
  return days <= 1 ? "Deleted for good tomorrow" : `${days} days left`;
}

/**
 * Items deleted on this PC or on a paired device, kept on this PC for 30 days. A restore makes a
 * new item that syncs to the other devices; the copy here is not synced.
 */
export function TrashPage() {
  const toast = useToast();
  const confirm = useConfirm();
  const router = useRouter();
  const { refresh } = useVault();
  const now = useNow(60000);
  const trash = usePolling<TrashedItem[]>(() => api.listTrash(), 10000);
  const items = trash.data ?? [];

  const restore = async (item: TrashedItem) => {
    try {
      const restored = await api.restoreTrashed(item.id);
      await refresh();
      await trash.reload();
      const open = restored.kind === "note"
        ? () => void router.navigate({ page: "note", id: restored.id })
        : () => void router.navigate({ page: "item", id: restored.id });
      toast.success(`${label(item)} restored`, { action: { label: "Open", run: open } });
    } catch (failure) {
      toast.error(failure, "Couldn't restore this item.");
    }
  };

  const forget = async (item: TrashedItem) => {
    if (!(await confirm({ title: `Delete "${item.title || "Untitled"}" for good?`, message: "This PC forgets its copy. You can't undo this.", confirmLabel: "Delete for good", danger: true }))) return;
    try {
      await api.forgetTrashed(item.id);
      await trash.reload();
    } catch (failure) {
      toast.error(failure, "Couldn't delete this item.");
    }
  };

  const empty = async () => {
    if (!(await confirm({ title: "Empty Recently deleted?", message: `This PC forgets all ${items.length} deleted items. You can't undo this.`, confirmLabel: "Empty", danger: true }))) return;
    try {
      await api.emptyTrash();
      await trash.reload();
      toast.success("Recently deleted is empty");
    } catch (failure) {
      toast.error(failure, "Couldn't empty Recently deleted.");
    }
  };

  return (
    <div className="page page-narrow">
      <div className="toolbar">
        <p className="toolbar-text">Items deleted on this PC or on a paired device stay here for {TRASH_DAYS} days. A restored item syncs to your other devices.</p>
        <div className="toolbar-group">
          <Button variant="ghost" icon={Trash2} onClick={() => void empty()} disabled={items.length === 0}>Empty</Button>
        </div>
      </div>
      {trash.loading && !trash.data ? <div className="card card-padded center"><Spinner label="Loading" /></div>
        : items.length === 0 ? <div className="card"><EmptyState icon={ArchiveRestore} title="Nothing deleted recently" body={`Deleted passwords, cards, codes and notes stay here for ${TRASH_DAYS} days.`} /></div>
        : (
          <ul className="card list trash-list">
            {items.map((item) => (
              <li key={item.id} className="trash-row">
                <Avatar title={item.title || "?"} />
                <span className="trash-text">
                  <span className="trash-title">{item.title || "Untitled"}</span>
                  <span className="trash-meta">
                    {label(item)} · deleted {item.deletedElsewhere ? "on another device " : ""}
                    <time title={formatDateTime(item.deletedAt)}>{relativeTime(item.deletedAt, now).replace(/^Just/, "just")}</time> · {daysLeft(item, now)}
                  </span>
                </span>
                <span className="trash-actions">
                  <Button size="sm" icon={ArchiveRestore} onClick={() => void restore(item)}>Restore</Button>
                  <Button size="sm" variant="ghost" className="btn-danger-text" onClick={() => void forget(item)}>Delete</Button>
                </span>
              </li>
            ))}
          </ul>
        )}
      <p className="detail-meta">Kept on this PC only. Photos and passkeys are not kept; logins keep their previous passwords.</p>
    </div>
  );
}
