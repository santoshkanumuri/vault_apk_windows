import { ArchiveRestore, Trash2 } from "lucide-react";
import { Button } from "../components/Button";
import { Avatar, EmptyState } from "../components/Display";
import { Spinner } from "../components/Spinner";
import { StatusBanner } from "../components/Status";
import { useConfirm } from "../app/confirm";
import { useNow, usePolling } from "../app/hooks";
import { useRouter } from "../app/router";
import { useToast } from "../app/toast";
import { useVault } from "../app/vault";
import { api, type TrashedItem } from "../lib/api";
import { typeLabel } from "../lib/entries";
import { formatDateTime, relativeTime } from "../lib/format";
import { TRASH_DAYS } from "../lib/trash";
import { codeText, strings } from "../strings";

function label(item: TrashedItem): string {
  return item.itemType === "NOTE" ? "Note" : typeLabel(item.itemType);
}

function daysLeft(item: TrashedItem, now: number): string {
  const days = Math.max(0, Math.ceil((item.expiresAt - now) / 86_400_000));
  return days <= 1 ? codeText.deletedForGoodTomorrow : codeText.daysLeft(days);
}

/**
 * Items deleted on this PC or on a paired device, kept on this PC for 30 days. A restore makes a
 * new item that syncs to the other devices; the copy here is not synced.
 * Also this PC's versions of items that the phone had in another version when this PC joined
 * (`reason: "join"`). They stay until the person restores or deletes them.
 * And versions from a paired device that had not applied when this PC was removed from the group
 * (`reason: "removal"`, local_recovery.rs). They stay 30 days like a deleted item.
 */
export function TrashPage() {
  const toast = useToast();
  const confirm = useConfirm();
  const router = useRouter();
  const { refresh } = useVault();
  const now = useNow(60000);
  const trash = usePolling<TrashedItem[]>(() => api.listTrash(), 10000);
  const items = trash.data ?? [];
  const joinCopies = items.filter((item) => item.reason === "join").length;

  const restore = async (item: TrashedItem) => {
    try {
      const restored = await api.restoreTrashed(item.id);
      await refresh();
      await trash.reload();
      const open = restored.kind === "note"
        ? () => void router.navigate({ page: "note", id: restored.id })
        : () => void router.navigate({ page: "item", id: restored.id });
      toast.success(item.reason === "join" ? codeText.thisPcSVersionRestoredAs(label(item).toLowerCase())
        : item.reason === "removal" ? codeText.thatVersionRestoredAsANew(label(item).toLowerCase())
        : codeText.restored(label(item)), { action: { label: strings.open, run: open } });
    } catch (failure) {
      toast.error(failure, codeText.couldnTRestoreThisItem);
    }
  };

  const forget = async (item: TrashedItem) => {
    const message = item.reason === "join" ? codeText.thisPcForgetsItsVersionYour : codeText.thisPcForgetsItsCopyYou;
    if (!(await confirm({ title: `Delete "${item.title || "Untitled"}" for good?`, message, confirmLabel: codeText.deleteForGood, danger: true }))) return;
    try {
      await api.forgetTrashed(item.id);
      await trash.reload();
    } catch (failure) {
      toast.error(failure, codeText.couldnTDeleteThisItem);
    }
  };

  const empty = async () => {
    if (!(await confirm({ title: codeText.emptyRecentlyDeleted, message: codeText.thisPcForgetsAllDeletedItems(items.length), confirmLabel: strings.empty, danger: true }))) return;
    try {
      await api.emptyTrash();
      await trash.reload();
      toast.success(codeText.recentlyDeletedIsEmpty);
    } catch (failure) {
      toast.error(failure, codeText.couldnTEmptyRecentlyDeleted);
    }
  };

  return (
    <div className="page page-narrow">
      <div className="toolbar">
        <p className="toolbar-text">{codeText.itemsDeletedOnThisPcOr(TRASH_DAYS)}</p>
        <div className="toolbar-group">
          <Button variant="ghost" icon={Trash2} onClick={() => void empty()} disabled={items.length === 0}>{strings.empty}</Button>
        </div>
      </div>
      {joinCopies > 0 && (
        <StatusBanner kind="info" title={joinCopies === 1 ? codeText.t1ItemNeedsReview : codeText.itemsNeedReview(joinCopies)}>
          When this PC joined your phone's vault, your phone had another version of {joinCopies === 1 ? codeText.thisItem : codeText.theseItems}. Your phone's version is kept. Compare, then restore this PC's version as a new item, or delete it. {joinCopies === 1 ? codeText.itStays : codeText.theyStay} here until you choose.
        </StatusBanner>
      )}
      {trash.loading && !trash.data ? <div className="card card-padded center"><Spinner label={strings.loading} /></div>
        : items.length === 0 ? <div className="card"><EmptyState icon={ArchiveRestore} title={strings.nothingDeletedRecently} body={codeText.deletedPasswordsCardsCodesAndNotes(TRASH_DAYS)} /></div>
        : (
          <ul className="card list trash-list">
            {items.map((item) => (
              <li key={item.id} className="trash-row">
                <Avatar title={item.title || "?"} />
                <span className="trash-text">
                  <span className="trash-title">{item.title || codeText.untitled}</span>
                  <span className="trash-meta">
                    {item.reason === "join" ? <><span className="badge">{strings.needsReview}</span> {label(item)} · this PC's version · set aside </>
                      : item.reason === "removal" ? <><span className="badge badge-removed" title={strings.thisPcWasRemovedFromThe}>{strings.removed}</span> {label(item)} · a paired device's version, not applied · kept </>
                      : <>{label(item)} · deleted {item.deletedElsewhere ? codeText.onAnotherDevice : ""}</>}
                    <time title={formatDateTime(item.deletedAt)}>{relativeTime(item.deletedAt, now).replace(/^Just/, "just").replace(/^Yesterday/, "yesterday")}</time>{item.reason === "join" ? "" : ` · ${daysLeft(item, now)}`}
                  </span>
                </span>
                <span className="trash-actions">
                  <Button size="sm" icon={ArchiveRestore} onClick={() => void restore(item)}>{strings.restore}</Button>
                  <Button size="sm" variant="ghost" className="btn-danger-text" onClick={() => void forget(item)}>{strings.delete}</Button>
                </span>
              </li>
            ))}
          </ul>
        )}
      <p className="detail-meta">{strings.keptOnThisPcOnlyPhotos}</p>
    </div>
  );
}
