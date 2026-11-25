import { useState } from "react";
import { Copy } from "lucide-react";
import { Button } from "../components/Button";
import { Checkbox } from "../components/Field";
import { Dialog } from "../components/Dialog";
import { Card, SettingsGroup, SettingsRow } from "../components/Display";
import { useConfirm } from "../app/confirm";
import { useToast } from "../app/toast";
import { useVault } from "../app/vault";
import { api, type DuplicateSet, type VaultEntry } from "../lib/api";
import { entrySubtitle } from "../lib/entries";
import { plural, relativeTime } from "../lib/format";
import { strings } from "../strings";

/**
 * Settings: find logins saved twice over and delete the copies the person picks, as on Android
 * ("Exact duplicate passwords"). The vault decides what counts as a copy and checks the picked
 * IDs again before it deletes anything, so a review left open while the vault changed deletes
 * nothing. Each copy goes to Recently deleted, as any deleted item does.
 */
export function DuplicatePasswordsSection() {
  const { entries, refresh } = useVault();
  const toast = useToast();
  const confirm = useConfirm();
  const [sets, setSets] = useState<DuplicateSet[] | null>(null);
  const [chosen, setChosen] = useState<ReadonlySet<string>>(new Set());
  const [busy, setBusy] = useState(false);

  const removable = (sets ?? []).flatMap((set) => set.remove);
  const chosenIds = removable.filter((id) => chosen.has(id));
  const known = new Map(entries.map((entry) => [entry.id, entry] as const));

  const check = async () => {
    setBusy(true);
    try {
      const found = await api.duplicatePasswords();
      if (found.length === 0) {
        toast.info(strings.noExactDuplicatesFound);
        return;
      }
      setChosen(new Set());
      setSets(found);
    } catch (problem) {
      toast.error(problem);
    } finally {
      setBusy(false);
    }
  };

  const close = () => { setSets(null); setChosen(new Set()); };

  const remove = async () => {
    if (chosenIds.length === 0) return;
    const agreed = await confirm({
      title: strings.deleteTheSelectedDuplicates,
      message: `${plural(chosenIds.length, "copy", "copies")} goes to Recently deleted. ${strings.theOldestCopyInEach}`,
      confirmLabel: strings.delete,
      cancelLabel: strings.back,
      danger: true
    });
    if (!agreed) return;
    setBusy(true);
    try {
      const deleted = await api.deleteDuplicatePasswords(chosenIds);
      toast.success(`Deleted ${plural(deleted, "exact duplicate")}.`);
    } catch (problem) {
      toast.error(problem);
    } finally {
      // Either way the review is stale now: close it and show what the vault holds.
      setBusy(false);
      close();
      await refresh();
    }
  };

  return (
    <>
      <SettingsGroup title={strings.exactDuplicatePasswords} id="settings-duplicates">
        <SettingsRow icon={Copy} title={strings.checkForDuplicates} description={strings.findLoginsWhoseSavedFields}
          control={<Button size="sm" busy={busy && sets === null} onClick={() => void check()}>{strings.check}</Button>} />
      </SettingsGroup>

      <Dialog open={sets !== null} onClose={close} title={strings.reviewExactDuplicates} size="md" locked={busy}
        description={`Found ${plural(removable.length, "removable copy", "removable copies")} in ${plural((sets ?? []).length, "set")}. ${strings.nothingIsSelectedUntilYou}`}
        footer={<>
          <Button variant="ghost" onClick={close} disabled={busy}>{strings.cancel}</Button>
          <Button variant="danger" busy={busy} disabled={chosenIds.length === 0} onClick={() => void remove()}>
            {chosenIds.length === 0 ? strings.deleteSelected : `${strings.deleteSelected} (${chosenIds.length})`}
          </Button>
        </>}>
        <div className="form-stack">
          <Checkbox checked={removable.length > 0 && chosenIds.length === removable.length}
            onChange={(selected) => setChosen(selected ? new Set(removable) : new Set())} label={strings.selectAllDuplicates} />
          {(sets ?? []).map((set) => (
            <DuplicateCard key={set.keep} set={set} known={known} chosen={chosen}
              onPick={(id, selected) => setChosen((current) => {
                const next = new Set(current);
                if (selected) next.add(id); else next.delete(id);
                return next;
              })} />
          ))}
        </div>
      </Dialog>
    </>
  );
}

function DuplicateCard({ set, known, chosen, onPick }: {
  set: DuplicateSet;
  known: Map<string, VaultEntry>;
  chosen: ReadonlySet<string>;
  onPick: (id: string, selected: boolean) => void;
}) {
  const keeper = known.get(set.keep);
  return (
    <Card title={keeper?.title || "Untitled"} description={keeper ? entrySubtitle(keeper) : undefined}>
      <div className="form-stack">
        <p className="field-hint">{strings.theOldestCopyStaysEvery}</p>
        {set.remove.map((id, index) => (
          <Checkbox key={id} checked={chosen.has(id)} onChange={(selected) => onPick(id, selected)}
            label={`${strings.deleteCopy} ${index + 2}${saved(known.get(id))}`} />
        ))}
      </div>
    </Card>
  );
}

/** " · saved yesterday", when this window knows the copy. */
function saved(copy: VaultEntry | undefined): string {
  return copy?.createdAt ? ` · saved ${relativeTime(copy.createdAt).toLowerCase()}` : "";
}
