import { useEffect, useState, type FormEvent } from "react";
import { Trash2 } from "lucide-react";
import { Button } from "../components/Button";
import { Dialog } from "../components/Dialog";
import { SelectField, TextArea, TextField } from "../components/Field";
import { useConfirm } from "../app/confirm";
import { useToast } from "../app/toast";
import { useVault } from "../app/vault";
import { api, type VaultGroup } from "../lib/api";

type Props = {
  open: boolean;
  onClose: () => void;
  /** Entry type or "NOTE" for the category the folder is created from. */
  scope: string;
  scopeLabel: string;
  folder?: VaultGroup | null;
  onDeleted?: (id: string) => void;
  onSaved?: (folder: VaultGroup) => void;
};

export function FolderDialog({ open, onClose, scope, scopeLabel, folder, onDeleted, onSaved }: Props) {
  const { refresh } = useVault();
  const toast = useToast();
  const confirm = useConfirm();
  const [name, setName] = useState("");
  const [notes, setNotes] = useState("");
  const [folderType, setFolderType] = useState(scope);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!open) return;
    setName(folder?.name ?? "");
    setNotes(folder?.notes ?? "");
    setFolderType(folder ? folder.folderType : scope);
    setError("");
  }, [open, folder, scope]);

  const save = async (event: FormEvent) => {
    event.preventDefault();
    if (!name.trim()) { setError("Give the folder a name."); return; }
    setBusy(true);
    try {
      const saved = await api.saveGroup({ id: folder?.id, name: name.trim(), notes, folderType });
      toast.success(folder ? "Folder updated" : "Folder created");
      await refresh();
      onSaved?.(saved);
      onClose();
    } catch (failure) {
      toast.error(failure, "Couldn't save the folder.");
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    if (!folder) return;
    const ok = await confirm({ title: `Delete "${folder.name}"?`, message: "Items in this folder stay in your vault.", confirmLabel: "Delete folder", danger: true });
    if (!ok) return;
    setBusy(true);
    try {
      await api.deleteGroup(folder.id);
      toast.success("Folder deleted");
      onDeleted?.(folder.id);
      await refresh();
      onClose();
    } catch (failure) {
      toast.error(failure, "Couldn't delete the folder.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onClose={onClose} title={folder ? "Edit folder" : "New folder"} locked={busy}
      footer={<>
        {folder && <Button variant="ghost" className="btn-danger-text push-start" icon={Trash2} onClick={() => void remove()} disabled={busy}>Delete</Button>}
        <Button variant="ghost" onClick={onClose} disabled={busy}>Cancel</Button>
        <Button variant="primary" type="submit" form="folder-form" busy={busy}>Save</Button>
      </>}>
      <form id="folder-form" className="form-stack" onSubmit={(event) => void save(event)}>
        <TextField label="Name" value={name} onValue={(value) => { setName(value); setError(""); }} error={error} maxLength={120} required data-autofocus />
        <SelectField label="Available in" value={folderType} onValue={setFolderType} options={[{ value: scope, label: scopeLabel }, { value: "", label: "All categories" }, ...(folder && folder.folderType !== scope && folder.folderType !== "" ? [{ value: folder.folderType, label: "Its original category" }] : [])]} />
        <TextArea label="Notes" value={notes} onValue={setNotes} rows={3} hint="Optional" />
      </form>
    </Dialog>
  );
}
