import { useId, useRef, useState, type FormEvent } from "react";
import { FileKey, FolderOpen, Upload, X } from "lucide-react";
import { Button, IconButton } from "../components/Button";
import { Dialog } from "../components/Dialog";
import { PasswordField } from "../components/Field";
import { StatusBanner } from "../components/Status";
import { useToast } from "../app/toast";
import { useVault } from "../app/vault";
import { api, type KeepassSummary } from "../lib/api";
import { cx, plural } from "../lib/format";

/** The largest KeePass file the import reads (keepass_import.rs MAX_FILE_BYTES). */
const MAX_BYTES = 32 * 1024 * 1024;

async function base64Of(file: File): Promise<string> {
  const bytes = new Uint8Array(await file.arrayBuffer());
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  return btoa(binary);
}

/** A styled "Choose file" button with the chosen file's name, like the pairing "Read QR image" button. */
function FilePicker({ label, hint, accept, file, onFile }: { label: string; hint: string; accept: string; file: File | null; onFile: (file: File | null) => void }) {
  const id = useId();
  const input = useRef<HTMLInputElement>(null);
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <div className="file-picker">
        <Button id={id} icon={FolderOpen} onClick={() => input.current?.click()} aria-describedby={`${id}-name`}>{file ? "Change file" : "Choose file"}</Button>
        <span id={`${id}-name`} className={cx("file-picker-name", !file && "muted")}>{file ? `${file.name} · ${Math.max(1, Math.round(file.size / 1024))} KB` : "No file chosen"}</span>
        {file && <IconButton label={`Remove ${label.toLowerCase()}`} icon={X} size="sm" onClick={() => { if (input.current) input.current.value = ""; onFile(null); }} />}
      </div>
      <input ref={input} type="file" accept={accept} className="sr-only" tabIndex={-1} aria-hidden="true" onChange={(event) => onFile(event.target.files?.[0] ?? null)} />
      <span className="field-hint">{hint}</span>
    </div>
  );
}

/**
 * Import from KeePass: choose a .kdbx file and its password (and key file), see what it holds,
 * then import. The file is opened in memory on this PC only and never stored.
 */
export function KeepassImportDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useToast();
  const { refresh } = useVault();
  const [file, setFile] = useState<File | null>(null);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [password, setPassword] = useState("");
  const [preview, setPreview] = useState<KeepassSummary | null>(null);
  const [busy, setBusy] = useState<"" | "open" | "import">("");
  const [error, setError] = useState("");

  const close = () => {
    if (busy) return;
    setFile(null); setKeyFile(null); setPassword(""); setPreview(null); setError("");
    onClose();
  };

  const inputs = async () => {
    if (!file) throw new Error("Choose a KeePass file.");
    if (file.size > MAX_BYTES) throw new Error("The KeePass file is larger than 32 MB.");
    return { data: await base64Of(file), key: keyFile ? await base64Of(keyFile) : null };
  };

  const openFile = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    setBusy("open");
    try {
      const { data, key } = await inputs();
      setPreview(await api.keepassPreview(data, password, key));
    } catch (failure) {
      setError(typeof failure === "string" ? failure : failure instanceof Error ? failure.message : "The KeePass file couldn't be opened.");
    } finally {
      setBusy("");
    }
  };

  const runImport = async () => {
    setError("");
    setBusy("import");
    try {
      const { data, key } = await inputs();
      const done = await api.keepassImport(data, password, key);
      await refresh();
      const parts = [plural(done.logins, "login"), plural(done.codes, "code"), plural(done.notes, "note")].join(", ");
      toast.success(`Imported ${parts} from KeePass${done.duplicates ? `. Skipped ${plural(done.duplicates, "login")} already in Nuvori` : ""}.`);
      setBusy("");
      close();
    } catch (failure) {
      setError(typeof failure === "string" ? failure : failure instanceof Error ? failure.message : "The import stopped.");
      setBusy("");
    }
  };

  const skipped = preview ? [
    preview.inRecycleBin && `${plural(preview.inRecycleBin, "entry", "entries")} in the Recycle Bin`,
    preview.withoutContent && `${plural(preview.withoutContent, "empty entry", "empty entries")}`,
    preview.attachments && `${plural(preview.attachments, "attachment")}`,
    preview.passkeys && `${plural(preview.passkeys, "passkey")}`,
  ].filter(Boolean) as string[] : [];

  return (
    <Dialog open={open} onClose={close} locked={busy !== ""} size="md" title="Import from KeePass"
      description="KeePassXC, KeePass 2, KeePassDX and Strongbox databases (.kdbx). The file is opened on this PC only and is not stored."
      footer={preview ? <>
        <Button variant="ghost" onClick={() => setPreview(null)} disabled={busy !== ""}>Back</Button>
        <Button variant="primary" icon={Upload} busy={busy === "import"} onClick={() => void runImport()} disabled={preview.logins + preview.codes + preview.notes === 0}>Import</Button>
      </> : <>
        <Button variant="ghost" onClick={close} disabled={busy !== ""}>Cancel</Button>
        <Button variant="primary" type="submit" form="keepass-form" icon={FileKey} busy={busy === "open"} disabled={!file}>Open file</Button>
      </>}>
      {error && <StatusBanner kind="error">{error}</StatusBanner>}
      {!preview ? (
        <form id="keepass-form" className="form-stack" onSubmit={(event) => void openFile(event)}>
          <FilePicker label="KeePass database" hint="A .kdbx file" accept=".kdbx" file={file} onFile={(next) => { setFile(next); setError(""); }} />
          <PasswordField label="KeePass master password" value={password} onValue={setPassword} autoComplete="off" hint="The password of the KeePass file, not your Nuvori password." />
          <FilePicker label="Key file (optional)" hint="Only if the database uses a key file" accept=".key,.keyx,*" file={keyFile} onFile={setKeyFile} />
          <p className="field-hint">Opening the file can take a few seconds: KeePass protects it with a slow key derivation on purpose.</p>
        </form>
      ) : (
        <div className="form-stack keepass-preview">
          <p><strong>{file?.name}</strong> holds:</p>
          <ul className="keepass-counts">
            <li><strong>{preview.logins}</strong> {preview.logins === 1 ? "login" : "logins"}</li>
            <li><strong>{preview.codes}</strong> authenticator {preview.codes === 1 ? "code" : "codes"}, linked to their logins</li>
            <li><strong>{preview.notes}</strong> {preview.notes === 1 ? "note" : "notes"} (entries without a password)</li>
          </ul>
          {preview.groups.length > 0 && <p className="field-hint">Each item gets its KeePass group as a tag, for example "KeePass: {preview.groups[0]}".</p>}
          <p className="field-hint">Logins already in Nuvori with the same website, username and password are skipped. Imported items sync to your paired devices.</p>
          {skipped.length > 0 && <p className="field-hint">Not imported: {skipped.join(", ")}.</p>}
        </div>
      )}
    </Dialog>
  );
}
