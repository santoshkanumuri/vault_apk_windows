import { useMemo, useState, type FormEvent } from "react";
import { FileUp, Upload } from "lucide-react";
import { Button } from "../components/Button";
import { Dialog } from "../components/Dialog";
import { Checkbox, SelectField, Segmented } from "../components/Field";
import { StatusBanner } from "../components/Status";
import { useToast } from "../app/toast";
import { useVault } from "../app/vault";
import { api } from "../lib/api";
import { importChoices, importResult, itemLabel, mappingValid, matchesFilter, reviewCounts,
  type ColumnMapping, type ColumnPreview, type ImportFilter, type ImportReview, type ImportStatus } from "../lib/passwordImport";
import { base64Of, FilePicker } from "./KeepassImport";
import { passwordImportText as text, strings } from "../strings";

/** The largest export the import reads (password_import.rs MAX_FILE_BYTES). */
const MAX_BYTES = 16 * 1024 * 1024;

const statusLabel: Record<ImportStatus, string> = {
  new: text.statusNew, alreadySaved: text.statusAlreadySaved, passwordDiffers: text.statusPasswordDiffers, ambiguous: text.statusAmbiguous,
};

type Field = keyof ColumnMapping;
const fields: ReadonlyArray<{ field: Field; label: string; required: boolean }> = [
  { field: "website", label: text.website, required: true },
  { field: "username", label: text.username, required: true },
  { field: "password", label: text.password, required: true },
  { field: "title", label: text.titleColumn, required: false },
  { field: "notes", label: text.notes, required: false },
];

const message = (failure: unknown, fallback: string) =>
  typeof failure === "string" ? failure : failure instanceof Error ? failure.message : fallback;

/**
 * Import passwords as on Android: choose a browser or password manager export, match its columns
 * when the app can't tell them apart, review every login against the saved ones, then save. The
 * file is read in memory on this PC only and never stored.
 */
export function PasswordImportDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const toast = useToast();
  const { refresh } = useVault();
  const [file, setFile] = useState<File | null>(null);
  const [columns, setColumns] = useState<ColumnPreview[] | null>(null);
  const [mapping, setMapping] = useState<ColumnMapping | null>(null);
  const [review, setReview] = useState<ImportReview | null>(null);
  const [unticked, setUnticked] = useState<Set<number>>(new Set());
  const [useImported, setUseImported] = useState<Set<number>>(new Set());
  const [filter, setFilter] = useState<ImportFilter>("all");
  const [busy, setBusy] = useState<"" | "open" | "import">("");
  const [error, setError] = useState("");

  const reset = () => {
    setColumns(null); setMapping(null); setReview(null); setUnticked(new Set()); setUseImported(new Set()); setFilter("all"); setError("");
  };
  const close = () => {
    if (busy) return;
    setFile(null); reset();
    onClose();
  };

  const data = async () => {
    if (!file) throw new Error(text.chooseFile);
    if (file.size > MAX_BYTES) throw new Error(text.tooLarge);
    return base64Of(file);
  };

  /** Reads the file again with the chosen columns, if any, and shows what comes next. */
  const preview = async (chosen: ColumnMapping | null) => {
    setError("");
    setBusy("open");
    try {
      const next = await api.passwordsPreview(await data(), chosen);
      if (next.kind === "mapping") {
        setColumns(next.columns);
        setMapping(next.suggested);
        setReview(null);
      } else {
        setReview(next);
        setUnticked(new Set());
        setUseImported(new Set());
        setFilter("all");
      }
    } catch (failure) {
      setError(message(failure, text.openFailed));
    } finally {
      setBusy("");
    }
  };

  const submitFile = (event: FormEvent) => {
    event.preventDefault();
    reset();
    void preview(null);
  };

  const runImport = async () => {
    if (!review) return;
    setError("");
    setBusy("import");
    try {
      const done = await api.passwordsImport(await data(), columns ? mapping : null, importChoices(review, unticked, useImported));
      await refresh();
      toast.success(importResult(done));
      setBusy("");
      close();
    } catch (failure) {
      setError(message(failure, text.failed));
      setBusy("");
    }
  };

  const toggle = (set: Set<number>, row: number, on: boolean) => {
    const next = new Set(set);
    if (on) next.add(row); else next.delete(row);
    return next;
  };
  const visible = useMemo(() => review?.items.filter((item) => matchesFilter(filter, item.status)) ?? [], [review, filter]);
  const changed = review?.items.filter((item) => item.status === "passwordDiffers") ?? [];

  const step = review ? "review" : columns && mapping ? "columns" : "file";
  const footer = step === "review" ? <>
    <Button variant="ghost" onClick={() => { setReview(null); if (!columns) reset(); }} disabled={busy !== ""}>{strings.back}</Button>
    <Button variant="primary" icon={Upload} busy={busy === "import"} onClick={() => void runImport()}>{text.continue}</Button>
  </> : step === "columns" ? <>
    <Button variant="ghost" onClick={close} disabled={busy !== ""}>{strings.cancel}</Button>
    <Button variant="primary" busy={busy === "open"} disabled={!mapping || !mappingValid(mapping)} onClick={() => void preview(mapping)}>{text.reviewImport}</Button>
  </> : <>
    <Button variant="ghost" onClick={close} disabled={busy !== ""}>{strings.cancel}</Button>
    <Button variant="primary" type="submit" form="password-import-form" icon={FileUp} busy={busy === "open"} disabled={!file}>{strings.openFile}</Button>
  </>;

  return (
    <Dialog open={open} onClose={close} locked={busy !== ""} size="md"
      title={step === "review" && review ? text.reviewTitle(review.rows) : step === "columns" ? text.matchColumns : text.title}
      description={step === "file" ? text.description : undefined} footer={footer}>
      {error && <StatusBanner kind="error">{error}</StatusBanner>}
      {step === "file" && (
        <form id="password-import-form" className="form-stack" onSubmit={submitFile}>
          <StatusBanner kind="warning">{text.readable}</StatusBanner>
          <FilePicker label={text.file} hint={text.fileHint} accept=".csv,.tsv,.txt,.json,text/csv,application/json" file={file}
            onFile={(next) => { setFile(next); setError(""); }} />
        </form>
      )}
      {step === "columns" && mapping && columns && (
        <div className="form-stack">
          <p className="field-hint">{text.matchHint}</p>
          {fields.map(({ field, label, required }) => (
            <SelectField key={field} label={label} value={mapping[field] ?? ""}
              onValue={(value) => setMapping({ ...mapping, [field]: value === "" ? null : value })}
              options={[{ value: "", label: required ? text.chooseColumn : text.doNotImport },
                ...columns.map((column) => ({ value: column.header, label: `${column.header} · ${column.sampleShape}` }))]} />
          ))}
          {!mappingValid(mapping) && <p className="field-error" role="alert">{text.columnsInvalid}</p>}
        </div>
      )}
      {step === "review" && review && (
        <div className="form-stack password-import-review">
          <p>{reviewCounts(review)}</p>
          <Segmented label={text.filter} size="sm" value={filter} onChange={setFilter} options={[
            { value: "all", label: text.filterAll }, { value: "new", label: text.filterNew },
            { value: "alreadySaved", label: text.filterAlreadySaved }, { value: "needsDecision", label: text.filterNeedsDecision }]} />
          {changed.length > 0 && <>
            <p className="field-hint">{text.changedDefault}</p>
            <div className="button-row">
              <Button size="sm" onClick={() => setUseImported(new Set())}>{text.keepAllSaved}</Button>
              <Button size="sm" onClick={() => setUseImported(new Set(changed.map((item) => item.row)))}>{text.useAllImported}</Button>
            </div>
          </>}
          {review.ambiguous > 0 && <p className="field-hint">{text.ambiguousNote}</p>}
          <ul className="password-import-list">
            {visible.map((item) => (
              <li key={item.row} className="password-import-item">
                {item.status === "new"
                  ? <Checkbox checked={!unticked.has(item.row)} onChange={(on) => setUnticked(toggle(unticked, item.row, !on))}
                      label={<span className="password-import-label">{itemLabel(item)}</span>} />
                  : <span className="password-import-label">{itemLabel(item)}</span>}
                <span className="password-import-status">{statusLabel[item.status]}</span>
                {item.status === "passwordDiffers" && (
                  <Segmented label={text.choiceFor(itemLabel(item))} size="sm" value={useImported.has(item.row) ? "imported" : "saved"}
                    onChange={(choice) => setUseImported(toggle(useImported, item.row, choice === "imported"))}
                    options={[{ value: "saved", label: text.keepSaved }, { value: "imported", label: text.useImported }]} />
                )}
              </li>
            ))}
          </ul>
          <p className="field-hint">{text.deleteExport}</p>
        </div>
      )}
    </Dialog>
  );
}
