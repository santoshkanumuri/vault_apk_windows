import { useMemo, useRef, useState, useEffect, type FormEvent } from "react";
import { FileText, Folder, Pencil, Plus, Save, SearchX, Trash2, X } from "lucide-react";
import { Button, IconButton } from "../../components/Button";
import { Avatar, EmptyState } from "../../components/Display";
import { CopyButton } from "../../components/DetailField";
import { Checkbox, TextArea, TextField } from "../../components/Field";
import { ListRow, useNewIds } from "../../components/ListRow";
import { Spinner } from "../../components/Spinner";
import { StatusBanner } from "../../components/Status";
import { useConfirm } from "../../app/confirm";
import { useRouteState, useRouter } from "../../app/router";
import { useToast } from "../../app/toast";
import { useVault } from "../../app/vault";
import { api, type VaultGroup } from "../../lib/api";
import { foldersFor, sortItems, type SortMode } from "../../lib/entries";
import { formatDateTime, plural, relativeTime } from "../../lib/format";
import { buildIndex, matchesFilter } from "../../lib/search";
import { FolderDialog } from "../FolderDialog";
import { useUnsavedGuard } from "../items/ItemEditor";
import { FilterInput, FolderPicker, SortPicker } from "../items/Toolbar";

export function NotesListPage() {
  const { notes, groups, loaded } = useVault();
  const router = useRouter();
  const [filter, setFilter] = useRouteState("filter", "");
  const [folderId, setFolderId] = useRouteState("folder", "");
  const [sort, setSort] = useRouteState<SortMode>("sort", "recent");
  const [folderDialog, setFolderDialog] = useState<{ folder: VaultGroup | null } | null>(null);
  const folders = foldersFor(groups, "NOTE");
  const docs = useMemo(() => buildIndex([], notes), [notes]);
  const visible = useMemo(() => {
    const ids = new Set(docs.filter((doc) => matchesFilter(doc, filter)).map((doc) => doc.id));
    return sortItems(notes.filter((note) => ids.has(note.id) && (!folderId || note.groupIds?.includes(folderId))), sort);
  }, [docs, notes, filter, folderId, sort]);
  const fresh = useNewIds(visible.map((note) => note.id));
  const add = () => void router.navigate({ page: "note-edit" });

  return (
    <div className="page">
      <div className="toolbar">
        <FilterInput value={filter} onChange={setFilter} placeholder="Filter notes" />
        <div className="toolbar-group">
          <FolderPicker folders={folders} value={folderId} onChange={setFolderId} allLabel="All folders" onNew={() => setFolderDialog({ folder: null })} onEdit={() => setFolderDialog({ folder: folders.find((folder) => folder.id === folderId) ?? null })} />
          <SortPicker value={sort} onChange={setSort} withFavorites={false} />
          <Button variant="primary" icon={Plus} onClick={add} className="toolbar-add">Add note</Button>
        </div>
      </div>
      {!loaded ? <div className="card card-padded center"><Spinner label="Loading" /></div>
        : notes.length === 0 ? <div className="card"><EmptyState icon={FileText} title="No notes yet" body="Keep private notes like Wi-Fi details or recovery steps here." action={<Button variant="primary" icon={Plus} onClick={add}>Add note</Button>} /></div>
        : visible.length === 0 ? <div className="card"><EmptyState icon={SearchX} title="No matches" action={<Button onClick={() => { setFilter(""); setFolderId(""); }}>Clear filters</Button>} /></div>
        : <>
          <p className="list-count">{plural(visible.length, "note")}</p>
          <ul className="card list" aria-label="Notes">
            {visible.map((note) => (
              <ListRow key={note.id} id={note.id} title={note.title || "Untitled"} subtitle={`${relativeTime(note.updatedAt)} · ${firstLine(note.body)}`}
                leading={<Avatar title={note.title || "Note"} icon={FileText} />} highlighted={router.highlight === note.id} entering={fresh.has(note.id)}
                onOpen={() => void router.navigate({ page: "note", id: note.id })} openLabel={`Open ${note.title}`} />
            ))}
          </ul>
        </>}
      <FolderDialog open={folderDialog !== null} folder={folderDialog?.folder} onClose={() => setFolderDialog(null)} scope="NOTE" scopeLabel="Notes"
        onSaved={(folder) => { if (!folderDialog?.folder) setFolderId(folder.id); }} onDeleted={(id) => { if (folderId === id) setFolderId(""); }} />
    </div>
  );
}

function firstLine(body: string): string {
  return (body.split(/\r?\n/).find((line) => line.trim()) ?? "").slice(0, 140);
}

export function NoteDetailPage({ id }: { id: string }) {
  const { notes, groups, loaded, removeNote, upsertNote, refresh } = useVault();
  const router = useRouter();
  const toast = useToast();
  const confirm = useConfirm();
  const [busy, setBusy] = useState(false);
  const note = notes.find((item) => item.id === id);
  if (!note) return <div className="page page-narrow">{loaded ? <div className="card"><EmptyState icon={X} title="This note isn't here anymore" action={<Button onClick={() => void router.back()}>Go back</Button>} /></div> : <Spinner label="Loading" />}</div>;
  const folderNames = groups.filter((group) => note.groupIds?.includes(group.id)).map((group) => group.name);

  const remove = async () => {
    if (!(await confirm({ title: `Delete "${note.title}"?`, message: "It will be removed from this PC and from paired devices on the next sync.", confirmLabel: "Delete", danger: true }))) return;
    setBusy(true);
    const copy = { ...note };
    try {
      await api.deleteNote(note.id);
      removeNote(note.id);
      toast.success("Note deleted", {
        action: {
          label: "Undo",
          run: async () => {
            try {
              upsertNote(await api.saveNote({ title: copy.title, body: copy.body, groupIds: copy.groupIds ?? [] }));
              toast.success("Note restored");
              void refresh();
            } catch (failure) {
              toast.error(failure, "Couldn't restore the note.");
            }
          }
        }
      });
      await router.back();
      void refresh();
    } catch (failure) {
      toast.error(failure, "Couldn't delete the note.");
      setBusy(false);
    }
  };

  return (
    <div className="page page-narrow">
      <section className="detail-hero">
        <Avatar title={note.title} icon={FileText} size="lg" />
        <div className="detail-hero-text">
          <h2>{note.title || "Untitled"}</h2>
          <p>Note · updated {relativeTime(note.updatedAt)}</p>
        </div>
        <div className="detail-hero-actions">
          <CopyButton value={note.body} label="Note" />
          <Button icon={Pencil} onClick={() => void router.navigate({ page: "note-edit", id: note.id })}>Edit</Button>
          <IconButton label="Delete" icon={Trash2} className="btn-danger-text" onClick={() => void remove()} disabled={busy} />
        </div>
      </section>
      <article className="card card-padded note-body">{note.body}</article>
      {folderNames.length > 0 && <div className="tag-list">{folderNames.map((name) => <span className="tag" key={name}><Folder aria-hidden="true" />{name}</span>)}</div>}
      <p className="detail-meta">Updated {formatDateTime(note.updatedAt)} · Created {formatDateTime(note.createdAt)}</p>
    </div>
  );
}

export function NoteEditorPage({ id }: { id?: string }) {
  const { notes, groups, upsertNote, refresh } = useVault();
  const router = useRouter();
  const toast = useToast();
  const existing = id ? notes.find((note) => note.id === id) : undefined;
  const initial = useMemo(() => ({ title: existing?.title ?? "", body: existing?.body ?? "", groupIds: [...(existing?.groupIds ?? [])] }), [existing?.id]); // eslint-disable-line react-hooks/exhaustive-deps
  const [draft, setDraft] = useState(initial);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const form = useRef<HTMLFormElement>(null);
  const dirty = JSON.stringify(draft) !== JSON.stringify(initial);
  useUnsavedGuard(dirty && !busy);
  const folders = foldersFor(groups, "NOTE");

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") { event.preventDefault(); form.current?.requestSubmit(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const save = async (event: FormEvent) => {
    event.preventDefault();
    if (!draft.title.trim() || !draft.body.trim()) { setError("Add a title and some text."); return; }
    setBusy(true); setError("");
    try {
      const saved = await api.saveNote({ id: existing?.id, title: draft.title.trim(), body: draft.body, groupIds: draft.groupIds });
      upsertNote(saved);
      toast.success("Note saved");
      router.setGuard(null);
      if (existing) await router.back();
      else await router.navigate({ page: "note", id: saved.id }, { replace: true });
      void refresh();
    } catch (failure) {
      toast.error(failure, "Couldn't save the note.");
      setBusy(false);
    }
  };

  if (id && !existing) return <div className="page page-narrow"><StatusBanner kind="warning" title="This note isn't available">It may have been deleted on another device.</StatusBanner></div>;

  return (
    <div className="page page-narrow">
      <form ref={form} className="card card-padded form-stack" onSubmit={(event) => void save(event)} noValidate>
        {error && <StatusBanner kind="error">{error}</StatusBanner>}
        <TextField label="Title" value={draft.title} onValue={(title) => setDraft((current) => ({ ...current, title }))} maxLength={500} autoFocus={!existing} required />
        <TextArea label="Note" value={draft.body} onValue={(body) => setDraft((current) => ({ ...current, body }))} rows={12} required />
        {folders.length > 0 && (
          <fieldset className="fieldset">
            <legend>Folders</legend>
            <div className="check-grid">
              {folders.map((folder) => <Checkbox key={folder.id} label={folder.name} checked={draft.groupIds.includes(folder.id)}
                onChange={(checked) => setDraft((current) => ({ ...current, groupIds: checked ? [...current.groupIds, folder.id] : current.groupIds.filter((value) => value !== folder.id) }))} />)}
            </div>
          </fieldset>
        )}
        <div className="form-actions">
          <Button variant="ghost" onClick={() => void router.back()} disabled={busy}>Cancel</Button>
          <Button variant="primary" type="submit" icon={Save} busy={busy}>Save note</Button>
        </div>
      </form>
    </div>
  );
}
