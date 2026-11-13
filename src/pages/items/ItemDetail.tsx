import { useEffect, useRef, useState } from "react";
import { Folder, ImagePlus, Pencil, Star, Trash2, X } from "lucide-react";
import { Button, IconButton } from "../../components/Button";
import { Avatar, CountdownRing, EmptyState } from "../../components/Display";
import { CopyButton, DetailField } from "../../components/DetailField";
import { Spinner } from "../../components/Spinner";
import { useConfirm } from "../../app/confirm";
import { useNow } from "../../app/hooks";
import { useRouter } from "../../app/router";
import { useToast } from "../../app/toast";
import { useVault } from "../../app/vault";
import { api, type EntryPhoto, type VaultEntry } from "../../lib/api";
import { categoryForType, profileFields, profileFrom, typeLabel } from "../../lib/entries";
import { formatDateTime, groupCardNumber, groupCode, hostFromUrl, maskCard } from "../../lib/format";
import { totpAt } from "../../lib/totp";
import { useTotpCodes } from "../codes/useTotp";
import { markUsed } from "../../app/recent";

export function ItemDetailPage({ id }: { id: string }) {
  const { entries, groups, loaded, upsertEntry, removeEntry, refresh } = useVault();
  const router = useRouter();
  const toast = useToast();
  const confirm = useConfirm();
  const entry = entries.find((item) => item.id === id);
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (entry) markUsed(entry.id); }, [entry?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!entry) {
    return <div className="page page-narrow">{loaded ? <div className="card"><EmptyState icon={X} title="This item isn't here anymore" body="It may have been deleted on another device." action={<Button onClick={() => void router.back()}>Go back</Button>} /></div> : <div className="card card-padded center"><Spinner label="Loading" /></div>}</div>;
  }

  const category = categoryForType(entry.type);
  const folderNames = groups.filter((group) => entry.groupIds?.includes(group.id)).map((group) => group.name);

  const toggleFavorite = async () => {
    setBusy(true);
    try {
      const saved = await api.saveEntry({ ...entry, favorite: !entry.favorite });
      upsertEntry(saved);
      toast.success(saved.favorite ? "Added to favorites" : "Removed from favorites");
      void refresh();
    } catch (failure) {
      toast.error(failure, "Couldn't update favorites.");
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    // Undo re-creates the item from this copy; it can't bring photos back, so only offer it when there are none.
    const photoCount = await api.listEntryPhotos(entry.id).then((list) => list.length).catch(() => -1);
    const ok = await confirm({
      title: `Delete "${entry.title}"?`,
      message: `It will be removed from this PC and from paired devices on the next sync.${photoCount > 0 ? ` Its ${photoCount === 1 ? "photo" : `${photoCount} photos`} will be deleted too.` : ""}`,
      confirmLabel: "Delete", danger: true
    });
    if (!ok) return;
    setBusy(true);
    const copy = { ...entry };
    try {
      await api.deleteEntry(entry.id);
      removeEntry(entry.id);
      const undo = photoCount === 0 ? {
        label: "Undo",
        run: async () => {
          try {
            const { id: _id, createdAt: _created, updatedAt: _updated, ...rest } = copy;
            const restored = await api.saveEntry(rest);
            upsertEntry(restored);
            toast.success(`${typeLabel(copy.type)} restored`);
            void refresh();
          } catch (failure) {
            toast.error(failure, "Couldn't restore the item.");
          }
        }
      } : undefined;
      toast.success(`${typeLabel(entry.type)} deleted`, { action: undo });
      await router.back();
      void refresh();
    } catch (failure) {
      toast.error(failure, "Couldn't delete this item.");
      setBusy(false);
    }
  };

  return (
    <div className="page page-narrow">
      <section className="detail-hero">
        <Avatar title={entry.title} size="lg" />
        <div className="detail-hero-text">
          <h2>{entry.title || "Untitled"}</h2>
          <p>{typeLabel(entry.type)}{entry.type === "CARD" && entry.network ? ` · ${entry.network}` : ""}{entry.type === "PASSWORD" && entry.tertiaryValue ? ` · ${hostFromUrl(entry.tertiaryValue)}` : ""}</p>
        </div>
        <div className="detail-hero-actions">
          <IconButton label={entry.favorite ? "Remove from favorites" : "Add to favorites"} icon={Star} className={entry.favorite ? "is-favorite" : undefined} aria-pressed={entry.favorite} onClick={() => void toggleFavorite()} disabled={busy} />
          <Button icon={Pencil} onClick={() => void router.navigate({ page: "edit", id: entry.id, category })}>Edit</Button>
          <IconButton label="Delete" icon={Trash2} variant="ghost" className="btn-danger-text" onClick={() => void remove()} disabled={busy} />
        </div>
      </section>

      <div className="card fields">
        <EntryFields entry={entry} />
      </div>

      {(entry.notes || entry.tags || folderNames.length > 0) && (
        <div className="card fields">
          {entry.notes && <DetailField label="Notes" value={entry.notes} multiline />}
          {entry.tags && (
            <div className="detail-field">
              <div className="detail-field-text"><span className="detail-label">Tags</span>
                <span className="tag-list">{entry.tags.split(",").map((tag) => tag.trim()).filter(Boolean).map((tag) => <span className="tag" key={tag}>{tag}</span>)}</span>
              </div>
            </div>
          )}
          {folderNames.length > 0 && (
            <div className="detail-field">
              <div className="detail-field-text"><span className="detail-label">Folders</span>
                <span className="tag-list">{folderNames.map((name) => <span className="tag" key={name}><Folder aria-hidden="true" />{name}</span>)}</span>
              </div>
            </div>
          )}
        </div>
      )}

      <Photos entryId={entry.id} />

      <p className="detail-meta">Updated {formatDateTime(entry.updatedAt)} · Created {formatDateTime(entry.createdAt)}</p>
    </div>
  );
}

function EntryFields({ entry }: { entry: VaultEntry }) {
  switch (entry.type) {
    case "PASSWORD": return <>
      <DetailField label="Username" value={entry.primaryValue} />
      <DetailField label="Password" value={entry.secondaryValue} secret mono />
      <DetailField label="Website" value={entry.tertiaryValue} />
    </>;
    case "CARD": return <>
      <DetailField label="Card number" value={entry.primaryValue} secret mono masked={maskCard(entry.primaryValue) || "••••"} display={groupCardNumber(entry.primaryValue)} copyValue={entry.primaryValue.replace(/\D/g, "")} />
      <DetailField label="Name on card" value={entry.secondaryValue} />
      <DetailField label="Expiry" value={entry.tertiaryValue} mono />
      <DetailField label="Security code" value={entry.fourthValue} secret mono masked="•••" />
      <DetailField label="Type" value={`${entry.cardKind === "DEBIT" ? "Debit" : "Credit"}${entry.network ? ` · ${entry.network}` : ""}`} copy={false} />
    </>;
    case "AUTHENTICATOR": return <>
      <LiveCodeField entry={entry} />
      <DetailField label="Account" value={entry.primaryValue} />
      <DetailField label="Setup key" value={entry.secondaryValue} secret mono />
      <DetailField label="Settings" value={`${entry.totpAlgorithm} · ${entry.totpDigits} digits · every ${entry.totpPeriod}s`} copy={false} />
    </>;
    case "QUESTION": return <>
      <DetailField label="Question" value={entry.primaryValue} />
      <DetailField label="Answer" value={entry.secondaryValue} secret />
    </>;
    case "AUTOFILL": {
      const profile = profileFrom(entry.primaryValue);
      const filled = profileFields.filter(([key]) => profile[key].trim());
      return filled.length ? <>{filled.map(([key, label]) => <DetailField key={key} label={label} value={profile[key]} />)}</> : <DetailField label="Details" value="" copy={false} />;
    }
  }
}

function LiveCodeField({ entry }: { entry: VaultEntry }) {
  const now = useNow(1000);
  const code = useTotpCodes([entry], now).get(entry.id);
  return (
    <div className="detail-field detail-code">
      <div className="detail-field-text">
        <span className="detail-label">Code</span>
        <span className="code-value">{code?.value ? groupCode(code.value) : "••• •••"}</span>
        {code?.next && code.seconds <= 5 && <span className="code-next">Next {groupCode(code.next)}</span>}
      </div>
      <div className="detail-actions">
        {code && <CountdownRing seconds={code.seconds} period={code.period} />}
        <CopyButton label="Code" message="Code copied" secret value={async () => (await totpAt(entry))?.value ?? null} />
      </div>
    </div>
  );
}

function Photos({ entryId }: { entryId: string }) {
  const { snapshot } = useVault();
  const toast = useToast();
  const confirm = useConfirm();
  const [photos, setPhotos] = useState<EntryPhoto[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [viewing, setViewing] = useState<EntryPhoto | null>(null);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    let active = true;
    api.listEntryPhotos(entryId).then((list) => { if (active) setPhotos(list); }).catch(() => { if (active) setPhotos([]); });
    return () => { active = false; };
  }, [entryId, snapshot.revision]);

  const add = async (file?: File) => {
    if (!file) return;
    if (file.size > 10 * 1024 * 1024) { toast.warning("Choose an image under 10 MB."); return; }
    setBusy(true);
    const progress = toast.progress("Adding photo…");
    try {
      const dataUrl = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => typeof reader.result === "string" ? resolve(reader.result) : reject(new Error("Could not read image."));
        reader.onerror = () => reject(new Error("Could not read image."));
        reader.readAsDataURL(file);
      });
      const separator = dataUrl.indexOf(",");
      const mimeType = dataUrl.slice(5, dataUrl.indexOf(";"));
      await api.addEntryPhoto(entryId, mimeType, dataUrl.slice(separator + 1));
      setPhotos(await api.listEntryPhotos(entryId));
      progress.success("Photo added");
    } catch (failure) {
      progress.error(failure, "Couldn't add the photo.");
    } finally {
      setBusy(false);
      if (input.current) input.current.value = "";
    }
  };

  const remove = async (photo: EntryPhoto) => {
    if (!(await confirm({ title: "Delete this photo?", confirmLabel: "Delete photo", danger: true }))) return;
    setBusy(true);
    try {
      await api.deleteEntryPhoto(photo.id);
      setPhotos((current) => current?.filter((item) => item.id !== photo.id) ?? null);
      setViewing(null);
      toast.success("Photo deleted");
    } catch (failure) {
      toast.error(failure, "Couldn't delete the photo.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card card-padded" aria-labelledby="photos-title">
      <header className="card-header compact">
        <div className="card-heading"><h2 id="photos-title">Photos</h2></div>
        <div className="card-actions">
          <input ref={input} type="file" accept="image/jpeg,image/png,image/webp,image/gif" className="sr-only" tabIndex={-1} aria-hidden="true" onChange={(event) => void add(event.target.files?.[0])} />
          <Button size="sm" icon={ImagePlus} busy={busy} disabled={photos === null || photos.length >= 20} onClick={() => input.current?.click()}>Add photo</Button>
        </div>
      </header>
      {photos === null ? <Spinner label="Loading photos" /> : photos.length === 0 ? <p className="muted small">No photos. Add a card scan or receipt, up to 10 MB each.</p> : (
        <div className="photo-grid">
          {photos.map((photo) => (
            <figure key={photo.id} className="photo">
              <button type="button" className="photo-open" onClick={() => setViewing(photo)} aria-label={photo.isCover ? "View cover photo" : "View photo"}><img src={photo.dataUrl} alt="" /></button>
              {photo.isCover && <span className="photo-badge">Cover</span>}
              <IconButton label="Delete photo" icon={Trash2} size="sm" variant="secondary" className="photo-delete" onClick={() => void remove(photo)} disabled={busy} />
            </figure>
          ))}
        </div>
      )}
      {viewing && <PhotoViewer photo={viewing} onClose={() => setViewing(null)} />}
    </section>
  );
}

function PhotoViewer({ photo, onClose }: { photo: EntryPhoto; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => { ref.current?.showModal(); }, []);
  return (
    <dialog ref={ref} className="photo-viewer" aria-label="Photo" onCancel={(event) => { event.preventDefault(); onClose(); }} onClick={onClose}>
      <img src={photo.dataUrl} alt="Photo attached to this item" />
      <IconButton label="Close photo" icon={X} variant="secondary" className="photo-viewer-close" onClick={onClose} />
    </dialog>
  );
}
