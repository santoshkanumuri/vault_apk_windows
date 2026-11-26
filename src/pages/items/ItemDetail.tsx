import { useEffect, useRef, useState } from "react";
import { CopyPlus, Folder, History, ImagePlus, Pencil, Star, Trash2, X } from "lucide-react";
import { Button, IconButton } from "../../components/Button";
import { Avatar, CountdownRing, EmptyState } from "../../components/Display";
import { CardFace } from "../../components/CardFace";
import { CopyButton, DetailField } from "../../components/DetailField";
import { Spinner } from "../../components/Spinner";
import { useConfirm } from "../../app/confirm";
import { useNow } from "../../app/hooks";
import { useRouter } from "../../app/router";
import { useToast } from "../../app/toast";
import { useVault } from "../../app/vault";
import { api, type EntryPhoto, type PreviousPassword, type VaultEntry } from "../../lib/api";
import { deleteMessage, restoreDeleted } from "../../lib/trash";
import { categoryForType, profileFields, profileFrom, typeLabel } from "../../lib/entries";
import { codeLabel, linkedCode } from "../../lib/linkedCode";
import { iconHints } from "../../lib/siteIcons";
import { formatDateTime, groupCardNumber, groupCode, hostFromUrl, maskCard, relativeTime } from "../../lib/format";
import { totpAt } from "../../lib/totp";
import { useTotpCodes } from "../codes/useTotp";
import { markUsed } from "../../app/recent";
import { LoginSignIns } from "../signins/SignInsPage";
import { codeText, strings } from "../../strings";
import { StatusBanner } from "../../components/Status";
import { cardExpiryKind } from "../../lib/cardExpiry";

export function ItemDetailPage({ id }: { id: string }) {
  const { entries, groups, loaded, upsertEntry, removeEntry, refresh } = useVault();
  const router = useRouter();
  const toast = useToast();
  const confirm = useConfirm();
  const entry = entries.find((item) => item.id === id);
  const [busy, setBusy] = useState(false);
  useEffect(() => { if (entry) markUsed(entry.id); }, [entry?.id]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!entry) {
    return <div className="page page-narrow">{loaded ? <div className="card"><EmptyState icon={X} title={strings.thisItemIsnTHereAnymore} body={strings.itMayHaveBeenDeletedOn} action={<Button onClick={() => void router.back()}>{strings.goBack}</Button>} /></div> : <div className="card card-padded center"><Spinner label={strings.loading} /></div>}</div>;
  }

  const category = categoryForType(entry.type);
  const folderNames = groups.filter((group) => entry.groupIds?.includes(group.id)).map((group) => group.name);

  const toggleFavorite = async () => {
    setBusy(true);
    try {
      const saved = await api.saveEntry({ ...entry, favorite: !entry.favorite });
      upsertEntry(saved);
      toast.success(saved.favorite ? codeText.addedToFavorites : codeText.removedFromFavorites);
      void refresh();
    } catch (failure) {
      toast.error(failure, codeText.couldnTUpdateFavorites);
    } finally {
      setBusy(false);
    }
  };

  // As on Android: a new item with the same details and folders, without this item's password, card
  // number, cardholder, security code or answer. Opens the copy so those can be filled in.
  const duplicate = async () => {
    setBusy(true);
    try {
      const copy = await api.duplicateEntry(entry.id);
      upsertEntry(copy);
      toast.success(strings.copyCreated);
      void refresh();
      await router.navigate({ page: "item", id: copy.id });
    } catch (failure) {
      toast.error(failure, strings.couldnTCreateACopy);
    } finally {
      setBusy(false);
    }
  };

  const remove = async () => {
    // Recently deleted keeps the item's fields, folders and previous passwords, not its photos.
    const photoCount = await api.listEntryPhotos(entry.id).then((list) => list.length).catch(() => -1);
    const ok = await confirm({
      title: codeText.delete2(entry.title),
      message: `${deleteMessage}${photoCount > 0 ? ` Its ${photoCount === 1 ? "photo is" : `${photoCount} photos are`} deleted for good.` : ""}`,
      confirmLabel: strings.delete, danger: true
    });
    if (!ok) return;
    setBusy(true);
    const copy = { ...entry };
    try {
      await api.deleteEntry(entry.id);
      removeEntry(entry.id);
      const undo = {
        label: codeText.undo,
        run: async () => {
          try {
            await restoreDeleted(copy.id);
            toast.success(codeText.restored2(typeLabel(copy.type)));
            void refresh();
          } catch (failure) {
            toast.error(failure, codeText.couldnTRestoreTheItemOpen);
          }
        }
      };
      toast.success(codeText.deleted(typeLabel(entry.type)), { action: undo });
      await router.back();
      void refresh();
    } catch (failure) {
      toast.error(failure, codeText.couldnTDeleteThisItem);
      setBusy(false);
    }
  };

  return (
    <div className="page page-narrow">
      {entry.type === "CARD" && <div className="detail-card"><CardFace entry={entry} size="lg" /></div>}
      {entry.type === "CARD" && <CardExpiryBanner expiry={entry.tertiaryValue} />}
      <section className="detail-hero">
        {entry.type !== "CARD" && <Avatar title={entry.title} size="lg" {...iconHints(entry, entries)} />}
        <div className="detail-hero-text">
          <h2>{entry.title || codeText.untitled}</h2>
          <p>{typeLabel(entry.type)}{entry.type === "CARD" && entry.network ? ` · ${entry.network}` : ""}{entry.type === "PASSWORD" && entry.tertiaryValue ? ` · ${hostFromUrl(entry.tertiaryValue)}` : ""}</p>
        </div>
        <div className="detail-hero-actions">
          <IconButton label={entry.favorite ? codeText.removeFromFavorites : codeText.addToFavorites} icon={Star} className={entry.favorite ? "is-favorite" : undefined} aria-pressed={entry.favorite} onClick={() => void toggleFavorite()} disabled={busy} />
          <Button icon={Pencil} onClick={() => void router.navigate({ page: "edit", id: entry.id, category })}>{strings.edit}</Button>
          {entry.type !== "AUTHENTICATOR" && <IconButton label={strings.duplicate} icon={CopyPlus} variant="ghost" onClick={() => void duplicate()} disabled={busy} />}
          <IconButton label={strings.delete} icon={Trash2} variant="ghost" className="btn-danger-text" onClick={() => void remove()} disabled={busy} />
        </div>
      </section>

      <div className="card fields">
        <EntryFields entry={entry} entries={entries} />
      </div>

      {(entry.notes || entry.tags || folderNames.length > 0) && (
        <div className="card fields">
          {entry.notes && <DetailField label={strings.notes} value={entry.notes} multiline />}
          {entry.tags && (
            <div className="detail-field">
              <div className="detail-field-text"><span className="detail-label">{strings.tags}</span>
                <span className="tag-list">{entry.tags.split(",").map((tag) => tag.trim()).filter(Boolean).map((tag) => <span className="tag" key={tag}>{tag}</span>)}</span>
              </div>
            </div>
          )}
          {folderNames.length > 0 && (
            <div className="detail-field">
              <div className="detail-field-text"><span className="detail-label">{strings.folders}</span>
                <span className="tag-list">{folderNames.map((name) => <span className="tag" key={name}><Folder aria-hidden="true" />{name}</span>)}</span>
              </div>
            </div>
          )}
        </div>
      )}

      {entry.type === "PASSWORD" && <LoginSignIns loginId={entry.id} />}
      {entry.type === "PASSWORD" && <PreviousPasswords entryId={entry.id} updatedAt={entry.updatedAt} />}

      <Photos entryId={entry.id} entryType={entry.type} />

      <p className="detail-meta">{codeText.updatedCreated(formatDateTime(entry.updatedAt), formatDateTime(entry.createdAt))}</p>
    </div>
  );
}

/**
 * Earlier passwords of a login, newest first (up to 10). This PC keeps them when the password
 * changes here or on a paired device. They are not synced.
 */
function PreviousPasswords({ entryId, updatedAt }: { entryId: string; updatedAt: number }) {
  const confirm = useConfirm();
  const toast = useToast();
  const [list, setList] = useState<PreviousPassword[]>([]);
  const [open, setOpen] = useState(false);
  const now = useNow(60000);
  useEffect(() => {
    let live = true;
    api.previousPasswords(entryId).then((items) => { if (live) setList(items); }, () => { if (live) setList([]); });
    return () => { live = false; };
  }, [entryId, updatedAt]);
  if (list.length === 0) return null;

  const clear = async () => {
    if (!(await confirm({ title: codeText.clearPreviousPasswords, message: codeText.thisPcForgetsTheEarlierPasswords, confirmLabel: strings.clear, danger: true }))) return;
    try {
      await api.clearPreviousPasswords(entryId);
      setList([]);
      toast.success(codeText.previousPasswordsCleared);
    } catch (failure) {
      toast.error(failure, codeText.couldnTClearThePreviousPasswords);
    }
  };

  return (
    <div className="card fields previous-passwords">
      <button type="button" className="previous-passwords-toggle" aria-expanded={open} onClick={() => setOpen((value) => !value)}>
        <History aria-hidden="true" />
        <span>{strings.previousPasswords}</span>
        <span className="previous-passwords-count">{list.length}</span>
      </button>
      {open && <>
        {list.map((item, index) => (
          <DetailField key={`${item.replacedAt}-${index}`} label={codeText.replaced(relativeTime(item.replacedAt, now))} value={item.password} secret mono />
        ))}
        <div className="previous-passwords-footer">
          <span className="detail-meta">{strings.keptOnThisPcOnlyUp}</span>
          <Button variant="ghost" size="sm" icon={Trash2} onClick={() => void clear()}>{strings.clear}</Button>
        </div>
      </>}
    </div>
  );
}

/** Android's card details show "Expired" or "Expires soon" under the card face. */
function CardExpiryBanner({ expiry }: { expiry: string }) {
  const now = useNow(60000);
  const kind = cardExpiryKind(expiry, now);
  if (!kind) return null;
  return <StatusBanner kind={kind} className="detail-expiry">{kind === "error" ? strings.expired : strings.expiresSoon}</StatusBanner>;
}

function EntryFields({ entry, entries }: { entry: VaultEntry; entries: VaultEntry[] }) {
  const code = linkedCode(entry, entries);
  switch (entry.type) {
    case "PASSWORD": return <>
      <DetailField label={strings.username} value={entry.primaryValue} />
      <DetailField label={strings.password} value={entry.secondaryValue} secret mono />
      <DetailField label={strings.website} value={entry.tertiaryValue} />
      {code && <LiveCodeField entry={code} label={strings.linkedCode} note={codeLabel(code)} />}
    </>;
    case "CARD": return <>
      <DetailField label={strings.cardNumber} value={entry.primaryValue} secret mono masked={maskCard(entry.primaryValue) || "••••"} display={groupCardNumber(entry.primaryValue)} copyValue={entry.primaryValue.replace(/\D/g, "")} />
      <DetailField label={strings.nameOnCard} value={entry.secondaryValue} />
      <DetailField label={strings.expiry} value={entry.tertiaryValue} mono />
      <DetailField label={strings.securityCode} value={entry.fourthValue} secret mono masked="•••" />
      <DetailField label={strings.type} value={`${entry.cardKind === "DEBIT" ? "Debit" : "Credit"}${entry.network ? ` · ${entry.network}` : ""}`} copy={false} />
    </>;
    case "AUTHENTICATOR": return <>
      <LiveCodeField entry={entry} />
      <DetailField label={strings.account} value={entry.primaryValue} />
      <DetailField label={strings.setupKey} value={entry.secondaryValue} secret mono />
      <DetailField label={strings.settings} value={`${entry.totpAlgorithm} · ${entry.totpDigits} digits · every ${entry.totpPeriod}s`} copy={false} />
    </>;
    case "QUESTION": return <>
      <DetailField label={strings.question} value={entry.primaryValue} />
      <DetailField label={strings.answer} value={entry.secondaryValue} secret />
    </>;
    case "AUTOFILL": {
      const profile = profileFrom(entry.primaryValue);
      const filled = profileFields.filter(([key]) => profile[key].trim());
      return filled.length ? <>{filled.map(([key, label]) => <DetailField key={key} label={label} value={profile[key]} />)}</> : <DetailField label={strings.details} value="" copy={false} />;
    }
  }
}

/** The live one-time code of an authenticator item: its own "Code" row, or a login's linked code. */
function LiveCodeField({ entry, label, note }: { entry: VaultEntry; label?: string; note?: string }) {
  const now = useNow(1000);
  const code = useTotpCodes([entry], now).get(entry.id);
  return (
    <div className="detail-field detail-code">
      <div className="detail-field-text">
        <span className="detail-label">{label ?? strings.code}{note ? ` · ${note}` : ""}</span>
        <span className="code-value">{code?.value ? groupCode(code.value) : "••• •••"}</span>
        {code?.next && code.seconds <= 5 && <span className="code-next">{codeText.next(groupCode(code.next))}</span>}
      </div>
      <div className="detail-actions">
        {code && <CountdownRing seconds={code.seconds} period={code.period} />}
        <CopyButton label={strings.code} message={strings.codeCopied} secret value={async () => (await totpAt(entry))?.value ?? null} />
      </div>
    </div>
  );
}

function Photos({ entryId, entryType }: { entryId: string; entryType: string }) {
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
    if (file.size > 10 * 1024 * 1024) { toast.warning(codeText.chooseAnImageUnder10Mb); return; }
    setBusy(true);
    const progress = toast.progress(codeText.addingPhoto);
    try {
      const dataUrl = await new Promise<string>((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => typeof reader.result === "string" ? resolve(reader.result) : reject(new Error("Couldn't read the image."));
        reader.onerror = () => reject(new Error("Couldn't read the image."));
        reader.readAsDataURL(file);
      });
      const separator = dataUrl.indexOf(",");
      const mimeType = dataUrl.slice(5, dataUrl.indexOf(";"));
      await api.addEntryPhoto(entryId, mimeType, dataUrl.slice(separator + 1));
      setPhotos(await api.listEntryPhotos(entryId));
      progress.success(codeText.photoAdded);
    } catch (failure) {
      progress.error(failure, codeText.couldnTAddThePhoto);
    } finally {
      setBusy(false);
      if (input.current) input.current.value = "";
    }
  };

  // The cover is the photo lists and this page show first. On a phone it is picked the same way,
  // and the choice travels to every paired device.
  const chooseCover = async (photo: EntryPhoto) => {
    setBusy(true);
    try {
      await api.setCoverPhoto(photo.id);
      setPhotos(await api.listEntryPhotos(entryId));
      toast.success(codeText.coverPhotoSet);
    } catch (failure) {
      toast.error(failure, codeText.couldnTSetTheCoverPhoto);
    } finally {
      setBusy(false);
    }
  };

  const remove = async (photo: EntryPhoto) => {
    if (!(await confirm({ title: codeText.deleteThisPhoto, confirmLabel: strings.deletePhoto, danger: true }))) return;
    setBusy(true);
    try {
      await api.deleteEntryPhoto(photo.id);
      setPhotos((current) => current?.filter((item) => item.id !== photo.id) ?? null);
      setViewing(null);
      toast.success(codeText.photoDeleted);
    } catch (failure) {
      toast.error(failure, codeText.couldnTDeleteThePhoto);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card card-padded" aria-labelledby="photos-title">
      <header className="card-header compact">
        <div className="card-heading"><h2 id="photos-title">{strings.photos}</h2></div>
        <div className="card-actions">
          <input ref={input} type="file" accept="image/jpeg,image/png,image/webp,image/gif" className="sr-only" tabIndex={-1} aria-hidden="true" onChange={(event) => void add(event.target.files?.[0])} />
          <Button size="sm" icon={ImagePlus} busy={busy} disabled={photos === null || photos.length >= 20} onClick={() => input.current?.click()}>{strings.addPhoto}</Button>
        </div>
      </header>
      {photos === null ? <Spinner label={strings.loadingPhotos} /> : photos.length === 0 ? <p className="muted small">No photos. {entryType === "CARD" ? codeText.addACardScanOrReceipt : codeText.addAPhotoOrScreenshot}, up to 10 MB each.</p> : (
        <div className="photo-grid">
          {photos.map((photo) => (
            <figure key={photo.id} className="photo">
              <button type="button" className="photo-open" onClick={() => setViewing(photo)} aria-label={photo.isCover ? codeText.viewCoverPhoto : codeText.viewPhoto}><img src={photo.dataUrl} alt="" /></button>
              {photo.isCover
                ? <span className="photo-badge">{strings.cover}</span>
                : <button type="button" className="photo-badge photo-cover-set" onClick={() => void chooseCover(photo)} disabled={busy}>{strings.setAsCover}</button>}
              <IconButton label={strings.deletePhoto} icon={Trash2} size="sm" variant="secondary" className="photo-delete" onClick={() => void remove(photo)} disabled={busy} />
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
    <dialog ref={ref} className="photo-viewer" aria-label={strings.photo} onCancel={(event) => { event.preventDefault(); onClose(); }} onClick={onClose}>
      <img src={photo.dataUrl} alt={strings.photoAttachedToThisItem} />
      <IconButton label={strings.closePhoto} icon={X} variant="secondary" className="photo-viewer-close" onClick={onClose} />
    </dialog>
  );
}
