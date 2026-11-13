import { useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { Save, Wand2 } from "lucide-react";
import { Button } from "../../components/Button";
import { Checkbox, PasswordField, SelectField, TextArea, TextField } from "../../components/Field";
import { StatusBanner } from "../../components/Status";
import { useConfirm } from "../../app/confirm";
import { useRouter } from "../../app/router";
import { useToast } from "../../app/toast";
import { useVault } from "../../app/vault";
import { api, type EntryDraft } from "../../lib/api";
import { categories, emptyEntry, foldersFor, profileFields, profileFrom, type Category, type Profile } from "../../lib/entries";
import { cx } from "../../lib/format";
import { generatePassword, passwordStrength } from "../../lib/strength";
import { isValidSecret } from "../../lib/totp";

/** Registers a "Discard changes?" guard while the form is dirty. */
export function useUnsavedGuard(dirty: boolean) {
  const { setGuard } = useRouter();
  const confirm = useConfirm();
  useEffect(() => {
    if (!dirty) { setGuard(null); return; }
    setGuard(() => confirm({ title: "Discard changes?", message: "Your edits haven't been saved.", confirmLabel: "Discard", cancelLabel: "Keep editing", danger: true }));
    return () => setGuard(null);
  }, [dirty, setGuard, confirm]);
}

export function ItemEditorPage({ id, category }: { id?: string; category: Category }) {
  const { entries, groups, upsertEntry, refresh } = useVault();
  const router = useRouter();
  const toast = useToast();
  const existing = id ? entries.find((entry) => entry.id === id) : undefined;
  const info = categories[existing ? categoryFromType(existing.type) : category];
  const initial = useMemo<EntryDraft>(() => existing ? { ...existing, groupIds: [...(existing.groupIds ?? [])] } : emptyEntry(info.type), [existing?.id]); // eslint-disable-line react-hooks/exhaustive-deps
  const [draft, setDraft] = useState<EntryDraft>(initial);
  const [busy, setBusy] = useState(false);
  const [errors, setErrors] = useState<Record<string, string>>({});
  const [formError, setFormError] = useState("");
  const form = useRef<HTMLFormElement>(null);
  const dirty = JSON.stringify(draft) !== JSON.stringify(initial);
  useUnsavedGuard(dirty && !busy);

  const set = <K extends keyof EntryDraft>(key: K, value: EntryDraft[K]) => {
    setDraft((current) => ({ ...current, [key]: value }));
    if (errors[key as string]) setErrors((current) => ({ ...current, [key as string]: "" }));
  };
  const folders = foldersFor(groups, info.type);
  const type = info.type;

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "s") { event.preventDefault(); form.current?.requestSubmit(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const validate = (): Record<string, string> => {
    const next: Record<string, string> = {};
    if (!draft.title.trim()) next.title = "Add a name.";
    if (type === "PASSWORD" && !draft.secondaryValue) next.secondaryValue = "Add a password.";
    if (type === "CARD" && draft.primaryValue.replace(/\D/g, "").length < 8) next.primaryValue = "Enter the card number.";
    if (type === "AUTHENTICATOR" && !isValidSecret(draft.secondaryValue)) next.secondaryValue = "Enter a valid setup key (letters A–Z and digits 2–7).";
    if (type === "AUTHENTICATOR" && (draft.totpDigits < 6 || draft.totpDigits > 8)) next.totpDigits = "Use 6 to 8 digits.";
    if (type === "AUTHENTICATOR" && (draft.totpPeriod < 1 || draft.totpPeriod > 300)) next.totpPeriod = "Use 1 to 300 seconds.";
    if (type === "QUESTION" && !draft.primaryValue.trim()) next.primaryValue = "Add the question.";
    if (type === "QUESTION" && !draft.secondaryValue) next.secondaryValue = "Add the answer.";
    if (type === "AUTOFILL" && !Object.values(profileFrom(draft.primaryValue)).some((value) => value.trim())) next.primaryValue = "Enter at least one detail.";
    return next;
  };

  const save = async (event: FormEvent) => {
    event.preventDefault();
    const found = validate();
    setErrors(found);
    if (Object.values(found).some(Boolean)) {
      setFormError("Check the highlighted fields.");
      window.setTimeout(() => form.current?.querySelector<HTMLElement>("[aria-invalid=true]")?.focus(), 0);
      return;
    }
    setBusy(true); setFormError("");
    try {
      const saved = await api.saveEntry({ ...draft, title: draft.title.trim() });
      upsertEntry(saved);
      setDraft(saved);
      toast.success(`${capitalize(info.singular)} saved`);
      router.setGuard(null);
      if (existing) await router.back();
      else await router.navigate({ page: "item", id: saved.id }, { replace: true });
      void refresh();
    } catch (failure) {
      toast.error(failure, "Couldn't save this item.");
      setBusy(false);
    }
  };

  if (id && !existing) {
    return <div className="page page-narrow"><StatusBanner kind="warning" title="This item isn't available">It may have been deleted on another device.</StatusBanner></div>;
  }

  return (
    <div className="page page-narrow">
      <form ref={form} className="card card-padded form-stack" onSubmit={(event) => void save(event)} noValidate>
        {formError && <StatusBanner kind="error">{formError}</StatusBanner>}
        {type === "AUTOFILL" ? <ProfileFields draft={draft} set={set} error={errors.primaryValue} /> : <>
          <TextField label={type === "CARD" ? "Card name" : type === "PASSWORD" || type === "AUTHENTICATOR" ? "Service" : "Title"} value={draft.title} onValue={(v) => set("title", v)} error={errors.title} placeholder={type === "CARD" ? "e.g. Travel card" : type === "PASSWORD" ? "e.g. GitHub" : undefined} autoFocus={!existing} required maxLength={300} />
          {type === "PASSWORD" && <LoginFields draft={draft} set={set} errors={errors} />}
          {type === "CARD" && <>
            <TextField label="Card number" value={draft.primaryValue} onValue={(v) => set("primaryValue", v.replace(/\D/g, "").slice(0, 19))} error={errors.primaryValue} inputMode="numeric" autoComplete="off" className="mono" required />
            <div className="field-row">
              <SelectField label="Type" value={draft.cardKind} onValue={(v) => set("cardKind", v as EntryDraft["cardKind"])} options={[{ value: "CREDIT", label: "Credit" }, { value: "DEBIT", label: "Debit" }]} />
              <TextField label="Network" value={draft.network} onValue={(v) => set("network", v)} placeholder="Visa, Mastercard…" />
            </div>
            <TextField label="Name on card" value={draft.secondaryValue} onValue={(v) => set("secondaryValue", v)} autoComplete="off" />
            <div className="field-row">
              <TextField label="Expiry" value={draft.tertiaryValue} onValue={(v) => set("tertiaryValue", formatExpiry(v))} placeholder="MM/YY" inputMode="numeric" autoComplete="off" className="mono" />
              <PasswordField label="Security code" value={draft.fourthValue} onValue={(v) => set("fourthValue", v.replace(/\D/g, "").slice(0, 4))} inputMode="numeric" autoComplete="off" />
            </div>
          </>}
          {type === "AUTHENTICATOR" && <>
            <TextField label="Account" value={draft.primaryValue} onValue={(v) => set("primaryValue", v)} placeholder="name@example.com" autoComplete="off" />
            <PasswordField label="Setup key" value={draft.secondaryValue} onValue={(v) => set("secondaryValue", v.replace(/[\s-]/g, "").toUpperCase())} error={errors.secondaryValue} hint="The text key shown under the QR when you set up two-step sign-in." autoComplete="off" required />
            <details className="advanced">
              <summary>Code settings</summary>
              <div className="field-row three">
                <SelectField label="Algorithm" value={draft.totpAlgorithm} onValue={(v) => set("totpAlgorithm", v)} options={[{ value: "SHA1", label: "SHA1" }, { value: "SHA256", label: "SHA256" }, { value: "SHA512", label: "SHA512" }]} />
                <TextField label="Digits" type="number" min={6} max={8} value={String(draft.totpDigits)} onValue={(v) => set("totpDigits", Number(v))} error={errors.totpDigits} />
                <TextField label="Period (s)" type="number" min={1} max={300} value={String(draft.totpPeriod)} onValue={(v) => set("totpPeriod", Number(v))} error={errors.totpPeriod} />
              </div>
            </details>
          </>}
          {type === "QUESTION" && <>
            <TextField label="Question" value={draft.primaryValue} onValue={(v) => set("primaryValue", v)} error={errors.primaryValue} required />
            <PasswordField label="Answer" value={draft.secondaryValue} onValue={(v) => set("secondaryValue", v)} error={errors.secondaryValue} autoComplete="off" required />
          </>}
        </>}

        <TextArea label="Notes" value={draft.notes} onValue={(v) => set("notes", v)} rows={3} />
        <TextField label="Tags" value={draft.tags} onValue={(v) => set("tags", v)} placeholder="work, travel" hint="Separate with commas." />
        {folders.length > 0 && (
          <fieldset className="fieldset">
            <legend>Folders</legend>
            <div className="check-grid">
              {folders.map((folder) => <Checkbox key={folder.id} label={folder.name} checked={draft.groupIds.includes(folder.id)}
                onChange={(checked) => set("groupIds", checked ? [...draft.groupIds, folder.id] : draft.groupIds.filter((value) => value !== folder.id))} />)}
            </div>
          </fieldset>
        )}
        <Checkbox label="Favorite" checked={draft.favorite} onChange={(checked) => set("favorite", checked)} />

        <div className="form-actions">
          <Button variant="ghost" onClick={() => void router.back()} disabled={busy}>Cancel</Button>
          <Button variant="primary" type="submit" icon={Save} busy={busy}>{existing ? "Save changes" : `Save ${info.singular}`}</Button>
        </div>
      </form>
    </div>
  );
}

function LoginFields({ draft, set, errors }: { draft: EntryDraft; set: <K extends keyof EntryDraft>(key: K, value: EntryDraft[K]) => void; errors: Record<string, string> }) {
  const strength = passwordStrength(draft.secondaryValue);
  const tone = ["error", "warning", "info", "success", "success"][strength.score];
  return <>
    <TextField label="Username or email" value={draft.primaryValue} onValue={(v) => set("primaryValue", v)} autoComplete="off" spellCheck={false} />
    <PasswordField label="Password" value={draft.secondaryValue} onValue={(v) => set("secondaryValue", v)} error={errors.secondaryValue} autoComplete="new-password" required
      trailing={<button type="button" className="link-button" onClick={() => set("secondaryValue", generatePassword(20))}><Wand2 aria-hidden="true" /> Generate</button>} />
    {draft.secondaryValue && (
      <div className="strength compact">
        <div className={cx("strength-bar", `tone-${tone}`)}>{[0, 1, 2, 3].map((index) => <span key={index} className={cx(index < Math.max(1, strength.score) && "is-on")} />)}</div>
        <span className="strength-label">{strength.label}</span>
      </div>
    )}
    <TextField label="Website" value={draft.tertiaryValue} onValue={(v) => set("tertiaryValue", v)} placeholder="https://example.com" type="url" spellCheck={false} />
  </>;
}

function ProfileFields({ draft, set, error }: { draft: EntryDraft; set: <K extends keyof EntryDraft>(key: K, value: EntryDraft[K]) => void; error?: string }) {
  const profile = profileFrom(draft.primaryValue);
  const update = (key: keyof Profile, value: string) => set("primaryValue", JSON.stringify({ ...profile, [key]: value }));
  return <>
    <TextField label="Profile name" value={draft.title} onValue={(v) => set("title", v)} placeholder="e.g. Home" required />
    {error && <StatusBanner kind="error">{error}</StatusBanner>}
    <div className="field-row">
      {profileFields.map(([key, label]) => <TextField key={key} label={label} value={profile[key]} onValue={(v) => update(key, v)} type={key === "email" ? "email" : key === "phone" ? "tel" : "text"} autoComplete="off" fieldClassName={key === "address1" || key === "address2" ? "span-2" : undefined} />)}
    </div>
  </>;
}

function categoryFromType(type: EntryDraft["type"]): Category {
  return ({ PASSWORD: "logins", CARD: "cards", AUTHENTICATOR: "codes", QUESTION: "questions", AUTOFILL: "autofill" } as const)[type];
}

function formatExpiry(value: string): string {
  const digits = value.replace(/\D/g, "").slice(0, 4);
  return digits.length > 2 ? `${digits.slice(0, 2)}/${digits.slice(2)}` : digits;
}

function capitalize(value: string) { return value.charAt(0).toUpperCase() + value.slice(1); }
