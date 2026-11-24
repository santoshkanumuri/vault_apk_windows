import { Fragment, useCallback, useEffect, useId, useState } from "react";
import { RefreshCw } from "lucide-react";
import {
  entropyBits, generate, LENGTH_RANGE, normalizeSettings, strengthLabel, WORDS_RANGE,
  type GeneratorSettings, type Separator,
} from "../lib/generator";
import { loadWordList, readGeneratorSettings, saveGeneratorSettings, WORD_COUNT } from "../lib/wordlist";
import { Button, IconButton } from "./Button";
import { Dialog } from "./Dialog";
import { Segmented, Toggle } from "./Field";
import { StatusBanner } from "./Status";

/** One click: a new password or passphrase with the settings last used on this PC. */
export async function generateWithSavedSettings(): Promise<string> {
  const settings = readGeneratorSettings();
  return generate(settings, settings.mode === "passphrase" ? await loadWordList() : []);
}

const separatorOptions: ReadonlyArray<{ value: Separator; label: string }> = [
  { value: "-", label: "Hyphen" }, { value: ".", label: "Period" }, { value: "_", label: "Underscore" }, { value: " ", label: "Space" },
];

/** Display only: a long passphrase wraps after a separator instead of inside a word. */
function Breakable({ value, settings }: { value: string; settings: GeneratorSettings }) {
  if (settings.mode !== "passphrase") return <>{value}</>;
  const parts = value.split(settings.separator);
  return <>{parts.map((part, index) => <Fragment key={index}>{part}{index < parts.length - 1 && <>{settings.separator}<wbr /></>}</Fragment>)}</>;
}

function Option({ label, detail, checked, onChange, disabled }: { label: string; detail?: string; checked: boolean; onChange: (value: boolean) => void; disabled?: boolean }) {
  return (
    <div className="generator-option">
      <span>{label}{detail && <small>{detail}</small>}</span>
      <Toggle label={label} checked={checked} onChange={onChange} disabled={disabled} />
    </div>
  );
}

function Range({ label, value, min, max, onChange }: { label: string; value: number; min: number; max: number; onChange: (value: number) => void }) {
  const id = useId();
  return (
    <div className="field">
      <div className="field-label-row"><label htmlFor={id}>{label}</label><span className="generator-count">{value}</span></div>
      <input id={id} className="range" type="range" min={min} max={max} value={value} onChange={(event) => onChange(Number(event.target.value))} />
    </div>
  );
}

/**
 * Generator options with a live preview. The settings are saved on this PC when the user picks
 * the result, so the one-click Generate button uses them next time.
 */
export function PasswordGeneratorDialog({ open, onClose, onUse }: { open: boolean; onClose: () => void; onUse: (value: string) => void }) {
  const [settings, setSettings] = useState<GeneratorSettings>(readGeneratorSettings);
  const [value, setValue] = useState("");
  const [words, setWords] = useState<readonly string[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => { if (open) setSettings(readGeneratorSettings()); }, [open]);

  useEffect(() => {
    if (!open || settings.mode !== "passphrase" || words) return;
    loadWordList().then(setWords, () => setError("The word list couldn't be loaded. Use a password instead."));
  }, [open, settings.mode, words]);

  const regenerate = useCallback(() => {
    if (settings.mode === "passphrase" && !words) { setValue(""); return; }
    setValue(generate(settings, words ?? []));
  }, [settings, words]);

  useEffect(() => { if (open) regenerate(); }, [open, regenerate]);

  const change = (patch: Partial<GeneratorSettings>) => { setError(""); setSettings((current) => normalizeSettings({ ...current, ...patch })); };
  const sets = [settings.uppercase, settings.lowercase, settings.digits, settings.symbols].filter(Boolean).length;
  const onlySet = (on: boolean) => on && sets === 1;
  const bits = entropyBits(settings, WORD_COUNT);
  const noun = settings.mode === "passphrase" ? "passphrase" : "password";

  return (
    <Dialog open={open} onClose={onClose} title="Generate a password" size="md"
      footer={<>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="primary" disabled={!value} onClick={() => { saveGeneratorSettings(settings); onUse(value); }}>Use {noun}</Button>
      </>}>
      <div className="form-stack">
        <Segmented label="Type" value={settings.mode} onChange={(mode) => change({ mode })}
          options={[{ value: "password", label: "Password" }, { value: "passphrase", label: "Passphrase" }]} />
        <div className="generator-preview">
          <output className="mono" aria-live="polite" aria-label={`Generated ${noun}`}>{value ? <Breakable value={value} settings={settings} /> : "…"}</output>
          <IconButton label={`New ${noun}`} icon={RefreshCw} onClick={regenerate} disabled={!value} />
        </div>
        <p className="field-hint">{strengthLabel(bits)} · about {bits} bits of randomness</p>
        {error && <StatusBanner kind="error">{error}</StatusBanner>}
        {settings.mode === "password" ? <>
          <Range label="Length" value={settings.length} min={LENGTH_RANGE.min} max={LENGTH_RANGE.max} onChange={(length) => change({ length })} />
          <div className="generator-options">
            <Option label="Uppercase" detail="A–Z" checked={settings.uppercase} disabled={onlySet(settings.uppercase)} onChange={(uppercase) => change({ uppercase })} />
            <Option label="Lowercase" detail="a–z" checked={settings.lowercase} disabled={onlySet(settings.lowercase)} onChange={(lowercase) => change({ lowercase })} />
            <Option label="Numbers" detail="0–9" checked={settings.digits} disabled={onlySet(settings.digits)} onChange={(digits) => change({ digits })} />
            <Option label="Symbols" detail="! @ # $ % ^ & * - _ = + ?" checked={settings.symbols} disabled={onlySet(settings.symbols)} onChange={(symbols) => change({ symbols })} />
            <Option label="Avoid similar characters" detail="Leaves out l, I, O, 0 and 1" checked={settings.avoidSimilar} onChange={(avoidSimilar) => change({ avoidSimilar })} />
          </div>
        </> : <>
          <Range label="Words" value={settings.words} min={WORDS_RANGE.min} max={WORDS_RANGE.max} onChange={(count) => change({ words: count })} />
          <div className="field">
            <span className="generator-label">Separator</span>
            <Segmented label="Separator" size="sm" value={settings.separator} onChange={(separator) => change({ separator })} options={separatorOptions} />
          </div>
          <div className="generator-options">
            <Option label="Capitalize words" checked={settings.capitalize} onChange={(capitalize) => change({ capitalize })} />
            <Option label="Include a number" detail="Many websites ask for one" checked={settings.includeNumber} onChange={(includeNumber) => change({ includeNumber })} />
          </div>
        </>}
      </div>
    </Dialog>
  );
}
