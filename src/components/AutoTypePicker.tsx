import { useEffect, useMemo, useState } from "react";
import { Keyboard } from "lucide-react";
import { Button } from "./Button";
import { Dialog } from "./Dialog";
import { TextField } from "./Field";
import { Avatar } from "./Display";
import { useToast } from "../app/toast";
import { useVault } from "../app/vault";
import { api, onAutoType, type AutoTypeTarget } from "../lib/api";
import { rankForWindow } from "../lib/autoType";
import { hostFromUrl } from "../lib/format";

/**
 * The auto-type picker. The shortcut in another app records that window (auto_type.rs) and
 * shows Nuvori; this lists the logins that fit it first. Picking one types it into that window.
 * Mounted in the unlocked shell, so a locked vault always asks for the password first.
 */
export function AutoTypePicker() {
  const { entries } = useVault();
  const toast = useToast();
  const [target, setTarget] = useState<AutoTypeTarget | null>(null);
  const [filter, setFilter] = useState("");
  const [busy, setBusy] = useState("");

  useEffect(() => {
    // A press before the unlock: the recorded window is still waiting.
    api.autoTypePending().then((pending) => { if (pending) setTarget(pending); }).catch(() => {});
    return onAutoType((next) => { setFilter(""); setTarget(next); });
  }, []);

  const ranked = useMemo(() => {
    if (!target) return [];
    const query = filter.trim().toLowerCase();
    return rankForWindow(entries, target.title, target.app)
      .filter(({ entry }) => !query || `${entry.title} ${entry.primaryValue} ${entry.tertiaryValue}`.toLowerCase().includes(query));
  }, [entries, target, filter]);

  const close = () => {
    setTarget(null);
    void api.autoTypeCancel().catch(() => {});
  };

  const type = async (id: string) => {
    setBusy(id);
    try {
      await api.autoTypeLogin(id);
      setTarget(null);
      toast.success(`Typed into ${target?.app ?? "the app"}`);
    } catch (failure) {
      setTarget(null);
      toast.error(failure, "Couldn't type the login.");
    } finally {
      setBusy("");
    }
  };

  const matches = ranked.filter((item) => item.score > 0).length;
  return (
    <Dialog open={target !== null} onClose={close} locked={busy !== ""} size="md" title="Auto-type a login"
      description={target ? <>Into <strong>{target.app}</strong>: {target.title || "untitled window"}. Nuvori switches to that window, then types the username, Tab and the password.</> : null}
      footer={<Button variant="ghost" onClick={close} disabled={busy !== ""}>Cancel</Button>}>
      <div className="form-stack">
        <TextField label="Search logins" value={filter} onValue={setFilter} placeholder="Name, username or website" autoComplete="off" spellCheck={false} data-autofocus />
        <p className="field-hint">{matches ? `${matches === 1 ? "1 login fits" : `${matches} logins fit`} this window.` : "No login matches this window by name or website. Pick one below."}</p>
        <ul className="card list autotype-list">
          {ranked.slice(0, 50).map(({ entry, score }) => (
            <li key={entry.id} className="autotype-row">
              <Avatar title={entry.title} site={entry.tertiaryValue} />
              <span className="trash-text">
                <span className="trash-title">{entry.title}{score > 0 && <span className="autotype-match"> · fits</span>}</span>
                <span className="trash-meta">{[entry.primaryValue, hostFromUrl(entry.tertiaryValue ?? "")].filter(Boolean).join(" · ")}</span>
              </span>
              <Button size="sm" variant={score > 0 ? "primary" : "secondary"} icon={Keyboard} busy={busy === entry.id} disabled={busy !== ""} onClick={() => void type(entry.id)}>Type</Button>
            </li>
          ))}
          {ranked.length === 0 && <li className="autotype-row muted">No logins found.</li>}
        </ul>
      </div>
    </Dialog>
  );
}
