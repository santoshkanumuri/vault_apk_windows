import { useMemo, useState } from "react";
import { ChevronRight, Clock3, Copy, Fingerprint, Plus, SearchX, Trash2 } from "lucide-react";
import { Button, IconButton } from "../../components/Button";
import { Avatar, CountdownRing, EmptyState } from "../../components/Display";
import { useCopy } from "../../app/clipboard";
import { useConfirm } from "../../app/confirm";
import { useNow, usePolling } from "../../app/hooks";
import { useRouteState, useRouter } from "../../app/router";
import { useToast } from "../../app/toast";
import { useVault } from "../../app/vault";
import { api, type PasskeySummary, type VaultEntry } from "../../lib/api";
import { cx, formatDateTime, groupCode, plural } from "../../lib/format";
import { buildIndex, matchesFilter } from "../../lib/search";
import { totpAt } from "../../lib/totp";
import { FilterInput } from "../items/Toolbar";
import { useTotpCodes, type LiveCode } from "./useTotp";

export function CodesPage() {
  const { entries, unlocked } = useVault();
  const router = useRouter();
  const [filter, setFilter] = useRouteState("filter", "");
  const codes = useMemo(() => entries.filter((entry) => entry.type === "AUTHENTICATOR").sort((a, b) => Number(b.favorite) - Number(a.favorite) || a.title.localeCompare(b.title, undefined, { sensitivity: "base" })), [entries]);
  const docs = useMemo(() => buildIndex(codes, []), [codes]);
  const visible = useMemo(() => {
    const ids = new Set(docs.filter((doc) => matchesFilter(doc, filter)).map((doc) => doc.id));
    return codes.filter((entry) => ids.has(entry.id));
  }, [codes, docs, filter]);
  const now = useNow(1000);
  const live = useTotpCodes(visible, now);
  const passkeys = usePolling<PasskeySummary[]>(api.listPasskeys, 30000, unlocked);

  const add = () => void router.navigate({ page: "edit", category: "codes" });

  return (
    <div className="page">
      <div className="toolbar">
        <FilterInput value={filter} onChange={setFilter} placeholder="Filter codes" />
        <div className="toolbar-group">
          <Button variant="primary" icon={Plus} onClick={add} className="toolbar-add">Add code</Button>
        </div>
      </div>

      {codes.length === 0 ? (
        <div className="card"><EmptyState icon={Clock3} title="No codes yet" body="Add the setup key from a site's two-step sign-in to get codes here." action={<Button variant="primary" icon={Plus} onClick={add}>Add code</Button>} /></div>
      ) : visible.length === 0 ? (
        <div className="card"><EmptyState icon={SearchX} title="No matches" action={<Button onClick={() => setFilter("")}>Clear filter</Button>} /></div>
      ) : (
        <ul className="code-grid" aria-label="Authenticator codes">
          {visible.map((entry) => <CodeTile key={entry.id} entry={entry} code={live.get(entry.id)} highlighted={router.highlight === entry.id} onOpen={() => void router.navigate({ page: "item", id: entry.id })} />)}
        </ul>
      )}

      <Passkeys list={passkeys.data} error={passkeys.error} reload={passkeys.reload} />
    </div>
  );
}

function CodeTile({ entry, code, onOpen, highlighted }: { entry: VaultEntry; code?: LiveCode; onOpen: () => void; highlighted: boolean }) {
  const copy = useCopy();
  const copyCode = () => void copy(async () => (await totpAt(entry))?.value ?? null, { label: "Code", secret: true, message: "Code copied" });
  const urgent = code ? code.seconds <= 5 : false;
  return (
    <li className={cx("code-tile", highlighted && "is-highlighted", urgent && "is-urgent")} data-row-id={entry.id}>
      <button type="button" className="code-main" onClick={copyCode} aria-label={`Copy code for ${entry.title}`}>
        <Avatar title={entry.title} size="sm" />
        <span className="code-text">
          <span className="code-title truncate">{entry.title}</span>
          {entry.primaryValue && <span className="code-account truncate">{entry.primaryValue}</span>}
          <span className="code-value" aria-hidden="true">{code?.value ? groupCode(code.value) : "––– –––"}</span>
          <span className="code-next" aria-hidden="true">{code?.next && urgent ? `Next ${groupCode(code.next)}` : " "}</span>
        </span>
      </button>
      <div className="code-side">
        {code && <CountdownRing seconds={code.seconds} period={code.period} />}
        <IconButton label="Copy code" icon={Copy} size="sm" tabIndex={-1} onClick={copyCode} />
        <IconButton label={`Open ${entry.title}`} icon={ChevronRight} size="sm" onClick={onOpen} />
      </div>
    </li>
  );
}

function Passkeys({ list, error, reload }: { list: PasskeySummary[] | null; error: unknown; reload: () => Promise<void> }) {
  const confirm = useConfirm();
  const toast = useToast();
  const [busy, setBusy] = useState("");
  const remove = async (passkey: PasskeySummary) => {
    if (!(await confirm({ title: `Delete passkey for ${passkey.rpId}?`, message: `You won't be able to sign in to ${passkey.rpId} as ${passkey.displayName || passkey.username} with it anymore.`, confirmLabel: "Delete passkey", danger: true }))) return;
    setBusy(passkey.id);
    try {
      await api.deletePasskey(passkey.id);
      toast.success("Passkey deleted");
      await reload();
    } catch (failure) {
      toast.error(failure, "Couldn't delete the passkey.");
    } finally {
      setBusy("");
    }
  };
  return (
    <section className="section" aria-labelledby="passkeys-title">
      <div className="section-header">
        <h2 id="passkeys-title" className="with-icon"><Fingerprint aria-hidden="true" />Passkeys</h2>
        {list && list.length > 0 && <span className="muted small">{plural(list.length, "passkey")}</span>}
      </div>
      {error ? <div className="card card-padded muted small">Passkeys are unavailable right now.</div>
        : !list ? null
        : list.length === 0 ? <div className="card card-padded muted small">No passkeys yet. Passkeys you save on your phone show up here after sync.</div>
        : (
          <ul className="card list">
            {list.map((passkey) => (
              <li key={passkey.id} className="list-row static">
                <div className="list-row-main">
                  <Avatar title={passkey.rpId} icon={Fingerprint} />
                  <span className="list-row-text">
                    <span className="list-row-title truncate">{passkey.rpId}</span>
                    <span className="list-row-subtitle truncate">{[passkey.displayName || passkey.username, passkey.createdAt ? `Added ${formatDateTime(passkey.createdAt)}` : ""].filter(Boolean).join(" · ")}</span>
                  </span>
                </div>
                <div className="list-row-actions always">
                  <IconButton label={`Delete passkey for ${passkey.rpId}`} icon={Trash2} size="sm" className="btn-danger-text" busy={busy === passkey.id} onClick={() => void remove(passkey)} />
                </div>
              </li>
            ))}
          </ul>
        )}
    </section>
  );
}
