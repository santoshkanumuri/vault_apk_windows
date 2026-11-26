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
import { iconHints } from "../../lib/siteIcons";
import { api, type PasskeySummary, type VaultEntry } from "../../lib/api";
import { cx, formatDateTime, groupCode, plural } from "../../lib/format";
import { buildIndex, matchesFilter } from "../../lib/search";
import { totpAt } from "../../lib/totp";
import { FilterInput } from "../items/Toolbar";
import { useTotpCodes, type LiveCode } from "./useTotp";
import { codeText, strings } from "../../strings";

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
        <FilterInput value={filter} onChange={setFilter} placeholder={strings.filterCodes} />
        <div className="toolbar-group">
          <Button variant="primary" icon={Plus} onClick={add} className="toolbar-add">{strings.addCode}</Button>
        </div>
      </div>

      {codes.length === 0 ? (
        <div className="card"><EmptyState icon={Clock3} title={strings.noCodesYet} body={codeText.addTheSetupKeyFromA} action={<Button variant="primary" icon={Plus} onClick={add}>{strings.addCode}</Button>} /></div>
      ) : visible.length === 0 ? (
        <div className="card"><EmptyState icon={SearchX} title={strings.noMatches} action={<Button onClick={() => setFilter("")}>{strings.clearFilter}</Button>} /></div>
      ) : (
        <ul className="code-grid" aria-label={strings.authenticatorCodes}>
          {visible.map((entry) => <CodeTile key={entry.id} entry={entry} hints={iconHints(entry, entries)} code={live.get(entry.id)} highlighted={router.highlight === entry.id} onOpen={() => void router.navigate({ page: "item", id: entry.id })} />)}
        </ul>
      )}

      <Passkeys list={passkeys.data} error={passkeys.error} reload={passkeys.reload} />
    </div>
  );
}

function CodeTile({ entry, hints, code, onOpen, highlighted }: { entry: VaultEntry; hints: { site?: string; brand?: string }; code?: LiveCode; onOpen: () => void; highlighted: boolean }) {
  const copy = useCopy();
  const copyCode = () => void copy(async () => (await totpAt(entry))?.value ?? null, { label: strings.code, secret: true, message: strings.codeCopied });
  const urgent = code ? code.seconds <= 5 : false;
  return (
    <li className={cx("code-tile", highlighted && "is-highlighted", urgent && "is-urgent")} data-row-id={entry.id}>
      <button type="button" className="code-main" onClick={copyCode} aria-label={codeText.copyCodeFor(entry.title)}>
        <Avatar title={entry.title} size="sm" {...hints} />
        <span className="code-text">
          <span className="code-title truncate">{entry.title}</span>
          {entry.primaryValue && <span className="code-account truncate">{entry.primaryValue}</span>}
          <span className="code-value" aria-hidden="true">{code?.value ? groupCode(code.value) : "––– –––"}</span>
          <span className="code-next" aria-hidden="true">{code?.next && urgent ? codeText.next(groupCode(code.next)) : " "}</span>
        </span>
      </button>
      <div className="code-side">
        {code && <CountdownRing seconds={code.seconds} period={code.period} />}
        <IconButton label={strings.copyCode} icon={Copy} size="sm" tabIndex={-1} onClick={copyCode} />
        <IconButton label={codeText.open2(entry.title)} icon={ChevronRight} size="sm" onClick={onOpen} />
      </div>
    </li>
  );
}

function Passkeys({ list, error, reload }: { list: PasskeySummary[] | null; error: unknown; reload: () => Promise<void> }) {
  const confirm = useConfirm();
  const toast = useToast();
  const [busy, setBusy] = useState("");
  const remove = async (passkey: PasskeySummary) => {
    if (!(await confirm({ title: codeText.deletePasskeyFor(passkey.rpId), message: codeText.youWonTBeAbleTo(passkey.rpId, passkey.displayName || passkey.username), confirmLabel: codeText.deletePasskey, danger: true }))) return;
    setBusy(passkey.id);
    try {
      await api.deletePasskey(passkey.id);
      toast.success(codeText.passkeyDeleted);
      await reload();
    } catch (failure) {
      toast.error(failure, codeText.couldnTDeleteThePasskey);
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
      {error ? <div className="card card-padded muted small">{strings.passkeysAreUnavailableRightNow}</div>
        : !list ? null
        : list.length === 0 ? <div className="card card-padded muted small">{strings.noPasskeysYetPasskeysYouSave}</div>
        : (
          <ul className="card list">
            {list.map((passkey) => (
              <li key={passkey.id} className="list-row static">
                <div className="list-row-main">
                  <Avatar title={passkey.rpId} icon={Fingerprint} site={passkey.rpId} />
                  <span className="list-row-text">
                    <span className="list-row-title truncate">{passkey.rpId}</span>
                    <span className="list-row-subtitle truncate">{[passkey.displayName || passkey.username, passkey.createdAt ? `Added ${formatDateTime(passkey.createdAt)}` : ""].filter(Boolean).join(" · ")}</span>
                  </span>
                </div>
                <div className="list-row-actions always">
                  <IconButton label={codeText.deletePasskeyFor2(passkey.rpId)} icon={Trash2} size="sm" className="btn-danger-text" busy={busy === passkey.id} onClick={() => void remove(passkey)} />
                </div>
              </li>
            ))}
          </ul>
        )}
    </section>
  );
}
