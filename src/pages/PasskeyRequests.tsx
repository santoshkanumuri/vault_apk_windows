import { useMemo, useState } from "react";
import { KeyRound, Trash2 } from "lucide-react";
import { Button } from "../components/Button";
import { EmptyState } from "../components/Display";
import { Spinner } from "../components/Spinner";
import { StatusChip } from "../components/Status";
import { useConfirm } from "../app/confirm";
import { useNow, usePolling } from "../app/hooks";
import { useToast } from "../app/toast";
import { api, type PasskeyRequest } from "../lib/api";
import { cx, formatDateTime, relativeTime } from "../lib/format";
import { codeText, strings } from "../strings";

/**
 * "Passkey requests": what Windows asked Nuvori's passkey provider, newest first. Windows decides
 * by itself whether Nuvori appears in a passkey prompt, so when it doesn't, this is what tells you
 * whether Windows asked at all and why Nuvori didn't offer a passkey. Kept on this PC, outside the
 * vault, which is why a request that arrived while the vault was locked is here too.
 */
export function PasskeyRequestsSection() {
  const toast = useToast();
  const confirm = useConfirm();
  const requests = usePolling<PasskeyRequest[]>(() => api.passkeyRequests(), 5000);
  const [refusalsOnly, setRefusalsOnly] = useState(false);
  const now = useNow(30000);
  const all = requests.data ?? [];
  const shown = useMemo(() => (refusalsOnly ? all.filter((request) => !request.offered) : all), [all, refusalsOnly]);
  const refusals = all.filter((request) => !request.offered).length;

  const clear = async () => {
    if (!(await confirm({ title: codeText.clearThePasskeyRequestHistory, message: codeText.thisRemovesTheRequestsShownHere, confirmLabel: codeText.clearHistory, danger: true }))) return;
    try {
      await api.clearPasskeyRequests();
      toast.success(codeText.passkeyRequestHistoryCleared);
      await requests.reload();
    } catch (failure) {
      toast.error(failure, codeText.couldnTClearTheRequestHistory);
    }
  };

  return (
    <section className="card card-padded" aria-labelledby="passkey-requests-title">
      <header className="card-header compact">
        <div className="card-heading">
          <h2 id="passkey-requests-title">{strings.passkeyRequests}</h2>
          <p className="muted small">{strings.whatWindowsAskedNuvoriS}</p>
        </div>
        <div className="card-actions">
          {refusals > 0 && (
            <button type="button" aria-pressed={refusalsOnly} className={cx("filter-chip", refusalsOnly && "is-selected")} onClick={() => setRefusalsOnly(!refusalsOnly)}>
              {strings.notOffered}<span className="filter-chip-count">{refusals}</span>
            </button>
          )}
          <Button size="sm" variant="ghost" icon={Trash2} onClick={() => void clear()} disabled={all.length === 0}>{strings.clear}</Button>
        </div>
      </header>
      {requests.loading && !requests.data ? <Spinner label={strings.loadingPasskeyRequests} />
        : shown.length === 0 ? <EmptyState icon={KeyRound} title={all.length === 0 ? strings.noPasskeyRequestsYet : strings.everyRequestWasAnswered}
            body={all.length === 0 ? strings.ifAnAppOffersOtherPasskey : strings.nuvoriOfferedAPasskeyEveryTime} />
        : (
          <ul className="list">
            {shown.map((request, index) => (
              <li key={`${request.at}-${index}`} className="request-row">
                <span className="request-text">
                  <span className="request-site">{request.site || strings.theRequestDidnTNameASite}</span>
                  <span className="request-meta">
                    {request.create ? strings.aNewPasskey : strings.aSignIn} · <time dateTime={new Date(request.at).toISOString()} title={formatDateTime(request.at)}>{relativeTime(request.at, now)}</time>
                    {request.offered ? null : <> · {request.reason}</>}
                  </span>
                </span>
                <StatusChip kind={request.offered ? "success" : "neutral"} label={request.offered ? strings.offered : strings.notOffered} />
              </li>
            ))}
          </ul>
        )}
      <p className="detail-meta">{strings.theLast100RequestsAreKept}</p>
    </section>
  );
}
