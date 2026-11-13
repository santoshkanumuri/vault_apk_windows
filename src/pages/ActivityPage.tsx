import { useMemo } from "react";
import { ScrollText, Trash2 } from "lucide-react";
import { Button } from "../components/Button";
import { EmptyState } from "../components/Display";
import { Spinner } from "../components/Spinner";
import { StatusIcon } from "../components/Status";
import { useConfirm } from "../app/confirm";
import { useNow, usePolling } from "../app/hooks";
import { useRouteState } from "../app/router";
import { useToast } from "../app/toast";
import { api, type ActivityCategory, type ActivityEvent } from "../lib/api";
import { cx, formatDateTime, relativeTime, toMillis } from "../lib/format";

const categoryLabels: Record<ActivityCategory, string> = { vault: "Vault", items: "Items", sync: "Sync", pairing: "Pairing", browser: "Browser", security: "Security" };

function isoTime(at: number): string | undefined {
  const ms = toMillis(at);
  return ms && Number.isFinite(ms) ? new Date(ms).toISOString() : undefined;
}

export function ActivityList({ events }: { events: ActivityEvent[] }) {
  const now = useNow(30000);
  return (
    <ul className="card list activity-list">
      {events.map((event) => (
        <li key={event.id} className={cx("activity-row", `tone-text-${event.level}`)}>
          <span className={cx("activity-icon", `tone-${event.level}`)}><StatusIcon kind={event.level} size={16} /></span>
          <span className="activity-text">
            <span className="activity-message">{event.message}</span>
            <span className="activity-meta">{categoryLabels[event.category] ?? event.category} · <time dateTime={isoTime(event.at)} title={formatDateTime(event.at)}>{relativeTime(event.at, now)}</time></span>
          </span>
        </li>
      ))}
    </ul>
  );
}

export function ActivityPage() {
  const toast = useToast();
  const confirm = useConfirm();
  const log = usePolling<ActivityEvent[]>(() => api.activityLog(500), 3000);
  const [filter, setFilter] = useRouteState<ActivityCategory | "all">("category", "all");
  const events = useMemo(() => (log.data ?? []).filter((event) => filter === "all" || event.category === filter), [log.data, filter]);
  const counts = useMemo(() => {
    const map = new Map<string, number>();
    for (const event of log.data ?? []) map.set(event.category, (map.get(event.category) ?? 0) + 1);
    return map;
  }, [log.data]);

  const clear = async () => {
    if (!(await confirm({ title: "Clear the activity log?", message: "This removes the events shown here. It doesn't change your vault.", confirmLabel: "Clear log", danger: true }))) return;
    try {
      await api.clearActivityLog();
      toast.success("Activity log cleared");
      await log.reload();
    } catch (failure) {
      toast.error(failure, "Couldn't clear the activity log.");
    }
  };

  return (
    <div className="page page-narrow">
      <div className="toolbar">
        <div className="chip-filter" role="radiogroup" aria-label="Filter by category">
          {(["all", ...Object.keys(categoryLabels)] as Array<ActivityCategory | "all">).map((key) => (
            <button key={key} type="button" role="radio" aria-checked={filter === key} className={cx("filter-chip", filter === key && "is-selected")} onClick={() => setFilter(key)}>
              {key === "all" ? "All" : categoryLabels[key]}
              {key !== "all" && counts.get(key) ? <span className="filter-chip-count">{counts.get(key)}</span> : null}
            </button>
          ))}
        </div>
        <div className="toolbar-group">
          <Button variant="ghost" icon={Trash2} onClick={() => void clear()} disabled={!log.data?.length}>Clear</Button>
        </div>
      </div>
      {log.loading && !log.data ? <div className="card card-padded center"><Spinner label="Loading activity" /></div>
        : log.error && !log.data ? <div className="card"><EmptyState icon={ScrollText} title="Activity log unavailable" body="This version of Nuvori doesn't record activity yet, or the log couldn't be read." action={<Button onClick={() => void log.reload()}>Try again</Button>} /></div>
        : events.length === 0 ? <div className="card"><EmptyState icon={ScrollText} title={filter === "all" ? "No activity yet" : `No ${categoryLabels[filter as ActivityCategory].toLowerCase()} activity`} body="Unlocks, saves, syncs, and browser fills show up here. Events are kept until you close Nuvori." /></div>
        : <ActivityList events={events} />}
      <p className="detail-meta">Activity never includes passwords, usernames, or item names.</p>
    </div>
  );
}
