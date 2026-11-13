import { useMemo, useState } from "react";
import { ChevronRight, CircleCheck, Copy, FileText, Fingerprint, LockKeyhole, MonitorSmartphone, Plus, RefreshCw, Search, Star, X, type LucideIcon } from "lucide-react";
import { Button, IconButton } from "../components/Button";
import { Avatar, CountdownRing, Kbd } from "../components/Display";
import { Menu, type MenuItem } from "../components/Menu";
import { StatusIcon, type StatusKind } from "../components/Status";
import { useCopy } from "../app/clipboard";
import { useBrowserStatus, useConflicts, useHelloAvailable, useLock, useMembership, useNow, useSyncStatus } from "../app/hooks";
import { RemovedNoticeBanner } from "./sync/Membership";
import { dismissHint, readDismissed, readRecent } from "../app/recent";
import { useRouter } from "../app/router";
import { useOpenSearch } from "../app/search";
import { useToast } from "../app/toast";
import { useVault } from "../app/vault";
import { api, type VaultEntry } from "../lib/api";
import { categories, categoryOrder, entrySubtitle, type Category } from "../lib/entries";
import { cx, greeting, groupCode, plural, relativeTime } from "../lib/format";
import { browserIndicator, isSyncing, syncIndicator } from "../lib/syncState";
import { totpAt } from "../lib/totp";
import { useTotpCodes } from "./codes/useTotp";
import { EntryQuickActions } from "./items/actions";

/** Items for the Add type picker. Shared with the Home quick actions. */
export function useAddItems(): MenuItem[] {
  const router = useRouter();
  return [
    ...(["logins", "cards", "codes", "questions", "autofill"] as Category[]).map((key) => ({
      key, label: key === "autofill" ? "Autofill profile" : key === "questions" ? "Security question" : key === "codes" ? "Two-step code" : categories[key].singular.charAt(0).toUpperCase() + categories[key].singular.slice(1), icon: categories[key].icon,
      onSelect: () => void router.navigate({ page: "edit", category: key })
    })),
    { key: "note", label: "Note", icon: FileText, onSelect: () => void router.navigate({ page: "note-edit" }) }
  ];
}

export function HomePage() {
  const { snapshot, entries, notes } = useVault();
  const openSearch = useOpenSearch();
  const lock = useLock();
  const addItems = useAddItems();

  return (
    <div className="page home">
      <section className="home-hero" aria-label="Welcome">
        <div className="home-hello">
          <h2 className="home-greeting">{greeting()}</h2>
          <p className="muted">{plural(entries.length + notes.length, "item")} in your vault</p>
        </div>
        <div className="home-hero-actions">
          <Menu label="Add new" items={addItems} trigger={(props) => <Button {...props} variant="primary" icon={Plus}>Add</Button>} />
          <IconButton label="Lock vault (Ctrl+L)" icon={LockKeyhole} variant="secondary" className="home-lock" onClick={() => void lock()} />
        </div>
        <button type="button" className="home-search" onClick={openSearch} aria-keyshortcuts="Control+K">
          <Search aria-hidden="true" />
          <span className="home-search-label">Search passwords, cards, codes, notes</span>
          <span className="home-search-keys"><Kbd>Ctrl</Kbd><Kbd>K</Kbd></span>
        </button>
      </section>

      <HomeRemovedNotice />
      <AttentionStrip />

      <div className="home-grid">
        <div className="home-main">
          <QuickAccess />
          <LiveCodes />
        </div>
        <div className="home-side">
          <Categories counts={snapshot.counts} />
          <QuickActions />
        </div>
      </div>
    </div>
  );
}

function HomeRemovedNotice() {
  const membership = useMembership();
  return <RemovedNoticeBanner membership={membership.data} reload={membership.reload} />;
}

type Attention = { key: string; kind: StatusKind; label: string; detail?: string; onClick: () => void; dismissible?: boolean };

function AttentionStrip() {
  const { snapshot } = useVault();
  const router = useRouter();
  const sync = useSyncStatus(4000);
  const browser = useBrowserStatus(10000);
  const conflicts = useConflicts();
  const hello = useHelloAvailable();
  const [dismissed, setDismissed] = useState(readDismissed);
  const phone = syncIndicator(snapshot, sync.data, Boolean(sync.error));
  const extension = browserIndicator(snapshot, browser.data, Boolean(browser.error));

  const items: Attention[] = [];
  const conflictCount = !snapshot.enrolled ? 0 : conflicts.data ? conflicts.data.length : sync.data?.conflicts ?? 0;
  if (conflictCount > 0) items.push({ key: "conflicts", kind: "warning", label: `${plural(conflictCount, "change")} need${conflictCount === 1 ? "s" : ""} review`, detail: "Edited on both devices", onClick: () => void router.navigate(conflicts.data ? { page: "conflicts" } : { page: "sync" }) });
  if (snapshot.enrolled && (phone.kind === "warning" || phone.kind === "error") && phone.label !== "Needs review") items.push({ key: "phone", kind: phone.kind, label: phone.label, detail: phone.detail, onClick: () => void router.root({ page: "sync" }) });
  if (sync.data && (sync.data.setAside ?? 0) > 0) items.push({ key: "set-aside", kind: "warning", label: `${plural(sync.data.setAside ?? 0, "change")} could not be read`, detail: "Set aside and tried again on each sync", onClick: () => void router.root({ page: "sync" }) });
  if (sync.data && sync.data.waitingToApply - (sync.data.setAside ?? 0) > 0) items.push({ key: "waiting", kind: "info", label: `${plural(sync.data.waitingToApply - (sync.data.setAside ?? 0), "change")} waiting`, detail: "Applied on a later sync", onClick: () => void router.root({ page: "sync" }) });
  if (browser.data && extension.label === "Not listening") items.push({ key: "browser", kind: "warning", label: "Browser filling is off", detail: "Nuvori isn't listening for the extension", onClick: () => void router.root({ page: "settings", section: "browser" }) });
  if (!snapshot.enrolled) items.push({ key: "pair", kind: "info", label: "Pair with your phone", detail: "Keep both devices in sync", onClick: () => void router.root({ page: "sync" }), dismissible: true });
  if (hello && !snapshot.helloEnabled) items.push({ key: "hello", kind: "info", label: "Turn on Windows Hello", detail: "Unlock with your face, fingerprint, or PIN", onClick: () => void router.root({ page: "settings", section: "security" }), dismissible: true });
  const visible = items.filter((item) => !item.dismissible || !dismissed.includes(item.key));

  if (!visible.length) {
    const syncing = isSyncing(sync.data);
    return (
      <p className="calm-line" role="status">
        {syncing ? <StatusIcon kind="progress" size={16} /> : <CircleCheck aria-hidden="true" />}
        {!snapshot.enrolled ? "Your vault is ready" : syncing ? "Syncing with your devices…" : sync.data?.lastSync ? `Everything's in sync · ${relativeTime(sync.data.lastSync).toLowerCase()}` : "Everything's up to date"}
      </p>
    );
  }
  return (
    <div className="attention" role="list" aria-label="Needs attention">
      {visible.map((item) => (
        <div key={item.key} role="listitem" className={cx("attention-item", `tone-${item.kind}`)}>
          <button type="button" className="attention-main" onClick={item.onClick}>
            <StatusIcon kind={item.kind} size={18} />
            <span className="attention-text"><strong>{item.label}</strong>{item.detail && <span>{item.detail}</span>}</span>
            <ChevronRight aria-hidden="true" className="attention-chevron" />
          </button>
          {item.dismissible && <button type="button" className="attention-dismiss" aria-label={`Dismiss: ${item.label}`} onClick={() => { dismissHint(item.key); setDismissed(readDismissed()); }}><X aria-hidden="true" /></button>}
        </div>
      ))}
    </div>
  );
}

function QuickAccess() {
  const { entries } = useVault();
  const router = useRouter();
  const items = useMemo(() => {
    // Codes have their own live section below, so quick access shows everything else.
    const items = entries.filter((entry) => entry.type !== "AUTHENTICATOR");
    const byId = new Map(items.map((entry) => [entry.id, entry]));
    const favorites = items.filter((entry) => entry.favorite).sort((a, b) => a.title.localeCompare(b.title));
    const recent = readRecent().map((id) => byId.get(id)).filter((entry): entry is VaultEntry => Boolean(entry));
    const updated = [...items].sort((a, b) => b.updatedAt - a.updatedAt);
    const seen = new Set<string>();
    const list: Array<{ entry: VaultEntry; reason: "favorite" | "recent" }> = [];
    for (const entry of favorites) if (!seen.has(entry.id)) { seen.add(entry.id); list.push({ entry, reason: "favorite" }); }
    for (const entry of [...recent, ...updated]) if (!seen.has(entry.id) && list.length < 8) { seen.add(entry.id); list.push({ entry, reason: "recent" }); }
    return list.slice(0, 8);
  }, [entries]);

  return (
    <section className="section" aria-labelledby="quick-title">
      <div className="section-header"><h2 id="quick-title">Quick access</h2></div>
      {items.length === 0 ? (
        <div className="card card-padded hint-card"><Star aria-hidden="true" /><span>Star an item or open one, and it shows up here.</span></div>
      ) : (
        <ul className="qa-grid">
          {items.map(({ entry }) => (
            <li key={entry.id} className={cx("qa-card", router.highlight === entry.id && "is-highlighted")} data-row-id={entry.id}>
              <button type="button" className="qa-open" onClick={() => void router.navigate({ page: "item", id: entry.id })} aria-label={`Open ${entry.title}`}>
                <Avatar title={entry.title || "?"} />
                <span className="qa-text">
                  <span className="qa-title"><span className="truncate">{entry.title || "Untitled"}</span>{entry.favorite && <Star className="fav-star" aria-label="Favorite" />}</span>
                  <span className="qa-subtitle truncate">{entrySubtitle(entry)}</span>
                </span>
              </button>
              <div className="qa-actions"><EntryQuickActions entry={entry} /></div>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

function LiveCodes() {
  const { entries } = useVault();
  const router = useRouter();
  const copy = useCopy();
  const codes = useMemo(() => {
    const all = entries.filter((entry) => entry.type === "AUTHENTICATOR");
    const byName = (a: VaultEntry, b: VaultEntry) => a.title.localeCompare(b.title);
    // Favorites first, then the rest, up to four.
    return [...all.filter((entry) => entry.favorite).sort(byName), ...all.filter((entry) => !entry.favorite).sort(byName)].slice(0, 4);
  }, [entries]);
  const now = useNow(1000, codes.length > 0);
  const live = useTotpCodes(codes, now);
  if (!codes.length) return null;
  return (
    <section className="section" aria-labelledby="codes-title">
      <div className="section-header">
        <h2 id="codes-title">Codes</h2>
        <Button variant="ghost" size="sm" trailingIcon={ChevronRight} onClick={() => void router.root({ page: "codes" })}>All codes</Button>
      </div>
      <ul className="live-codes">
        {codes.map((entry) => {
          const code = live.get(entry.id);
          const urgent = code ? code.seconds <= 5 : false;
          return (
            <li key={entry.id} className={cx("live-code", urgent && "is-urgent")}>
              <button type="button" className="live-code-main" aria-label={`Copy code for ${entry.title}`}
                onClick={() => void copy(async () => (await totpAt(entry))?.value ?? null, { label: "Code", secret: true, message: `${entry.title} code copied` })}>
                <span className="live-code-text">
                  <span className="live-code-title truncate">{entry.title}</span>
                  <span className="live-code-value">{code?.value ? groupCode(code.value) : "––– –––"}</span>
                </span>
                {code && <CountdownRing seconds={code.seconds} period={code.period} size={30} />}
                <Copy aria-hidden="true" className="live-code-copy" />
              </button>
            </li>
          );
        })}
      </ul>
    </section>
  );
}

function Categories({ counts }: { counts: Record<Category | "notes", number> }) {
  const router = useRouter();
  const tiles: Array<{ key: Category | "notes"; label: string; icon: LucideIcon }> = [
    ...categoryOrder.map((key) => ({ key, label: categories[key].label, icon: categories[key].icon })),
    { key: "notes" as const, label: "Notes", icon: FileText }
  ];
  return (
    <section className="section" aria-labelledby="categories-title">
      <div className="section-header"><h2 id="categories-title">Categories</h2></div>
      <div className="tiles">
        {tiles.map(({ key, label, icon: Icon }) => (
          <button key={key} type="button" className="tile" onClick={() => void router.root(key === "codes" ? { page: "codes" } : key === "notes" ? { page: "notes" } : { page: "list", category: key })}>
            <span className={`tile-icon cat-${key}`}><Icon aria-hidden="true" /></span>
            <span className="tile-count">{counts[key]}</span>
            <span className="tile-label">{label}</span>
          </button>
        ))}
      </div>
    </section>
  );
}

function QuickActions() {
  const { snapshot } = useVault();
  const router = useRouter();
  const sync = useSyncStatus(4000);
  const syncNow = useSyncNow(sync.data?.phoneAddress ?? "", sync.reload);
  const addItems = useAddItems();
  const running = syncNow.busy || isSyncing(sync.data);
  return (
    <section className="section" aria-labelledby="actions-title">
      <div className="section-header"><h2 id="actions-title">Quick actions</h2></div>
      <div className="card rows quick-actions">
        <Menu label="Add new" align="start" items={addItems} trigger={(props) => (
          <button type="button" {...props} className="action-row"><span className="row-icon"><Plus aria-hidden="true" /></span><span className="row-text"><span className="row-title">Add an item</span><span className="row-description">Password, card, code, note…</span></span><ChevronRight aria-hidden="true" className="row-chevron" /></button>
        )} />
        {snapshot.enrolled ? (
          <button type="button" className="action-row" disabled={running || !sync.data} onClick={() => void syncNow.run()}>
            <span className="row-icon"><RefreshCw aria-hidden="true" className={running ? "spin" : undefined} /></span>
            <span className="row-text"><span className="row-title">{running ? "Syncing changes" : "Sync now"}</span><span className="row-description">{sync.data?.lastSync ? `Last sync ${relativeTime(sync.data.lastSync).toLowerCase()}` : "Exchange changes with your devices"}</span></span>
          </button>
        ) : (
          <button type="button" className="action-row" onClick={() => void router.root({ page: "sync" })}>
            <span className="row-icon"><MonitorSmartphone aria-hidden="true" /></span>
            <span className="row-text"><span className="row-title">Pair with your phone</span><span className="row-description">Scan a QR to copy your vault here</span></span>
            <ChevronRight aria-hidden="true" className="row-chevron" />
          </button>
        )}
        <button type="button" className="action-row" onClick={() => void router.root({ page: "codes" })}>
          <span className="row-icon"><Fingerprint aria-hidden="true" /></span>
          <span className="row-text"><span className="row-title">Codes and passkeys</span><span className="row-description">Two-step codes and saved passkeys</span></span>
          <ChevronRight aria-hidden="true" className="row-chevron" />
        </button>
      </div>
    </section>
  );
}

/** Runs a sync pass with a progress toast. Shared by Home and Sync. */
export function useSyncNow(address: string, after?: () => Promise<void> | void) {
  const toast = useToast();
  const { refresh } = useVault();
  const [busy, setBusy] = useState(false);
  const run = async (override?: { address: string; automatic: boolean }) => {
    const target = (override?.address ?? address).trim();

    setBusy(true);
    const progress = toast.progress("Syncing with your devices…");
    try {
      const report = await api.syncNow(target);
      if (override) await api.configureSync(target, override.automatic);
      const parts = [report.sent ? `sent ${report.sent}` : "", report.received ? `received ${report.received}` : ""].filter(Boolean);
      const route = report.cloud && !report.peersChecked ? "Synced through Google Drive" : "Synced";
      const summary = parts.length ? `${route} · ${parts.join(", ")}` : report.cloud && !report.peersChecked ? "Google Drive is up to date" : "Sync check complete";
      if (report.conflicts) progress.warning(`${summary}. ${plural(report.conflicts, "change")} need review.`);
      else if (report.waitingToApply) progress.info(`${summary}. ${report.waitingToApply} still waiting to apply.`);
      else if (report.peersWaiting && !report.cloud) progress.info(`${summary}. ${plural(report.peersWaiting, "device")} will catch up when connected.`);
      else progress.success(summary);
      return true;
    } catch (failure) {
      progress.error(failure, "Sync didn't finish. Try again.");
      return false;
    } finally {
      setBusy(false);
      await refresh();
      await after?.();
    }
  };
  return { busy, run };
}

