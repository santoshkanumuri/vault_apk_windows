import { useEffect, useMemo, useRef, useState, type KeyboardEvent } from "react";
import { Activity, ArrowRight, CornerDownLeft, FileText, House, LockKeyhole, MonitorSmartphone, Plus, Search, Settings, type LucideIcon } from "lucide-react";
import { Avatar, Highlighted, Kbd } from "../components/Display";
import { IconButton } from "../components/Button";
import { useLock } from "../app/hooks";
import { useRouter, type Route } from "../app/router";
import { useVault } from "../app/vault";
import type { EntryType } from "../lib/api";
import { categories, categoryOrder, typeLabel } from "../lib/entries";
import { cx } from "../lib/format";
import { buildIndex, fold, highlight, searchDocs, tokenize, type SearchDoc } from "../lib/search";
import { useEntryActions, type QuickAction } from "./items/actions";

type Command = { id: string; title: string; hint: string; icon: LucideIcon; keywords: string; run: () => void };
type Result =
  | { kind: "doc"; key: string; doc: SearchDoc; actions: QuickAction[] }
  | { kind: "command"; key: string; command: Command };

const groupOrder: Array<EntryType | "NOTE" | "COMMAND"> = ["PASSWORD", "CARD", "AUTHENTICATOR", "QUESTION", "AUTOFILL", "NOTE", "COMMAND"];
const groupTitle = (group: EntryType | "NOTE" | "COMMAND") => group === "NOTE" ? "Notes" : group === "COMMAND" ? "Go to" : categories[categoryOrder.find((key) => categories[key].type === group)!].label;
const groupIcon = (group: EntryType | "NOTE" | "COMMAND"): LucideIcon => group === "NOTE" ? FileText : group === "COMMAND" ? ArrowRight : categories[categoryOrder.find((key) => categories[key].type === group)!].icon;

export function SearchPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const list = useRef<HTMLDivElement>(null);
  const { entries, notes } = useVault();
  const router = useRouter();
  const lock = useLock();
  const actionsFor = useEntryActions();
  const [query, setQuery] = useState("");
  const [active, setActive] = useState(0);

  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      dialog.showModal();
      setQuery("");
      setActive(0);
      window.setTimeout(() => input.current?.focus(), 0);
    } else if (!open && dialog.open) dialog.close();
  }, [open]);

  const go = (route: Route) => { onClose(); void router.navigate(route); };
  const goRoot = (route: Route) => { onClose(); void router.root(route); };

  const commands = useMemo<Command[]>(() => [
    { id: "home", title: "Home", hint: "Dashboard", icon: House, keywords: "home dashboard", run: () => goRoot({ page: "home" }) },
    ...categoryOrder.map((key) => ({ id: key, title: categories[key].label, hint: "Open list", icon: categories[key].icon, keywords: `${categories[key].label} ${categories[key].singular}${key === "logins" ? " logins login" : ""}`, run: () => goRoot(key === "codes" ? { page: "codes" } : { page: "list", category: key }) })),
    { id: "notes", title: "Notes", hint: "Open list", icon: FileText, keywords: "notes", run: () => goRoot({ page: "notes" }) },
    ...categoryOrder.map((key) => ({ id: `new-${key}`, title: `New ${categories[key].singular}`, hint: "Create", icon: Plus, keywords: `new add create ${categories[key].singular}`, run: () => go({ page: "edit", category: key }) })),
    { id: "new-note", title: "New note", hint: "Create", icon: Plus, keywords: "new add create note", run: () => go({ page: "note-edit" }) },
    { id: "sync", title: "Devices & sync", hint: "Phone sync and pairing", icon: MonitorSmartphone, keywords: "sync phone devices pair pairing", run: () => goRoot({ page: "sync" }) },
    { id: "activity", title: "Activity", hint: "Recent events", icon: Activity, keywords: "activity log logs history events", run: () => goRoot({ page: "activity" }) },
    { id: "settings", title: "Settings", hint: "Theme, security, extension", icon: Settings, keywords: "settings preferences theme dark light hello extension browser", run: () => goRoot({ page: "settings" }) },
    { id: "lock", title: "Lock vault", hint: "Ctrl+L", icon: LockKeyhole, keywords: "lock", run: () => { onClose(); void lock(); } }
  ], [router, lock]); // eslint-disable-line react-hooks/exhaustive-deps

  const docs = useMemo(() => open ? buildIndex(entries, notes) : [], [open, entries, notes]);
  const tokens = useMemo(() => tokenize(query), [query]);

  const groups = useMemo(() => {
    const results: Array<{ group: EntryType | "NOTE" | "COMMAND"; items: Result[] }> = [];
    if (!tokens.length) {
      const recent = [...docs].sort((a, b) => Number(b.favorite) - Number(a.favorite) || b.updatedAt - a.updatedAt).slice(0, 6);
      if (recent.length) results.push({ group: "PASSWORD", items: recent.map((doc) => ({ kind: "doc", key: `${doc.kind}:${doc.id}`, doc, actions: doc.kind === "entry" ? actionsFor(doc.entry) : [] })) });
      results.push({ group: "COMMAND", items: commands.slice(0, 7).map((command) => ({ kind: "command", key: `cmd:${command.id}`, command })) });
      return results;
    }
    const found = searchDocs(docs, query, 50);
    const byGroup = new Map<EntryType | "NOTE" | "COMMAND", Result[]>();
    for (const { doc } of found) {
      const group = doc.kind === "note" ? "NOTE" : doc.entry.type;
      const bucket = byGroup.get(group) ?? [];
      bucket.push({ kind: "doc", key: `${doc.kind}:${doc.id}`, doc, actions: doc.kind === "entry" ? actionsFor(doc.entry) : [] });
      byGroup.set(group, bucket);
    }
    const matchingCommands = commands.filter((command) => tokens.every((token) => fold(`${command.title} ${command.keywords}`).includes(token))).slice(0, 5);
    if (matchingCommands.length) byGroup.set("COMMAND", matchingCommands.map((command) => ({ kind: "command", key: `cmd:${command.id}`, command })));
    // Order groups by their best result so the strongest match is on top.
    const orderOf = (group: EntryType | "NOTE" | "COMMAND") => {
      if (group === "COMMAND") return found.length ? 1000 : -1;
      const index = found.findIndex(({ doc }) => (doc.kind === "note" ? "NOTE" : doc.entry.type) === group);
      return index < 0 ? 999 : index;
    };
    for (const group of [...groupOrder].sort((a, b) => orderOf(a) - orderOf(b))) {
      const items = byGroup.get(group);
      if (items?.length) results.push({ group, items });
    }
    return results;
  }, [docs, query, tokens, commands, actionsFor]);

  const flat = useMemo(() => groups.flatMap((group) => group.items), [groups]);
  useEffect(() => { setActive(0); }, [query]);
  useEffect(() => {
    list.current?.querySelector<HTMLElement>(`[data-index="${active}"]`)?.scrollIntoView({ block: "nearest" });
  }, [active]);

  const choose = (result: Result | undefined) => {
    if (!result) return;
    if (result.kind === "command") { result.command.run(); return; }
    go(result.doc.kind === "note" ? { page: "note", id: result.doc.id } : { page: "item", id: result.doc.id });
  };

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown") { event.preventDefault(); setActive((index) => Math.min(flat.length - 1, index + 1)); }
    else if (event.key === "ArrowUp") { event.preventDefault(); setActive((index) => Math.max(0, index - 1)); }
    else if (event.key === "Enter") {
      event.preventDefault();
      const result = flat[active];
      // Ctrl+Enter runs the first quick action (e.g. copy password) without opening the item.
      if ((event.ctrlKey || event.metaKey) && result?.kind === "doc" && result.actions.length) {
        const primary = ["password", "code", "answer", "number", "email"].map((key) => result.actions.find((action) => action.key === key)).find(Boolean) ?? result.actions[0];
        void primary.run();
        onClose();
        return;
      }
      choose(result);
    }
  };

  let index = -1;
  return (
    <dialog ref={ref} className="palette" aria-label="Search" onCancel={(event) => { event.preventDefault(); onClose(); }} onMouseDown={(event) => { if (event.target === ref.current) onClose(); }}>
      {open && <div className="palette-surface">
        <div className="palette-input">
          <Search aria-hidden="true" />
          <input ref={input} type="text" role="combobox" aria-expanded="true" aria-controls="palette-results" aria-activedescendant={flat[active] ? `palette-${active}` : undefined}
            aria-label="Search your vault" placeholder="Search logins, cards, codes, notes…" value={query} onChange={(event) => setQuery(event.target.value)} onKeyDown={onKeyDown} spellCheck={false} autoComplete="off" />
          <Kbd>Esc</Kbd>
        </div>
        <div className="palette-results" id="palette-results" role="listbox" ref={list} aria-label="Results">
          {tokens.length > 0 && flat.length === 0 && <p className="palette-empty">No results for "{query}". Search matches titles, usernames, websites, tags, notes, and card last 4.</p>}
          {groups.map(({ group, items }) => {
            const GroupIcon = groupIcon(group);
            return (
              <div key={group} className="palette-group" role="group" aria-label={!tokens.length && group === "PASSWORD" ? "Recent" : groupTitle(group)}>
                <div className="palette-group-title"><GroupIcon aria-hidden="true" />{!tokens.length && group === "PASSWORD" ? "Favorites and recent" : groupTitle(group)}</div>
                {items.map((result) => {
                  index++;
                  const current = index;
                  const selected = current === active;
                  if (result.kind === "command") {
                    const Icon = result.command.icon;
                    return (
                      <div key={result.key} id={`palette-${current}`} data-index={current} role="option" aria-selected={selected} className={cx("palette-item", selected && "is-active")} onMouseMove={() => setActive(current)} onClick={() => choose(result)}>
                        <span className="palette-icon"><Icon aria-hidden="true" /></span>
                        <span className="palette-text"><span className="palette-title"><Highlighted segments={highlight(result.command.title, tokens)} /></span><span className="palette-subtitle">{result.command.hint}</span></span>
                        {selected && <CornerDownLeft className="palette-enter" aria-hidden="true" />}
                      </div>
                    );
                  }
                  const { doc } = result;
                  return (
                    <div key={result.key} id={`palette-${current}`} data-index={current} role="option" aria-selected={selected} className={cx("palette-item", selected && "is-active")} onMouseMove={() => setActive(current)} onClick={() => choose(result)}>
                      <Avatar title={doc.title || "?"} size="sm" icon={doc.kind === "note" ? FileText : undefined} />
                      <span className="palette-text">
                        <span className="palette-title"><Highlighted segments={highlight(doc.title || "Untitled", tokens)} /></span>
                        <span className="palette-subtitle">{doc.kind === "entry" && !tokens.length ? `${typeLabel(doc.entry.type)} · ` : ""}<Highlighted segments={highlight(doc.subtitle, tokens)} /></span>
                      </span>
                      <span className="palette-actions">
                        {result.actions.map((action) => (
                          <IconButton key={action.key} label={action.label} icon={action.icon} size="sm" tabIndex={-1}
                            onClick={(event) => { event.stopPropagation(); void action.run(); onClose(); }} />
                        ))}
                      </span>
                    </div>
                  );
                })}
              </div>
            );
          })}
        </div>
        <div className="palette-footer">
          <span><Kbd>↑</Kbd><Kbd>↓</Kbd> move</span>
          <span><Kbd>Enter</Kbd> open</span>
          <span><Kbd>Ctrl</Kbd><Kbd>Enter</Kbd> copy secret</span>
        </div>
      </div>}
    </dialog>
  );
}
