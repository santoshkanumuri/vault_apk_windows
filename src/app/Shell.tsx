import { useCallback, useEffect, useLayoutEffect, useRef, useState, type ReactNode, type SyntheticEvent } from "react";
import { SearchContext } from "./search";
import { Activity, ArchiveRestore, ArrowLeft, Clock3, CircleHelp, CreditCard, Ellipsis, FileText, House, KeyRound, LockKeyhole, LogIn, MonitorSmartphone, Moon, Search, Settings, Sun, UserRound, type LucideIcon } from "lucide-react";
import { IconButton } from "../components/Button";
import { api, onQuickSearch } from "../lib/api";
import { Kbd } from "../components/Display";
import { BrandMark } from "../pages/Unlock";
import { HomePage } from "../pages/Home";
import { ItemsListPage } from "../pages/items/ItemsList";
import { ItemDetailPage } from "../pages/items/ItemDetail";
import { ItemEditorPage } from "../pages/items/ItemEditor";
import { CodesPage } from "../pages/codes/CodesPage";
import { SignInsPage } from "../pages/signins/SignInsPage";
import { NoteDetailPage, NoteEditorPage, NotesListPage } from "../pages/notes/Notes";
import { SyncPage } from "../pages/sync/SyncPage";
import { ConflictsPage } from "../pages/sync/ConflictsPage";
import { SettingsPage } from "../pages/SettingsPage";
import { ActivityPage } from "../pages/ActivityPage";
import { MorePage } from "../pages/MorePage";
import { TrashPage } from "../pages/TrashPage";
import { AutoTypePicker } from "../components/AutoTypePicker";
import { SearchPalette } from "../pages/SearchPalette";
import { categories, categoryForType, type Category } from "../lib/entries";
import { cx } from "../lib/format";
import { useLock } from "./hooks";
import { isTransient, routeKey, useRouter, type Route } from "./router";
import { usePreferences } from "./settings";
import { useTheme } from "./theme";
import { useToast } from "./toast";
import { useVault } from "./vault";
import { strings } from "../strings";

type NavItem = { id: string; label: string; icon: LucideIcon; route: Route };

const primaryNav: NavItem[] = [
  { id: "home", label: "Home", icon: House, route: { page: "home" } },
  { id: "cards", label: "Cards", icon: CreditCard, route: { page: "list", category: "cards" } },
  { id: "logins", label: "Passwords", icon: KeyRound, route: { page: "list", category: "logins" } },
  { id: "signins", label: "Sign-ins", icon: LogIn, route: { page: "signins" } },
  { id: "codes", label: "Codes", icon: Clock3, route: { page: "codes" } },
  { id: "notes", label: "Notes", icon: FileText, route: { page: "notes" } },
  { id: "questions", label: "Questions", icon: CircleHelp, route: { page: "list", category: "questions" } },
  { id: "autofill", label: "Autofill", icon: UserRound, route: { page: "list", category: "autofill" } }
];
const secondaryNav: NavItem[] = [
  { id: "sync", label: "Devices & sync", icon: MonitorSmartphone, route: { page: "sync" } },
  { id: "activity", label: "Activity", icon: Activity, route: { page: "activity" } },
  { id: "trash", label: "Recently deleted", icon: ArchiveRestore, route: { page: "trash" } },
  { id: "settings", label: "Settings", icon: Settings, route: { page: "settings" } }
];
const bottomNav: NavItem[] = [
  primaryNav[0], primaryNav[1], primaryNav[2], primaryNav.find((item) => item.id === "codes") ?? primaryNav[3],
  { id: "more", label: "More", icon: Ellipsis, route: { page: "more" } }
];


/** Which nav entry is "current" for any route, including details and editors. */
function sectionFor(route: Route, entryCategory: (id: string) => Category | undefined): string {
  switch (route.page) {
    case "list": return route.category;
    case "codes": return "codes";
    case "item": return entryCategory(route.id) ?? "home";
    case "edit": return route.category;
    case "notes": case "note": case "note-edit": return "notes";
    case "conflicts": return "sync";
    default: return route.page;
  }
}

export function Shell() {
  const router = useRouter();
  const { route, canGoBack, back, scrollElement, scrollPositions, direction, highlight } = router;
  const { entries } = useVault();
  const { resolved, toggle } = useTheme();
  const toast = useToast();
  const lock = useLock();
  const { autoLockMinutes } = usePreferences();
  const [searchOpen, setSearchOpen] = useState(false);
  const key = routeKey(route);
  const entryCategory = useCallback((id: string) => {
    const entry = entries.find((item) => item.id === id);
    return entry ? categoryForType(entry.type) : undefined;
  }, [entries]);
  const section = sectionFor(route, entryCategory);
  const bottomSection = bottomNav.some((item) => item.id === section) ? section : "more";

  const openSearch = useCallback(() => setSearchOpen(true), []);

  // The system-wide quick search shortcut. The app only tells us it was pressed recently (the
  // window is unlocked here, so the lock was never bypassed). Pressed again with the palette open,
  // it hides the window.
  const searchOpenRef = useRef(false);
  searchOpenRef.current = searchOpen;
  useEffect(() => {
    const handle = async (hadFocus: boolean) => {
      const requested = await api.takeQuickSearchRequest().catch(() => false);
      if (!requested) return;
      if (hadFocus && searchOpenRef.current) {
        setSearchOpen(false);
        void api.hideMainWindow().catch(() => {});
      } else if (!document.querySelector("dialog[open]")) setSearchOpen(true);
    };
    void handle(false);
    return onQuickSearch((hadFocus) => void handle(hadFocus));
  }, []);
  const toggleTheme = () => {
    const next = toggle();
    toast.success(next === "dark" ? "Dark theme on" : "Light theme on");
  };

  // Restore scroll per route: back/root navigation returns to the saved position, forward starts at the top.
  useLayoutEffect(() => {
    const element = scrollElement.current;
    if (!element) return;
    const saved = scrollPositions.current.get(key);
    const target = direction.current !== "forward" && saved !== undefined ? saved : 0;
    element.scrollTop = target;
    const frame = window.requestAnimationFrame(() => {
      if (Math.abs(element.scrollTop - target) > 1) element.scrollTop = target;
      if (direction.current === "back" && highlight) {
        const row = element.querySelector<HTMLElement>(`[data-row-id="${CSS.escape(highlight)}"]`);
        if (row) {
          const box = row.getBoundingClientRect();
          const view = element.getBoundingClientRect();
          if (box.top < view.top || box.bottom > view.bottom) row.scrollIntoView({ block: "nearest" });
          row.querySelector<HTMLElement>("button")?.focus({ preventScroll: true });
          return;
        }
      }
      // Keep the focus a new page set itself (an editor's first field); otherwise start at the page.
      if (direction.current !== "back" && !element.contains(document.activeElement)) element.focus({ preventScroll: true });
    });
    return () => window.cancelAnimationFrame(frame);
  }, [key]); // eslint-disable-line react-hooks/exhaustive-deps

  // Global shortcuts: search, lock, new item, back.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      const dialogOpen = document.querySelector("dialog[open]") !== null;
      const ctrl = event.ctrlKey || event.metaKey;
      const lowerKey = event.key.toLowerCase();
      if (ctrl && !event.shiftKey && !event.altKey && (lowerKey === "k" || lowerKey === "f")) {
        event.preventDefault();
        if (!dialogOpen) setSearchOpen(true);
        return;
      }
      if (ctrl && lowerKey === "l") { event.preventDefault(); void lock(); return; }
      if (dialogOpen) return;
      if (ctrl && lowerKey === "n") {
        event.preventDefault();
        if (section === "notes") void router.navigate({ page: "note-edit" });
        else if (section in categories) void router.navigate({ page: "edit", category: section as Category });
        else void router.navigate({ page: "edit", category: "logins" });
        return;
      }
      if (event.altKey && event.key === "ArrowLeft") { event.preventDefault(); void back(); return; }
      if (event.key === "Escape" && isTransient(route)) {
        const target = event.target as HTMLElement | null;
        // Let an open <select> or a field that handles Esc itself go first.
        if (event.defaultPrevented || target?.tagName === "SELECT") return;
        event.preventDefault();
        void back();
      }
    };
    const onMouse = (event: MouseEvent) => {
      if (event.button === 3) { event.preventDefault(); if (!document.querySelector("dialog[open]")) void back(); }
    };
    window.addEventListener("keydown", onKey);
    window.addEventListener("mouseup", onMouse);
    return () => { window.removeEventListener("keydown", onKey); window.removeEventListener("mouseup", onMouse); };
  }, [route, section, back, lock, router]);

  // Auto-lock after inactivity.
  useEffect(() => {
    if (!autoLockMinutes) return;
    let last = Date.now();
    const bump = () => { last = Date.now(); };
    const events = ["mousemove", "mousedown", "keydown", "wheel", "touchstart", "focus"] as const;
    events.forEach((name) => window.addEventListener(name, bump, { passive: true }));
    const timer = window.setInterval(() => {
      if (Date.now() - last >= autoLockMinutes * 60_000) void lock({ force: true, reason: "Locked after inactivity" });
    }, 10_000);
    return () => { events.forEach((name) => window.removeEventListener(name, bump)); window.clearInterval(timer); };
  }, [autoLockMinutes, lock]);

  const title = useRouteTitle(route);

  // Icon-rail labels. The rail's nav scrolls on short windows, which would clip CSS ::after tooltips,
  // so one fixed-position tooltip follows the hovered or keyboard-focused item instead.
  const [railTip, setRailTip] = useState<{ text: string; top: number; left: number } | null>(null);
  const showRailTip = (event: SyntheticEvent) => {
    const item = (event.target as HTMLElement).closest<HTMLElement>(".nav-item[data-tooltip]");
    if (!item || (event.type === "focus" && !item.matches(":focus-visible"))) { setRailTip(null); return; }
    const rect = item.getBoundingClientRect();
    const next = { text: item.dataset.tooltip ?? "", top: rect.top + rect.height / 2, left: rect.right + 10 };
    setRailTip((current) => current && current.text === next.text && current.top === next.top && current.left === next.left ? current : next);
  };
  const hideRailTip = () => setRailTip(null);

  const navButton = (item: NavItem, current: string, variant: "side" | "bottom") => (
    <button key={item.id} type="button" className={cx(variant === "side" ? "nav-item" : "bottom-item", current === item.id && "is-active")} aria-current={current === item.id ? "page" : undefined}
      data-tooltip={variant === "side" ? item.label : undefined} onClick={() => void router.root(item.route)}>
      <item.icon aria-hidden="true" />
      <span className="nav-label">{item.label}</span>
    </button>
  );

  return (
    <SearchContext.Provider value={openSearch}>
      <div className="shell">
        <a className="skip-link" href="#main-content">{strings.skipToContent}</a>
        <aside className="sidebar" aria-label={strings.primary} onMouseOver={showRailTip} onMouseLeave={hideRailTip} onFocus={showRailTip} onBlur={hideRailTip}>
          <div className="sidebar-brand">
            <BrandMark />
            <span className="nav-label brand-text"><strong>{strings.nuvori}</strong><span>{strings.yoursByDesign}</span></span>
          </div>
          <nav className="nav" aria-label={strings.vault} onScroll={hideRailTip}>
            {primaryNav.map((item) => navButton(item, section, "side"))}
            <div className="nav-divider" role="separator" />
            {secondaryNav.map((item) => navButton(item, section, "side"))}
          </nav>
          <div className="sidebar-footer">
            <button type="button" className="nav-item" data-tooltip={resolved === "dark" ? "Light theme" : "Dark theme"} onClick={toggleTheme} aria-label={resolved === "dark" ? "Switch to light theme" : "Switch to dark theme"}>
              {resolved === "dark" ? <Sun aria-hidden="true" /> : <Moon aria-hidden="true" />}
              <span className="nav-label">{resolved === "dark" ? "Light theme" : "Dark theme"}</span>
            </button>
            <button type="button" className="nav-item" data-tooltip="Lock (Ctrl+L)" onClick={() => void lock()}>
              <LockKeyhole aria-hidden="true" />
              <span className="nav-label">{strings.lockVault}</span>
            </button>
          </div>
        </aside>
        {railTip && <div className="rail-tooltip" aria-hidden="true" style={{ top: railTip.top, left: railTip.left }}>{railTip.text}</div>}

        <div className="main-column">
          <header className={cx("topbar", route.page === "home" && "is-home")}>
            {canGoBack && <IconButton label={strings.back} icon={ArrowLeft} onClick={() => void back()} className="back-button" />}
            {!canGoBack && <span className="topbar-brand"><BrandMark /></span>}
            <h1 className="topbar-title truncate">{title}</h1>
            <div className="topbar-actions">
              <button type="button" className="search-trigger" onClick={openSearch} aria-label={strings.searchCtrlK} aria-keyshortcuts="Control+K">
                <Search aria-hidden="true" />
                <span className="search-trigger-label">{strings.search}</span>
                <span className="search-trigger-keys"><Kbd>{strings.ctrl}</Kbd><Kbd>{strings.k}</Kbd></span>
              </button>
              <IconButton className="narrow-only" label={resolved === "dark" ? "Switch to light theme" : "Switch to dark theme"} icon={resolved === "dark" ? Sun : Moon} onClick={toggleTheme} />
              <IconButton className="narrow-only" label={strings.lockVault} icon={LockKeyhole} onClick={() => void lock()} />
            </div>
          </header>
          <main id="main-content" className="content" ref={(element) => { scrollElement.current = element; }} tabIndex={-1}>
            <div className={cx("content-inner", `enter-${direction.current}`)} key={key}>
              <PageFor route={route} />
            </div>
          </main>
        </div>

        <nav className="bottom-nav" aria-label={strings.quickNavigation}>
          {bottomNav.map((item) => navButton(item, bottomSection, "bottom"))}
        </nav>
      </div>
      <AutoTypePicker />
      <SearchPalette open={searchOpen} onClose={() => setSearchOpen(false)} />
    </SearchContext.Provider>
  );
}

function PageFor({ route }: { route: Route }): ReactNode {
  switch (route.page) {
    case "home": return <HomePage />;
    case "list": return <ItemsListPage category={route.category} />;
    case "codes": return <CodesPage />;
    case "signins": return <SignInsPage />;
    case "item": return <ItemDetailPage id={route.id} />;
    case "edit": return <ItemEditorPage id={route.id} category={route.category} />;
    case "notes": return <NotesListPage />;
    case "note": return <NoteDetailPage id={route.id} />;
    case "note-edit": return <NoteEditorPage id={route.id} />;
    case "sync": return <SyncPage />;
    case "conflicts": return <ConflictsPage />;
    case "settings": return <SettingsPage section={route.section} />;
    case "activity": return <ActivityPage />;
    case "trash": return <TrashPage />;
    case "more": return <MorePage />;
  }
}

function useRouteTitle(route: Route): string {
  const { entries, notes } = useVault();
  switch (route.page) {
    case "home": return "Home";
    case "list": return categories[route.category].label;
    case "codes": return "Codes";
    case "signins": return "Sign-ins";
    case "item": {
      const entry = entries.find((item) => item.id === route.id);
      return entry ? categories[categoryForType(entry.type)].label.replace(/s$/, "") : "Item";
    }
    case "edit": {
      const info = categories[route.category];
      return route.id ? `Edit ${info.singular}` : `New ${info.singular}`;
    }
    case "notes": return "Notes";
    case "note": return notes.some((note) => note.id === route.id) ? "Note" : "Note";
    case "note-edit": return route.id ? "Edit note" : "New note";
    case "sync": return "Devices & sync";
    case "conflicts": return "Needs review";
    case "settings": return "Settings";
    case "activity": return "Activity";
    case "trash": return "Recently deleted";
    case "more": return "More";
  }
}
