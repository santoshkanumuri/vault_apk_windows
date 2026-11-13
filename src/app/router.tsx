import { createContext, useCallback, useContext, useMemo, useRef, useState, type MutableRefObject, type ReactNode } from "react";
import type { Category } from "../lib/entries";

export type Route =
  | { page: "home" }
  | { page: "list"; category: Exclude<Category, "codes"> }
  | { page: "codes" }
  | { page: "item"; id: string }
  | { page: "edit"; id?: string; category: Category }
  | { page: "notes" }
  | { page: "note"; id: string }
  | { page: "note-edit"; id?: string }
  | { page: "sync" }
  | { page: "conflicts" }
  | { page: "settings"; section?: string }
  | { page: "activity" }
  | { page: "more" };

export function routeKey(route: Route): string {
  switch (route.page) {
    case "list": return `list:${route.category}`;
    case "item": return `item:${route.id}`;
    case "edit": return `edit:${route.id ?? `new-${route.category}`}`;
    case "note": return `note:${route.id}`;
    case "note-edit": return `note-edit:${route.id ?? "new"}`;
    default: return route.page;
  }
}

/** Detail and editor routes close with Esc. */
export function isTransient(route: Route): boolean {
  return route.page === "item" || route.page === "edit" || route.page === "note" || route.page === "note-edit" || route.page === "conflicts";
}

type Guard = () => Promise<boolean> | boolean;

type RouterValue = {
  route: Route;
  stack: Route[];
  canGoBack: boolean;
  /** Push a route (or replace the current one). */
  navigate: (route: Route, options?: { replace?: boolean }) => Promise<boolean>;
  /** Top-level navigation: resets history to this route. */
  root: (route: Route) => Promise<boolean>;
  back: () => Promise<boolean>;
  /** Set by editors with unsaved changes. Returning false cancels navigation. */
  setGuard: (guard: Guard | null) => void;
  /** Id of the row to flash after returning to a list. */
  highlight: string | null;
  /** How the current route was reached; used for scroll restoration. */
  direction: MutableRefObject<"forward" | "back" | "root">;
  scrollPositions: MutableRefObject<Map<string, number>>;
  scrollElement: MutableRefObject<HTMLElement | null>;
  routeState: MutableRefObject<Map<string, unknown>>;
  reset: () => void;
};

const RouterContext = createContext<RouterValue | null>(null);

export function RouterProvider({ children }: { children: ReactNode }) {
  const [stack, setStack] = useState<Route[]>([{ page: "home" }]);
  const [highlight, setHighlight] = useState<string | null>(null);
  const stackRef = useRef(stack);
  stackRef.current = stack;
  const guard = useRef<Guard | null>(null);
  const direction = useRef<"forward" | "back" | "root">("root");
  const scrollPositions = useRef(new Map<string, number>());
  const scrollElement = useRef<HTMLElement | null>(null);
  const routeState = useRef(new Map<string, unknown>());
  const highlightTimer = useRef<number | undefined>(undefined);
  const busy = useRef(false);

  const allow = useCallback(async () => {
    if (!guard.current) return true;
    if (busy.current) return false;
    busy.current = true;
    try {
      const ok = await guard.current();
      if (ok) guard.current = null;
      return ok;
    } finally {
      busy.current = false;
    }
  }, []);

  const saveScroll = useCallback(() => {
    const current = stackRef.current[stackRef.current.length - 1];
    if (current && scrollElement.current) scrollPositions.current.set(routeKey(current), scrollElement.current.scrollTop);
  }, []);

  const flash = useCallback((id: string | null) => {
    window.clearTimeout(highlightTimer.current);
    setHighlight(id);
    if (id) highlightTimer.current = window.setTimeout(() => setHighlight(null), 1800);
  }, []);

  const navigate = useCallback(async (route: Route, options?: { replace?: boolean }) => {
    if (!(await allow())) return false;
    saveScroll();
    direction.current = "forward";
    flash(null);
    setStack((current) => {
      const next = options?.replace ? current.slice(0, -1) : current;
      return [...next, route];
    });
    return true;
  }, [allow, saveScroll, flash]);

  const root = useCallback(async (route: Route) => {
    if (!(await allow())) return false;
    saveScroll();
    const current = stackRef.current[stackRef.current.length - 1];
    direction.current = current && routeKey(current) === routeKey(route) && stackRef.current.length === 1 ? "forward" : "root";
    flash(null);
    setStack(route.page === "home" ? [route] : [{ page: "home" }, route]);
    return true;
  }, [allow, saveScroll, flash]);

  const back = useCallback(async () => {
    if (stackRef.current.length < 2) return false;
    if (!(await allow())) return false;
    saveScroll();
    const leaving = stackRef.current[stackRef.current.length - 1];
    direction.current = "back";
    if (leaving.page === "item" || leaving.page === "note") flash(leaving.id);
    else if (leaving.page === "edit" && leaving.id) flash(leaving.id);
    else flash(null);
    // Forget the scroll position of the page we leave: it is gone from history.
    scrollPositions.current.delete(routeKey(leaving));
    setStack((current) => current.length > 1 ? current.slice(0, -1) : current);
    return true;
  }, [allow, saveScroll, flash]);

  const setGuard = useCallback((next: Guard | null) => { guard.current = next; }, []);

  const reset = useCallback(() => {
    guard.current = null;
    scrollPositions.current.clear();
    routeState.current.clear();
    direction.current = "root";
    flash(null);
    setStack([{ page: "home" }]);
  }, [flash]);

  const value = useMemo<RouterValue>(() => ({
    route: stack[stack.length - 1],
    stack,
    canGoBack: stack.length > 1,
    navigate, root, back, setGuard, highlight, direction, scrollPositions, scrollElement, routeState, reset
  }), [stack, navigate, root, back, setGuard, highlight, reset]);

  return <RouterContext.Provider value={value}>{children}</RouterContext.Provider>;
}

export function useRouter(): RouterValue {
  const context = useContext(RouterContext);
  if (!context) throw new Error("useRouter outside RouterProvider");
  return context;
}

/** State that survives leaving and returning to a route (filters, sort, tabs). */
export function useRouteState<T>(name: string, initial: T): [T, (value: T) => void] {
  const { route, routeState } = useRouter();
  const key = `${routeKey(route)}:${name}`;
  const [value, setValue] = useState<T>(() => (routeState.current.has(key) ? routeState.current.get(key) as T : initial));
  const set = useCallback((next: T) => { routeState.current.set(key, next); setValue(next); }, [key, routeState]);
  return [value, set];
}
