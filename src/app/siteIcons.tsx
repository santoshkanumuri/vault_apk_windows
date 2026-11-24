import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, onSiteIconsChanged, type SiteIconsState } from "../lib/api";
import { brandKey, buildBrandDomains, buildBuiltinMap, findIcon, type BuiltinIcon, type SiteIconData } from "../lib/siteIcons";
import { useVault } from "./vault";

/** What to draw instead of a letter. */
export type SiteIcon = { kind: "captured"; src: string } | { kind: "builtin"; title: string; hex: string; path: string };

type SiteIconsContextValue = {
  enabled: boolean;
  captured: ReadonlyMap<string, string> | null;
  builtin: ReadonlyMap<string, BuiltinIcon> | null;
  /** Brand name -> domain, for codes, which have an issuer name but no website. */
  brands: ReadonlyMap<string, string> | null;
  /** Save the setting and the icon list that the app returns. */
  apply: (state: SiteIconsState) => void;
};

const SiteIconsContext = createContext<SiteIconsContextValue | null>(null);

/**
 * Holds the "Website icons" setting, the icons the extension saved, and the built-in icons.
 * The built-in JSON (about 1 MB) is its own chunk. It loads once, after unlock, and never when the setting is off.
 */
export function SiteIconsProvider({ children }: { children: ReactNode }) {
  const { unlocked } = useVault();
  const [enabled, setEnabled] = useState(true);
  const [captured, setCaptured] = useState<ReadonlyMap<string, string> | null>(null);
  const [builtin, setBuiltin] = useState<ReadonlyMap<string, BuiltinIcon> | null>(null);
  const [brands, setBrands] = useState<ReadonlyMap<string, string> | null>(null);

  const apply = useMemo(() => (state: SiteIconsState) => {
    setEnabled(state.enabled);
    setCaptured(new Map(Object.entries(state.icons)));
  }, []);

  useEffect(() => {
    if (!unlocked) { setCaptured(null); return; }
    let live = true;
    const refresh = () => { api.siteIcons().then((state) => { if (live) apply(state); }).catch(() => {}); };
    refresh();
    const stop = onSiteIconsChanged(refresh);
    return () => { live = false; stop(); };
  }, [unlocked, apply]);

  const wantBuiltin = unlocked && enabled;
  useEffect(() => {
    if (!wantBuiltin || builtin) return;
    let live = true;
    import("../lib/site-icons.json").then((module) => {
      if (!live) return;
      const data = module.default as unknown as SiteIconData;
      setBuiltin(buildBuiltinMap(data));
      setBrands(buildBrandDomains(data));
    }).catch(() => {});
    return () => { live = false; };
  }, [wantBuiltin, builtin]);

  const value = useMemo<SiteIconsContextValue>(() => ({ enabled, captured, builtin, brands, apply }), [enabled, captured, builtin, brands, apply]);
  return <SiteIconsContext.Provider value={value}>{children}</SiteIconsContext.Provider>;
}

function useSiteIconsContext() {
  const context = useContext(SiteIconsContext);
  if (!context) throw new Error("useSiteIcons outside SiteIconsProvider");
  return context;
}

/** Settings page: the current switch and a way to change the state. */
export function useSiteIconsSetting() {
  const { enabled, apply } = useSiteIconsContext();
  return { enabled, apply };
}

/**
 * The icon for a login's website or a passkey's RP ID: a saved one first, then a built-in one.
 * Then, for a code, its issuer name ([brand]) as a built-in brand ("GitHub"). Else null (show the letter).
 */
export function useSiteIcon(site?: string, brand?: string): SiteIcon | null {
  const { enabled, captured, builtin, brands } = useSiteIconsContext();
  return useMemo(() => {
    if (!enabled || (!site && !brand)) return null;
    const lookup = (value: string): SiteIcon | null => {
      const saved = findIcon(captured, value);
      if (saved) return { kind: "captured", src: saved };
      const icon = findIcon(builtin, value);
      return icon ? { kind: "builtin", ...icon } : null;
    };
    const bySite = site ? lookup(site) : null;
    if (bySite) return bySite;
    const domain = brand ? brands?.get(brandKey(brand)) : undefined;
    return domain ? lookup(domain) : null;
  }, [enabled, site, brand, captured, builtin, brands]);
}
