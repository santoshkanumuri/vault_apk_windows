import { useEffect, useMemo, useState, type KeyboardEvent } from "react";
import { KeyRound, LogIn, Pencil, SearchX, Trash2 } from "lucide-react";
import { Button, IconButton } from "../../components/Button";
import { Avatar, EmptyState, SettingsRow } from "../../components/Display";
import { Dialog } from "../../components/Dialog";
import { TextField, Toggle } from "../../components/Field";
import { Spinner } from "../../components/Spinner";
import { StatusBanner } from "../../components/Status";
import { useConfirm } from "../../app/confirm";
import { useNow } from "../../app/hooks";
import { useRouteState, useRouter } from "../../app/router";
import { useToast } from "../../app/toast";
import { useVault } from "../../app/vault";
import { api, onSignInsChanged, type SignIn, type SignInsState } from "../../lib/api";
import { cx, formatDateTime, plural, relativeTime } from "../../lib/format";
import { accountProblem, accountsOf, forLogin, groupBySite, providerName, providersOf } from "../../lib/signIns";
import { FilterInput } from "../items/Toolbar";
import marks from "../../lib/sign-in-marks.json";
import "./signins.css";

type Mark = { title: string; hex: string; path?: string; letter?: string };
const MARKS = marks.marks as Record<string, Mark>;

function luminance(hex: string): number {
  const channel = (offset: number) => {
    const value = parseInt(hex.slice(offset, offset + 2), 16) / 255;
    return value <= 0.03928 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  };
  return 0.2126 * channel(0) + 0.7152 * channel(2) + 0.0722 * channel(4);
}

/** The provider's mark (Simple Icons, CC0) or its letter, in its brand color. It only names the sign-in method. */
export function ProviderMark({ provider, size = 28 }: { provider: string; size?: number }) {
  const mark = MARKS[provider];
  const hex = mark?.hex ?? "737373";
  const ink = luminance(hex) < 0.4 ? "#FFFFFF" : "#111111";
  return (
    <span className={cx("provider-mark", luminance(hex) < 0.02 && "is-dark")} style={{ width: size, height: size, background: `#${hex}`, color: ink, fontSize: Math.round(size * 0.48) }} aria-hidden="true">
      {mark?.path ? <svg viewBox="0 0 24 24" width={Math.round(size * 0.6)} height={Math.round(size * 0.6)} focusable="false"><path d={mark.path} fill={ink} /></svg> : (mark?.letter ?? providerName(provider).slice(0, 1))}
    </span>
  );
}

/** Loads the list and reloads it when the extension remembers a new sign-in. */
export function useSignIns() {
  const [state, setState] = useState<SignInsState | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const reload = useMemo(() => async () => {
    setLoading(true);
    try { setState(await api.signIns()); setError(null); } catch (failure) { setError(failure); } finally { setLoading(false); }
  }, []);
  useEffect(() => {
    void reload();
    return onSignInsChanged(() => void reload());
  }, [reload]);
  return { state, setState, error, loading, reload };
}

const NO_ACCOUNT = "\u0000none";

/**
 * Sign-ins: which "Continue with <provider>" and which account the user used on each site, as the
 * browser extension remembered them (with the user's OK). Grouped by site (registrable domain), with
 * provider chips, an account filter and a site search that matches any page of a site.
 */
export function SignInsPage() {
  const router = useRouter();
  const toast = useToast();
  const confirm = useConfirm();
  const { entries } = useVault();
  const now = useNow(60_000);
  const { state, setState, error, loading, reload } = useSignIns();
  const [query, setQuery] = useRouteState("query", "");
  const [provider, setProvider] = useRouteState("provider", "");
  const [account, setAccount] = useRouteState("account", "");
  const [editing, setEditing] = useState<SignIn | null>(null);
  const [busy, setBusy] = useState(false);

  const items = state?.items ?? [];
  const groups = useMemo(() => groupBySite(items, { provider, account, query }), [items, provider, account, query]);
  const providers = providersOf(items);
  const accounts = accountsOf(items);
  const counts = useMemo(() => new Map(providers.map((id) => [id, items.filter((item) => item.provider === id).length])), [items, providers]);
  const unknownAccounts = items.some((item) => !item.account);
  const filtered = Boolean(query || provider || account);

  const apply = async (task: () => Promise<SignInsState>, done?: string, failed = "Couldn't change the sign-in method.") => {
    setBusy(true);
    try { setState(await task()); if (done) toast.success(done); return true; } catch (failure) { toast.error(failure, failed); return false; } finally { setBusy(false); }
  };

  const remove = async (item: SignIn) => {
    const who = item.account ? ` (${item.account})` : "";
    if (!(await confirm({ title: `Forget ${providerName(item.provider)}${who} on ${item.site}?`, message: "Nuvori stops reminding you about it. The site and your account there are not changed.", confirmLabel: "Forget", danger: true }))) return;
    await apply(() => api.deleteSignIn(item.id), "Sign-in method forgotten", "Couldn't forget this sign-in method.");
  };

  const onChipKey = (event: KeyboardEvent<HTMLDivElement>) => {
    const keys = ["", ...providers];
    const index = keys.indexOf(provider);
    const next = event.key === "ArrowRight" || event.key === "ArrowDown" ? index + 1 : event.key === "ArrowLeft" || event.key === "ArrowUp" ? index - 1 : null;
    if (next === null) return;
    event.preventDefault();
    const value = keys[(next + keys.length) % keys.length];
    setProvider(value);
    // React clears currentTarget after the handler; keep the group for the next frame.
    const group = event.currentTarget;
    window.requestAnimationFrame(() => group.querySelector<HTMLButtonElement>(`[data-provider="${value || "all"}"]`)?.focus());
  };

  const loginTitle = (id: string) => entries.find((entry) => entry.id === id)?.title || "Login";

  return (
    <div className="page page-narrow signins-page">
      <p className="toolbar-text">When you sign in to a site with Google, Apple, GitHub or another account in your browser, the Nuvori extension asks to remember which one you used. It reminds you on that site's sign-in page.</p>
      {state && !state.enabled && (
        <StatusBanner kind="info" title="Remembering sign-in methods is off"
          action={<Button size="sm" busy={busy} onClick={() => void apply(() => api.setSignIns(true), "Sign-in methods on")}>Turn on</Button>}>
          The extension doesn't watch sign-ins or show reminders. The methods below stay until you forget them.
        </StatusBanner>
      )}
      {items.length > 0 && (
        <div className="toolbar signins-toolbar">
          <FilterInput value={query} onChange={setQuery} placeholder="Search by site" />
          <div className="toolbar-group">
            <label className="sr-only" htmlFor="signin-account">Account</label>
            <select id="signin-account" className="input select select-compact" value={account} onChange={(event) => setAccount(event.target.value)}>
              <option value="">All accounts</option>
              {accounts.map((value) => <option key={value} value={value}>{value}</option>)}
              {unknownAccounts && <option value={NO_ACCOUNT}>Account not known</option>}
            </select>
          </div>
          {providers.length > 1 && (
            <div className="chip-filter" role="radiogroup" aria-label="Filter by sign-in provider" onKeyDown={onChipKey}>
              {["", ...providers].map((id) => (
                <button key={id || "all"} type="button" role="radio" data-provider={id || "all"} aria-checked={provider === id} tabIndex={provider === id ? 0 : -1}
                  className={cx("filter-chip", provider === id && "is-selected")} onClick={() => setProvider(id)}>
                  {id && <ProviderMark provider={id} size={18} />}
                  {id ? providerName(id) : "All"}
                  {id && <span className="filter-chip-count">{counts.get(id as (typeof providers)[number])}</span>}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {loading && !state ? <div className="card card-padded center"><Spinner label="Loading sign-in methods" /></div>
        : error && !state ? (
          <div className="card"><EmptyState icon={LogIn} title="Sign-in methods unavailable" body="Nuvori couldn't read them from your vault. Try again; if it keeps failing, restart Nuvori."
            action={<Button onClick={() => void reload()}>Try again</Button>} /></div>
        ) : items.length === 0 ? (
          <div className="card"><EmptyState icon={LogIn} title="No sign-in methods yet"
            body="Sign in to a site with “Continue with Google”, GitHub, Microsoft, Apple or another provider, and choose Save when the extension asks. Nuvori then shows which one, and which account, you used." /></div>
        ) : groups.length === 0 ? (
          <div className="card"><EmptyState icon={SearchX} title="No matches" body="Try another site, or clear the filters."
            action={filtered ? <Button onClick={() => { setQuery(""); setProvider(""); setAccount(""); }}>Clear filters</Button> : undefined} /></div>
        ) : (
          <>
            <p className="list-count">{plural(groups.length, "site")} · {plural(groups.reduce((sum, group) => sum + group.methods.length, 0), "sign-in method")}</p>
            <ul className="signin-groups" aria-label="Sign-in methods by site">
              {groups.map((group) => {
                const logins = state?.logins[group.site] ?? [];
                return (
                  <li key={group.site} className="card signin-site">
                    <div className="signin-site-head">
                      <Avatar title={group.site} site={group.site} size="sm" />
                      <h2 className="signin-site-name">{group.site}</h2>
                      {logins.length > 0 && (
                        <span className="signin-logins">
                          {logins.slice(0, 2).map((id) => (
                            <Button key={id} size="sm" variant="ghost" icon={KeyRound} onClick={() => void router.navigate({ page: "item", id })}>{loginTitle(id)}</Button>
                          ))}
                          {logins.length > 2 && <span className="muted">+{logins.length - 2}</span>}
                        </span>
                      )}
                    </div>
                    <ul className="signin-methods" aria-label={`Sign-in methods for ${group.site}`}>
                      {group.methods.map((item) => (
                        <li key={item.id} className="signin-method">
                          <ProviderMark provider={item.provider} size={30} />
                          <span className="signin-text">
                            <span className="signin-title">{providerName(item.provider)}{item.account ? <span className="signin-account"> · {item.account}</span> : <span className="signin-unknown"> · account not known</span>}</span>
                            <span className="signin-meta">
                              Last used <time dateTime={new Date(item.lastUsedAt).toISOString()} title={formatDateTime(item.lastUsedAt)}>{relativeTime(item.lastUsedAt, now).replace(/^Just/, "just").replace(/^Yesterday/, "yesterday")}</time>
                              {" · "}{plural(item.useCount, "time")}
                            </span>
                          </span>
                          <span className="signin-actions">
                            <IconButton label={item.account ? `Edit account for ${providerName(item.provider)} on ${group.site}` : `Add account for ${providerName(item.provider)} on ${group.site}`} icon={Pencil} onClick={() => setEditing(item)} disabled={busy} />
                            <IconButton label={`Forget ${providerName(item.provider)} on ${group.site}`} icon={Trash2} className="btn-danger-text" onClick={() => void remove(item)} disabled={busy} />
                          </span>
                        </li>
                      ))}
                    </ul>
                  </li>
                );
              })}
            </ul>
          </>
        )}
      <p className="detail-meta">Kept in your encrypted vault on this PC. Nuvori never stores a password, token or code from these sign-ins. Provider logos only show which sign-in you used.</p>
      <AccountDialog item={editing} busy={busy} onClose={() => setEditing(null)}
        onSave={async (value) => { if (editing && (await apply(() => api.editSignIn(editing.id, value), "Account saved", "Couldn't save the account."))) setEditing(null); }} />
    </div>
  );
}

function AccountDialog({ item, busy, onClose, onSave }: { item: SignIn | null; busy: boolean; onClose: () => void; onSave: (account: string) => Promise<void> }) {
  const [value, setValue] = useState("");
  useEffect(() => { if (item) setValue(item.account); }, [item]);
  const problem = accountProblem(value);
  return (
    <Dialog open={item !== null} title={item?.account ? "Edit account" : "Add account"} description={item ? `${providerName(item.provider)} on ${item.site}` : undefined} onClose={onClose}
      footer={<>
        <Button variant="ghost" onClick={onClose}>Cancel</Button>
        <Button variant="primary" busy={busy} disabled={problem !== null} onClick={() => void onSave(value)}>Save</Button>
      </>}>
      <form onSubmit={(event) => { event.preventDefault(); if (!problem) void onSave(value); }}>
        <TextField label="Account" value={value} onValue={setValue} maxLength={256} autoComplete="off" spellCheck={false} error={problem ?? undefined}
          hint="The email address or user name you use with this provider. Leave it empty if you don't know." autoFocus />
      </form>
    </Dialog>
  );
}

/** A login's detail page: the sign-in methods remembered for its site. Nothing when there are none. */
export function LoginSignIns({ loginId }: { loginId: string }) {
  const router = useRouter();
  const { state } = useSignIns();
  const methods = forLogin(state, loginId);
  if (!methods.length) return null;
  return (
    <section className="card card-padded login-signins" aria-labelledby={`signins-${loginId}`}>
      <h2 id={`signins-${loginId}`} className="login-signins-title">Also signs in with</h2>
      <ul className="signin-methods">
        {methods.slice(0, 4).map((item) => (
          <li key={item.id} className="signin-method is-compact">
            <ProviderMark provider={item.provider} size={24} />
            <span className="signin-text">
              <span className="signin-title">{providerName(item.provider)}{item.account ? <span className="signin-account"> · {item.account}</span> : null}</span>
              <span className="signin-meta">Last used {relativeTime(item.lastUsedAt).toLowerCase()}</span>
            </span>
          </li>
        ))}
      </ul>
      <Button size="sm" variant="ghost" icon={LogIn} onClick={() => void router.navigate({ page: "signins" })}>All sign-in methods</Button>
    </section>
  );
}

/** Settings: the switch next to Website icons. */
export function SignInsSettingRow() {
  const toast = useToast();
  const { state, setState } = useSignIns();
  const [busy, setBusy] = useState(false);
  if (!state) return null;
  const change = async (enabled: boolean) => {
    setBusy(true);
    try { setState(await api.setSignIns(enabled)); toast.success(enabled ? "Sign-in methods on" : "Sign-in methods off"); }
    catch (failure) { toast.error(failure, "Couldn't change the setting."); }
    finally { setBusy(false); }
  };
  return (
    <SettingsRow icon={LogIn} title="Remember sign-in methods"
      description={state.enabled
        ? "The extension asks to remember when you use “Continue with Google”, GitHub or another provider, and reminds you on that site next time. Never in private windows."
        : "Off. The extension doesn't watch sign-ins or show reminders. Remembered methods stay until you forget them."}
      control={<Toggle label="Remember sign-in methods" checked={state.enabled} disabled={busy} onChange={(value) => void change(value)} />} />
  );
}
