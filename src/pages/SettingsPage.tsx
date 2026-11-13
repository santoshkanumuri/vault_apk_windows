import { useEffect, useState, type FormEvent } from "react";
import { Activity, Clipboard, ExternalLink, Info, KeyRound, MonitorSmartphone, LockKeyhole, LogOut, Monitor, Moon, Package, Palette, Puzzle, RotateCcw, ShieldCheck, Sun, Timer, Unplug, PlugZap } from "lucide-react";
import { Button } from "../components/Button";
import { SettingsGroup, SettingsRow } from "../components/Display";
import { Dialog } from "../components/Dialog";
import { PasswordField, Segmented, TextField, Toggle } from "../components/Field";
import { StatusBanner, StatusChip, type StatusKind } from "../components/Status";
import { useConfirm } from "../app/confirm";
import { useBrowserStatus, useBuildStatus, useLock, useMembership, useSyncStatus } from "../app/hooks";
import { PendingLeaveChip, useLeaveGroup } from "./sync/Membership";
import { useRouter } from "../app/router";
import { autoLockChoices, clipboardChoices, usePreferences } from "../app/settings";
import { useTheme, type ThemePreference } from "../app/theme";
import { useToast } from "../app/toast";
import { useVault } from "../app/vault";
import { api, type BrowserStatus, type BuildStatus, type PasskeyProviderState } from "../lib/api";
import { humanError } from "../lib/errors";
import { relativeTime } from "../lib/format";
import { browserIndicator, syncIndicator } from "../lib/syncState";


export function SettingsPage({ section }: { section?: string }) {
  const { preference, setPreference } = useTheme();
  const { autoLockMinutes, setAutoLockMinutes, clipboardSeconds, setClipboardSeconds } = usePreferences();
  const { snapshot } = useVault();
  const router = useRouter();
  const toast = useToast();
  const lock = useLock();
  const sync = useSyncStatus(10000);
  const phone = syncIndicator(snapshot, sync.data, Boolean(sync.error));
  const build = useBuildStatus(4000).data;

  useEffect(() => {
    if (!section) return;
    const timer = window.setTimeout(() => document.getElementById(`settings-${section}`)?.scrollIntoView({ block: "start" }), 50);
    return () => window.clearTimeout(timer);
  }, [section]);

  const changeTheme = (value: ThemePreference) => {
    setPreference(value);
    toast.success(value === "system" ? "Theme follows Windows" : `${value === "dark" ? "Dark" : "Light"} theme on`);
  };

  return (
    <div className="page page-narrow settings">
      <SettingsGroup title="Security" id="settings-security">
        <SettingsRow icon={LockKeyhole} title="Lock now" description="Shortcut: Ctrl+L" control={<Button size="sm" icon={LockKeyhole} onClick={() => void lock()}>Lock</Button>} />
        <HelloRow />
        {build && <PasskeyProviderRow state={build.passkeyProvider} />}
        <SettingsRow icon={Timer} title="Auto-lock" description="Lock after this long without mouse or keyboard activity."
          control={<select className="input select select-compact" aria-label="Auto-lock" value={autoLockMinutes} onChange={(event) => { const value = Number(event.target.value); setAutoLockMinutes(value); toast.success(value ? `Auto-lock after ${value} min` : "Auto-lock off"); }}>
            {autoLockChoices.map((value) => <option key={value} value={value}>{value === 0 ? "Never" : `${value} min`}</option>)}
          </select>} />
        <SettingsRow icon={Clipboard} title="Clear copied secrets"
          description={clipboardSeconds ? `Clear the clipboard ${clipboardSeconds}s after copying a password, code, or card number, while Nuvori is open.` : "Copied secrets stay on the clipboard until you copy something else."}
          control={<select className="input select select-compact" aria-label="Clear copied secrets" value={clipboardSeconds} onChange={(event) => { const value = Number(event.target.value); setClipboardSeconds(value); toast.success(value ? `Clipboard clears after ${value}s while Nuvori is open` : "Clipboard clearing off"); }}>
            {clipboardChoices.map((value) => <option key={value} value={value}>{value === 0 ? "Never" : `${value} s`}</option>)}
          </select>} />
      </SettingsGroup>

      <BrowserSection />

      <SettingsGroup title="Sync" id="settings-devices">
        <SettingsRow icon={MonitorSmartphone} title="Devices & sync" description={<span className="row-inline"><StatusChip kind={phone.kind} label={phone.label} />{sync.data?.lastSync ? <span className="muted">Last sync {relativeTime(sync.data.lastSync).toLowerCase()}</span> : null}</span>} onClick={() => void router.navigate({ page: "sync" })} />
      </SettingsGroup>

      <SettingsGroup title="App" id="settings-appearance">
        <SettingsRow icon={Palette} title="Theme" description="Follow Windows, or pick light or dark."
          control={<Segmented label="Theme" size="sm" value={preference} onChange={changeTheme} options={[{ value: "system", label: "System", icon: Monitor }, { value: "light", label: "Light", icon: Sun }, { value: "dark", label: "Dark", icon: Moon }]} />} />
        <SettingsRow icon={Activity} title="Activity log" description="Recent unlocks, saves, syncs, and browser fills." onClick={() => void router.navigate({ page: "activity" })} />
      </SettingsGroup>

      <SettingsGroup title="About" id="settings-about">
        <SettingsRow icon={Info} title="Nuvori for Windows" description={build ? `Version ${build.version} · ${build.storeBuild ? "Microsoft Store build" : "Installer build"}` : "Nuvori for Windows"} />
        {build?.storeBuild && build.installerBuildInstalled && <InstallerBuildRow />}
        <div className="about-text">
          <p>Your vault is encrypted with a key derived from your master password and stays on this PC. Your phone keeps its own copy; changes travel directly over your Wi-Fi after you pair with a confirmed code.</p>
          <p>The browser extension never sees your master password or the full vault. It gets one login at a time, only after you choose it.</p>
        </div>
      </SettingsGroup>

      <DangerZone />
    </div>
  );
}

function HelloRow() {
  const { snapshot, setSnapshot } = useVault();
  const toast = useToast();
  const [available, setAvailable] = useState<boolean | null>(null);
  const [dialog, setDialog] = useState(false);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => { api.helloAvailable().then(setAvailable).catch(() => setAvailable(false)); }, []);

  const disable = async () => {
    setBusy(true);
    try {
      setSnapshot(await api.disableHello());
      toast.success("Windows Hello unlock off");
    } catch (failure) {
      toast.error(failure, "Couldn't turn off Windows Hello.");
    } finally {
      setBusy(false);
    }
  };

  const enable = async (event: FormEvent) => {
    event.preventDefault();
    if (!password) { setError("Enter your master password."); return; }
    setBusy(true); setError("");
    try {
      const next = await api.enableHello(password);
      setPassword("");
      setDialog(false);
      setSnapshot(next);
      toast.success("Windows Hello is ready for your next unlock");
    } catch (failure) {
      setPassword("");
      setError(humanError(failure, "Windows Hello couldn't be set up."));
    } finally {
      setBusy(false);
    }
  };

  const description = available === false && !snapshot.helloEnabled ? "Set up a PIN, face, or fingerprint in Windows Settings first." : "Unlock with your PIN, face, or fingerprint. Your master password still works.";

  return (
    <>
      <SettingsRow icon={ShieldCheck} title="Windows Hello" description={description}
        control={<Toggle label="Windows Hello" checked={snapshot.helloEnabled} disabled={busy || (!snapshot.helloEnabled && !available)} onChange={(on) => { if (on) { setError(""); setDialog(true); } else void disable(); }} />} />
      <Dialog open={dialog} onClose={() => { setDialog(false); setPassword(""); }} title="Turn on Windows Hello" locked={busy}
        description="Confirm your master password. Windows will then ask for your PIN, face, or fingerprint."
        footer={<>
          <Button variant="ghost" onClick={() => { setDialog(false); setPassword(""); }} disabled={busy}>Cancel</Button>
          <Button variant="primary" type="submit" form="hello-form" busy={busy}>Turn on</Button>
        </>}>
        <form id="hello-form" className="form-stack" onSubmit={(event) => void enable(event)}>
          {error && <StatusBanner kind="error">{error}</StatusBanner>}
          <PasswordField label="Master password" value={password} onValue={setPassword} autoComplete="current-password" capsLockWarning disabled={busy} data-autofocus />
        </form>
      </Dialog>
    </>
  );
}

const PROVIDER_TEXT: Record<PasskeyProviderState, { description: string; chip?: [StatusKind, string] }> = {
  on: { description: "Windows offers your Nuvori passkeys in every browser and app on this PC.", chip: ["success", "On"] },
  off: { description: "Turn on Nuvori under Passkey managers in Windows Settings. Windows asks for this once." },
  notRegistered: { description: "Windows didn't accept Nuvori as a passkey manager. Restart Nuvori, or see the activity log.", chip: ["error", "Not available"] },
  unsupported: { description: "This version of Windows can't use passkey managers. Update Windows 11 to use your passkeys here.", chip: ["neutral", "Not available"] },
  installerBuild: { description: "Signing in with passkeys on this PC needs the Microsoft Store build of Nuvori. Your passkeys still sync.", chip: ["neutral", "Store build only"] },
};

function PasskeyProviderRow({ state }: { state: PasskeyProviderState }) {
  const toast = useToast();
  const text = PROVIDER_TEXT[state];
  const open = async () => {
    try {
      await api.openWindowsSettings("passkeys");
      toast.info("Turn on Nuvori under Passkey managers, then come back here.");
    } catch (failure) {
      toast.error(failure, "Couldn't open Windows Settings.");
    }
  };
  const control = state === "off"
    ? <Button size="sm" icon={ExternalLink} onClick={() => void open()}>Turn on</Button>
    : text.chip && <StatusChip kind={text.chip[0]} label={text.chip[1]} />;
  return <SettingsRow icon={KeyRound} title="Passkeys in Windows" description={text.description} control={control || undefined} />;
}

/** Store build only: the MSI or setup EXE build is installed too. */
function InstallerBuildRow() {
  const toast = useToast();
  const open = async () => {
    try {
      await api.openWindowsSettings("apps");
    } catch (failure) {
      toast.error(failure, "Couldn't open Windows Settings.");
    }
  };
  return (
    <SettingsRow icon={Package} title="Installer build also installed"
      description="Starting it opens this Store build, so you can keep it or uninstall it. In Installed apps, the Store build shows a four-part version such as 2.1.9.0. Your vault stays either way."
      control={<Button size="sm" variant="ghost" icon={ExternalLink} onClick={() => void open()}>Installed apps</Button>} />
  );
}

const BROWSER_NAMES: Record<string, string> = { chrome: "Chrome", edge: "Edge", brave: "Brave" };

function BrowserSection() {
  const { snapshot } = useVault();
  const toast = useToast();
  const [connecting, setConnecting] = useState(false);
  const browser = useBrowserStatus(4000);
  const status: BrowserStatus | null = browser.data;
  const indicator = browserIndicator(snapshot, status, Boolean(browser.error));
  const hosts: Array<[keyof BrowserStatus["hosts"], string]> = [["chrome", "Chrome"], ["edge", "Edge"], ["brave", "Brave"]];
  const connect = async () => {
    setConnecting(true);
    try {
      const report = await api.connectBrowsers();
      const names = report.browsers.map((name) => BROWSER_NAMES[name] ?? name).join(", ");
      if (!report.browsers.length) toast.info("No Chrome, Edge or Brave was found on this PC.");
      else if (report.changed) toast.success(`Connected ${names}. Restart the browser to use the extension.`);
      else toast.success(`${names} already connected.`);
      await browser.reload?.();
    } catch (failure) {
      toast.error(failure, "Couldn't connect the browsers.");
    } finally {
      setConnecting(false);
    }
  };

  return (
    <SettingsGroup title="Browser extension" id="settings-browser">
      <SettingsRow icon={Puzzle} title="Connection" description={browser.error ? "Status is unavailable in this version." : status?.listening ? "Nuvori is listening for the extension." : "Nuvori isn't listening for the extension."}
        control={<StatusChip kind={indicator.kind} label={indicator.label} />} />
      <SettingsRow icon={PlugZap} title="Connect browsers" description="Lets the Nuvori extension in Chrome, Edge and Brave reach this app. Nuvori does this by itself when it starts."
        control={<Button size="sm" busy={connecting} onClick={() => void connect()}>Connect</Button>} />
      {status && (
        <div className="settings-detail">
          <div className="chip-row" aria-label="Registered browsers">
            {hosts.map(([key, label]) => <StatusChip key={key} kind={status.hosts[key] ? "success" : "neutral"} label={`${label}${status.hosts[key] ? "" : " · not set up"}`} />)}
          </div>
          <dl className="facts">
            <div><dt>Last contact</dt><dd>{status.lastRequestAt ? relativeTime(status.lastRequestAt) : "Never"}</dd></div>
            {status.lastAction && <div><dt>Last action</dt><dd>{status.lastAction}</dd></div>}
            <div><dt>Requests since unlock</dt><dd>{status.requestsSinceUnlock}</dd></div>
          </dl>
        </div>
      )}
      <details className="settings-detail guide">
        <summary>Set up the extension</summary>
        <ol className="how-list">
          <li>Install <strong>Nuvori Password Fill</strong> from the Chrome Web Store. In Edge, first allow extensions from other stores. You can also choose <strong>Load unpacked</strong> on the extensions page and pick the <code>extension</code> folder.</li>
          <li>Nuvori connects the browsers when it starts. If a browser above shows <strong>not set up</strong>, choose <strong>Connect</strong>.</li>
          <li>Restart the browser. Keep Nuvori open and unlocked, then use the extension on a sign-in page.</li>
        </ol>
      </details>
    </SettingsGroup>
  );
}

export function DangerZone({ resetOnly, stopOnly }: { resetOnly?: boolean; stopOnly?: boolean } = {}) {
  const { snapshot, setSnapshot } = useVault();
  const router = useRouter();
  const toast = useToast();
  const confirm = useConfirm();
  const [busy, setBusy] = useState(false);
  const [resetOpen, setResetOpen] = useState(false);
  const [password, setPassword] = useState("");
  const [typed, setTyped] = useState("");
  const [error, setError] = useState("");
  const membership = useMembership();
  const leave = useLeaveGroup(membership.data?.managerName);

  const closeReset = () => { setResetOpen(false); setPassword(""); setTyped(""); setError(""); };

  const reset = async (event: FormEvent) => {
    event.preventDefault();
    if (typed !== "RESET") { setError("Type RESET exactly to confirm."); return; }
    if (!password) { setError("Enter your master password."); return; }
    setBusy(true); setError("");
    try {
      const next = await api.resetVault(password);
      closeReset();
      router.reset();
      setSnapshot(next);
      toast.success("This PC's vault was deleted");
    } catch (failure) {
      setPassword("");
      setError(humanError(failure, "Couldn't reset the vault."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <SettingsGroup title="Danger zone" id={stopOnly ? undefined : "settings-danger"}>
      {snapshot.enrolled && !resetOnly && <SettingsRow icon={Unplug} title="Leave group" description="Stop syncing. Keep this PC's items or start with an empty vault." danger control={<Button size="sm" variant="ghost" className="btn-danger-text" onClick={() => void leave.run(() => membership.reload())} busy={leave.busy}>Leave group</Button>} />}
      {!snapshot.enrolled && !resetOnly && membership.data?.pendingLeave && <SettingsRow icon={Unplug} title="Left the sync group" description="Your phone is told the next time this PC reaches it." control={<PendingLeaveChip membership={membership.data} />} />}
      {!stopOnly && <SettingsRow icon={RotateCcw} title="Reset this PC's vault" description="Delete this PC's vault, items, photos, and device identity. Other devices keep their copies." danger
        control={<Button size="sm" variant="danger" onClick={() => setResetOpen(true)}>Reset</Button>} />}
      <Dialog open={resetOpen} onClose={closeReset} title="Reset this PC's vault?" locked={busy} size="sm"
        description="This can't be undone on this PC. Your phone and other paired devices keep their copies."
        footer={<>
          <Button variant="ghost" onClick={closeReset} disabled={busy}>Cancel</Button>
          <Button variant="danger" type="submit" form="reset-form" icon={LogOut} busy={busy} disabled={typed !== "RESET" || !password}>Delete this PC's vault</Button>
        </>}>
        <form id="reset-form" className="form-stack" onSubmit={(event) => void reset(event)}>
          {error && <StatusBanner kind="error">{error}</StatusBanner>}
          <PasswordField label="Master password" value={password} onValue={setPassword} autoComplete="current-password" disabled={busy} data-autofocus />
          <TextField label="Type RESET to confirm" value={typed} onValue={setTyped} autoComplete="off" spellCheck={false} disabled={busy} />
        </form>
      </Dialog>
      {leave.dialog}
    </SettingsGroup>
  );
}
