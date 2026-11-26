import { useEffect, useState, type FormEvent } from "react";
import { Activity, ArchiveRestore, Clipboard, CornerDownLeft, Globe, FileKey, FileUp, Keyboard, ExternalLink, Info, KeyRound, MonitorSmartphone, LockKeyhole, LogOut, Monitor, Moon, Package, Palette, Puzzle, RotateCcw, ShieldCheck, Sun, Timer, Unplug, PlugZap } from "lucide-react";
import { KeepassImportDialog } from "./KeepassImport";
import { PasswordImportDialog } from "./PasswordImport";
import { codeText, passwordImportText } from "../strings";
import { Button } from "../components/Button";
import { Kbd, SettingsGroup, SettingsRow } from "../components/Display";
import { Dialog } from "../components/Dialog";
import { CloudUpload, DatabaseBackup } from "lucide-react";
import { driveBackupText } from "../strings";
import { PasswordField, Segmented, TextField, Toggle } from "../components/Field";
import { StatusBanner, StatusChip, type StatusKind } from "../components/Status";
import { useConfirm } from "../app/confirm";
import { useBrowserStatus, useBuildStatus, useCloudStatus, useLastSync, useLock, useMembership, useSyncStatus } from "../app/hooks";
import { PendingLeaveChip, useLeaveGroup } from "./sync/Membership";
import { DuplicatePasswordsSection } from "./DuplicatePasswords";
import { useRouter } from "../app/router";
import { autoLockChoices, clipboardChoices, usePreferences } from "../app/settings";
import { AccentPicker, AppearancePreview, SurfacePicker } from "../components/AppearancePicker";
import { capInterval, confirmsFirst, DAY_MS, WEEK_MS } from "../lib/helloWindow";
import { DEFAULT_ACCENT, DEFAULT_SURFACE, useTheme, type ThemePreference } from "../app/theme";
import { useToast } from "../app/toast";
import { useSiteIconsSetting } from "../app/siteIcons";
import { SignInsSettingRow } from "./signins/SignInsPage";
import { AuthenticatorImportRow } from "./AuthenticatorImport";
import { useVault } from "../app/vault";
import { api, type Browser, type BrowserFamily, type BrowserStatus, type BuildStatus, type PasskeyProviderState, type AutoTypeStatus, type QuickSearchStatus } from "../lib/api";
import { humanError } from "../lib/errors";
import { cx, relativeTime } from "../lib/format";
import { managerLabel } from "../lib/deviceList";
import { browserIndicator, syncIndicator } from "../lib/syncState";
import { accountText, strings } from "../strings";
import { passwordStrength } from "../lib/strength";


export function SettingsPage({ section }: { section?: string }) {
  const { preference, setPreference, resolved, accent, surface, pendingSync, setAppearance } = useTheme();
  const { autoLockMinutes, setAutoLockMinutes, clipboardSeconds, setClipboardSeconds } = usePreferences();
  const { snapshot } = useVault();
  const router = useRouter();
  const toast = useToast();
  const lock = useLock();
  const [keepass, setKeepass] = useState(false);
  const [passwordImport, setPasswordImport] = useState(false);
  const sync = useSyncStatus(10000);
  const lastSync = useLastSync(sync.data);
  const cloud = useCloudStatus();
  const phone = syncIndicator(snapshot, sync.data, Boolean(sync.error), lastSync, cloud.data);
  const build = useBuildStatus(4000).data;

  useEffect(() => {
    if (!section) return;
    const timer = window.setTimeout(() => document.getElementById(`settings-${section}`)?.scrollIntoView({ block: "start" }), 50);
    return () => window.clearTimeout(timer);
  }, [section]);

  const changeTheme = (value: ThemePreference) => {
    setPreference(value);
    toast.success(value === "system" ? codeText.themeFollowsWindows : `${value === "dark" ? "Dark" : "Light"} theme on`);
  };

  const changeAppearance = (nextAccent: string, nextSurface: string) => {
    setAppearance(nextAccent, nextSurface).catch((failure) => toast.error(failure, codeText.couldnTSaveTheColors));
  };

  return (
    <div className="page page-narrow settings">
      <SettingsGroup title={strings.security} id="settings-security">
        <SettingsRow icon={LockKeyhole} title={strings.lockNow} description={strings.shortcutCtrlL} control={<Button size="sm" icon={LockKeyhole} onClick={() => void lock()}>{strings.lock}</Button>} />
        <HelloRow />
        <ChangePasswordRow />
        <QuickSearchRow />
        <AutoTypeRow />
        {build && <PasskeyProviderRow state={build.passkeyProvider} />}
        <SettingsRow icon={Timer} title={strings.autoLock} description={strings.lockAfterThisLongWithoutMouse}
          control={<select className="input select select-compact" aria-label={strings.autoLock} value={autoLockMinutes} onChange={(event) => { const value = Number(event.target.value); setAutoLockMinutes(value); toast.success(value ? codeText.autoLockAfterMin(value) : codeText.autoLockOff); }}>
            {autoLockChoices.map((value) => <option key={value} value={value}>{value === 0 ? codeText.never : codeText.min(value)}</option>)}
          </select>} />
        <SettingsRow icon={Clipboard} title={strings.clearCopiedSecrets}
          description={clipboardSeconds ? codeText.clearTheClipboardSAfterCopying(clipboardSeconds) : codeText.copiedSecretsStayOnTheClipboard}
          control={<select className="input select select-compact" aria-label={strings.clearCopiedSecrets} value={clipboardSeconds} onChange={(event) => { const value = Number(event.target.value); setClipboardSeconds(value); toast.success(value ? codeText.clipboardClearsAfterSWhileNuvori(value) : codeText.clipboardClearingOff); }}>
            {clipboardChoices.map((value) => <option key={value} value={value}>{value === 0 ? codeText.never : `${value} s`}</option>)}
          </select>} />
      </SettingsGroup>

      <BrowserSection />

      <SettingsGroup title={strings.sync} id="settings-devices">
        <SettingsRow icon={MonitorSmartphone} title="Devices & sync" description={<span className="row-inline"><StatusChip kind={phone.kind} label={phone.label} />{lastSync ? <span className="muted">{codeText.lastSync(relativeTime(lastSync).toLowerCase())}</span> : null}</span>} onClick={() => void router.navigate({ page: "sync" })} />
      </SettingsGroup>

      <SettingsGroup title={strings.app} id="settings-appearance">
        <SettingsRow icon={Palette} title={strings.theme} description={strings.followWindowsOrPickLightOr}
          control={<Segmented label={strings.theme} size="sm" value={preference} onChange={changeTheme} options={[{ value: "system", label: codeText.system, icon: Monitor }, { value: "light", label: codeText.light, icon: Sun }, { value: "dark", label: codeText.dark, icon: Moon }]} />} />
        <div className="appearance-picker" id="settings-colors">
          <div>
            <div className="appearance-label">{strings.accentColor}</div>
            <AccentPicker value={accent} onSelect={(id) => changeAppearance(id, surface)} />
          </div>
          <div>
            <div className="appearance-label">{strings.background}</div>
            <SurfacePicker value={surface} accent={accent} mode={resolved} onSelect={(id) => changeAppearance(accent, id)} />
          </div>
          <AppearancePreview />
          {pendingSync && snapshot.enrolled && <p className="appearance-note">{strings.savedOnThisPcYourOther}</p>}
          {(accent !== DEFAULT_ACCENT || surface !== DEFAULT_SURFACE) && (
            <div className="appearance-actions"><Button size="sm" icon={RotateCcw} onClick={() => changeAppearance(DEFAULT_ACCENT, DEFAULT_SURFACE)}>{strings.resetToNuvoriGreen}</Button></div>
          )}
        </div>
        <SiteIconsRow />
        <SettingsRow icon={Activity} title={strings.activityLog} description={strings.recentUnlocksSavesSyncsAndBrowser} onClick={() => void router.navigate({ page: "activity" })} />
      </SettingsGroup>

      <SettingsGroup title={strings.yourData} id="settings-data">
        <SettingsRow icon={FileUp} title={passwordImportText.title} description={passwordImportText.row} onClick={() => setPasswordImport(true)} />
        <SettingsRow icon={FileKey} title={strings.importFromKeepass} description={strings.loginsCodesAndNotesFromA} onClick={() => setKeepass(true)} />
        <AuthenticatorImportRow />
        <SettingsRow icon={ArchiveRestore} title={strings.recentlyDeleted} description={strings.restoreItemsDeletedInTheLast2} onClick={() => void router.navigate({ page: "trash" })} />
        <BackupRow />
        <SettingsRow icon={CloudUpload} title={driveBackupText.cardTitle} description={driveBackupText.pageRow}
          onClick={() => void router.navigate({ page: "backups" })} />
      </SettingsGroup>
      <KeepassImportDialog open={keepass} onClose={() => setKeepass(false)} />
      <PasswordImportDialog open={passwordImport} onClose={() => setPasswordImport(false)} />

      <SettingsGroup title={strings.about} id="settings-about">
        <SettingsRow icon={Info} title={strings.nuvoriForWindows} description={build ? `Version ${build.version} · ${build.storeBuild ? "Microsoft Store build" : "Installer build"}` : strings.nuvoriForWindows} />
        {build?.storeBuild && build.installerBuildInstalled && <InstallerBuildRow />}
        <div className="about-text">
          <p>{strings.yourVaultIsEncryptedWithA}</p>
          <p>{strings.theBrowserExtensionNeverSeesYour}</p>
        </div>
      </SettingsGroup>

      <DuplicatePasswordsSection />

      <DangerZone />
    </div>
  );
}

/** The local date, "2026-11-05", for the backup's suggested file name. */
function localDate(now = new Date()) {
  const two = (value: number) => String(value).padStart(2, "0");
  return `${now.getFullYear()}-${two(now.getMonth() + 1)}-${two(now.getDate())}`;
}

/** Export encrypted backup (backup_export.rs): a .pvault file that Nuvori for Android restores. */
function BackupRow() {
  const toast = useToast();
  const [dialog, setDialog] = useState(false);
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const close = () => { setDialog(false); setPassword(""); setError(""); };

  const save = async (event: FormEvent) => {
    event.preventDefault();
    if (!password) { setError(driveBackupText.enterPassword); return; }
    setBusy(true); setError("");
    try {
      const saved = await api.exportBackup(password, localDate());
      setPassword("");
      if (!saved) return;
      setDialog(false);
      toast.success(codeText.backupSavedAs(saved.fileName));
    } catch (failure) {
      setPassword("");
      setError(humanError(failure, codeText.couldnTCreateTheBackup));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <SettingsRow icon={DatabaseBackup} title={strings.exportEncryptedBackup} description={strings.saveYourVaultToAPvault} onClick={() => { setError(""); setDialog(true); }} />
      <Dialog open={dialog} onClose={close} title={strings.protectBackup} locked={busy}
        description={strings.thisBackupWillAlwaysRequireThe}
        footer={<>
          <Button variant="ghost" onClick={close} disabled={busy}>{strings.cancel}</Button>
          <Button variant="primary" type="submit" form="backup-form" icon={DatabaseBackup} busy={busy}>{strings.saveBackup}</Button>
        </>}>
        <form id="backup-form" className="form-stack" onSubmit={(event) => void save(event)}>
          {error && <StatusBanner kind="error">{error}</StatusBanner>}
          <PasswordField label={strings.currentMasterPassword} value={password} onValue={setPassword} autoComplete="current-password" capsLockWarning disabled={busy} data-autofocus />
          <p className="field-hint">{strings.aCloudFolderMayUploadThe}</p>
        </form>
      </Dialog>
    </>
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
      toast.success(codeText.windowsHelloUnlockOff);
    } catch (failure) {
      toast.error(failure, codeText.couldnTTurnOffWindowsHello);
    } finally {
      setBusy(false);
    }
  };

  const enable = async (event: FormEvent) => {
    event.preventDefault();
    if (!password) { setError(driveBackupText.enterPassword); return; }
    setBusy(true); setError("");
    try {
      const next = await api.enableHello(password);
      setPassword("");
      setDialog(false);
      setSnapshot(next);
      toast.success(codeText.windowsHelloIsReadyForYour);
    } catch (failure) {
      setPassword("");
      setError(humanError(failure, codeText.windowsHelloCouldnTBeSet));
    } finally {
      setBusy(false);
    }
  };

  const description = available === false && !snapshot.helloEnabled ? codeText.setUpAPinFaceOr : codeText.unlockWithYourPinFaceOr;

  return (
    <>
      <SettingsRow icon={ShieldCheck} title={strings.windowsHello} description={description}
        control={<Toggle label={strings.windowsHello} checked={snapshot.helloEnabled} disabled={busy || (!snapshot.helloEnabled && !available)} onChange={(on) => { if (on) { setError(""); setDialog(true); } else void disable(); }} />} />
      {snapshot.helloEnabled && <MasterPasswordAgainRow />}
      <Dialog open={dialog} onClose={() => { setDialog(false); setPassword(""); }} title={strings.turnOnWindowsHello} locked={busy}
        description={strings.confirmYourMasterPasswordWindowsWill}
        footer={<>
          <Button variant="ghost" onClick={() => { setDialog(false); setPassword(""); }} disabled={busy}>{strings.cancel}</Button>
          <Button variant="primary" type="submit" form="hello-form" busy={busy}>{strings.turnOn}</Button>
        </>}>
        <form id="hello-form" className="form-stack" onSubmit={(event) => void enable(event)}>
          {error && <StatusBanner kind="error">{error}</StatusBanner>}
          <PasswordField label={strings.masterPassword} value={password} onValue={setPassword} autoComplete="current-password" capsLockWarning disabled={busy} data-autofocus />
        </form>
      </Dialog>
    </>
  );
}

/**
 * Change master password (Android Settings > Change master password). The vault stays unlocked:
 * only the key file changes (`change_master_password`). New passwords follow the create-vault rules.
 */
function ChangePasswordRow() {
  const { snapshot } = useVault();
  const membership = useMembership();
  const toast = useToast();
  const [open, setOpen] = useState(false);
  const [current, setCurrent] = useState("");
  const [replacement, setReplacement] = useState("");
  const [confirmation, setConfirmation] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const strength = passwordStrength(replacement);
  const strengthTone = ["error", "warning", "info", "success", "success"][strength.score];
  const mismatch = confirmation !== "" && confirmation !== replacement && confirmation.length >= replacement.length;

  const close = () => { if (busy) return; setOpen(false); setCurrent(""); setReplacement(""); setConfirmation(""); setError(""); };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!current) { setError(accountText.enterCurrent); return; }
    if (replacement.length < 12) { setError(accountText.tooShort); return; }
    if (replacement !== confirmation) { setError(accountText.passwordsDontMatch); return; }
    if (replacement === current) { setError(accountText.sameAsCurrent); return; }
    setBusy(true); setError("");
    try {
      await api.changeMasterPassword(current, replacement);
      setOpen(false); setCurrent(""); setReplacement(""); setConfirmation("");
      toast.success(accountText.changed);
    } catch (failure) {
      setCurrent("");
      setError(humanError(failure, accountText.failed));
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <SettingsRow icon={KeyRound} title={accountText.changeMasterPassword}
        description={snapshot.enrolled ? accountText.pairedChangeOnPhone(managerLabel(membership.data?.managerName)) : accountText.changeMasterPasswordRow}
        control={snapshot.enrolled ? undefined : <Button size="sm" onClick={() => setOpen(true)}>{accountText.changePassword}</Button>}>
        {snapshot.enrolled && <p className="settings-detail muted small">{accountText.pairedOrLeaveGroup}</p>}
      </SettingsRow>
      <Dialog open={open} onClose={close} title={accountText.changeMasterPassword} locked={busy}
        footer={<>
          <Button variant="ghost" onClick={close} disabled={busy}>{strings.cancel}</Button>
          <Button variant="primary" type="submit" form="change-password-form" busy={busy}
            disabled={!current || replacement.length < 12 || replacement !== confirmation}>{accountText.changePassword}</Button>
        </>}>
        <form id="change-password-form" className="form-stack" onSubmit={(event) => void submit(event)}>
          {error && <StatusBanner kind="error">{error}</StatusBanner>}
          {busy && <StatusBanner kind="info">{accountText.changing}</StatusBanner>}
          <PasswordField label={accountText.currentPassword} value={current} onValue={(value) => { setCurrent(value); setError(""); }}
            autoComplete="current-password" capsLockWarning disabled={busy} data-autofocus />
          <PasswordField label={accountText.newPassword} value={replacement} onValue={(value) => { setReplacement(value); setError(""); }}
            autoComplete="new-password" capsLockWarning disabled={busy} />
          {replacement && (
            <div className="strength" aria-live="polite">
              <div className={cx("strength-bar", `tone-${strengthTone}`)} data-score={strength.score}>
                {[0, 1, 2, 3].map((index) => <span key={index} className={cx(index < Math.max(1, strength.score) && "is-on")} />)}
              </div>
              <span className="strength-label">{strength.label}{strength.hint ? ` · ${strength.hint}` : ""}</span>
            </div>
          )}
          <PasswordField label={accountText.confirmNewPassword} value={confirmation} onValue={(value) => { setConfirmation(value); setError(""); }}
            autoComplete="new-password" disabled={busy} error={mismatch ? accountText.passwordsDontMatch : undefined} />
          <StatusBanner kind="warning">{accountText.cantReset}</StatusBanner>
          {snapshot.helloEnabled && <p className="muted">{accountText.hello}</p>}
        </form>
      </Dialog>
    </>
  );
}

/** Auto-type (auto_type.rs): off until turned on here. */
function AutoTypeRow() {
  const toast = useToast();
  const [status, setStatus] = useState<AutoTypeStatus | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { api.autoTypeStatus().then(setStatus).catch(() => setStatus(null)); }, []);
  if (!status) return null;

  const change = async (enabled: boolean, preset?: string, pressEnter?: boolean) => {
    setBusy(true);
    try {
      const next = await api.setAutoType(enabled, preset, pressEnter);
      setStatus(next);
      if (next.state === "inUse") toast.error(codeText.isInUseByAnotherApp(next.shortcut));
      else if (pressEnter === undefined) toast.success(next.enabled ? `Auto-type: ${next.shortcut}` : codeText.autoTypeOff);
    } catch (error) {
      toast.error(humanError(error));
    } finally {
      setBusy(false);
    }
  };

  const description = status.state === "inUse"
    ? <span className="row-inline"><StatusChip kind="warning" label={strings.inUseByAnotherApp} /><span className="muted">{codeText.pickAnotherShortcutOrCloseThe(status.shortcut)}</span></span>
    : status.enabled ? <span>In an app's sign-in window, press <Kbd>{status.shortcut}</Kbd> and pick a login. Nuvori types it into that window only.</span>
    : codeText.offTurnOnToFillLogins;
  return (
    <>
      <SettingsRow icon={Keyboard} title={strings.autoType} description={description}
        control={<span className="row-inline">
          {status.enabled && <select className="input select select-compact" aria-label={strings.autoTypeShortcut} value={status.preset} disabled={busy} onChange={(event) => void change(true, event.target.value)}>
            {status.presets.map((preset) => <option key={preset.id} value={preset.id}>{preset.label}</option>)}
          </select>}
          <Toggle label={strings.autoType} checked={status.enabled} disabled={busy} onChange={(on) => void change(on)} />
        </span>} />
      {status.enabled && <SettingsRow icon={CornerDownLeft} title={strings.pressEnterAfterTyping} description={strings.signsInRightAwayTurnOff}
        control={<Toggle label={strings.pressEnterAfterTyping} checked={status.pressEnter} disabled={busy} onChange={(on) => void change(true, undefined, on)} />} />}
    </>
  );
}

/**
 * "Require the master password again" (hello_window.rs, Android Settings > Security): how long
 * Windows Hello may open the vault after the master password. Only while Windows Hello is on.
 */
function MasterPasswordAgainRow() {
  const { snapshot, setSnapshot } = useVault();
  const toast = useToast();
  const confirm = useConfirm();
  const [busy, setBusy] = useState(false);
  const current = capInterval(snapshot.masterPasswordIntervalMs);
  const choices = [{ value: 0, label: strings.everyUnlock }, { value: DAY_MS, label: strings.after1Day }, { value: WEEK_MS, label: strings.after1Week }];

  const change = async (next: number) => {
    if (next === current) return;
    // As on Android, a longer window is confirmed first.
    if (confirmsFirst(current, next) && !(await confirm({ title: strings.askForTheMasterPasswordLess, message: `${strings.youLlTypeYourMasterPassword} ${strings.forUpTo7DaysAnyone}`, confirmLabel: strings.askAfter1Week }))) return;
    setBusy(true);
    try {
      setSnapshot(await api.setMasterPasswordInterval(next));
      toast.success(strings.savedYourNextUnlockAsksFor);
    } catch (failure) {
      toast.error(failure, codeText.couldnTSaveTheSetting);
    } finally {
      setBusy(false);
    }
  };

  return (
    <SettingsRow icon={KeyRound} title={strings.requireTheMasterPasswordAgain} description={strings.howOftenNuvoriAsksForYour}
      control={<select className="input select select-compact" aria-label={strings.requireTheMasterPasswordAgain} value={current} disabled={busy} onChange={(event) => void change(Number(event.target.value))}>
        {choices.map((choice) => <option key={choice.value} value={choice.value}>{choice.label}</option>)}
      </select>} />
  );
}

function SiteIconsRow() {
  const toast = useToast();
  const { enabled, apply } = useSiteIconsSetting();
  const [busy, setBusy] = useState(false);
  const run = async (task: () => Promise<Parameters<typeof apply>[0]>, done: string) => {
    setBusy(true);
    try { apply(await task()); toast.success(done); } catch (failure) { toast.error(failure, codeText.couldnTChangeWebsiteIcons); } finally { setBusy(false); }
  };
  return (
    <SettingsRow icon={Globe} title={strings.websiteIcons}
      description={enabled ? codeText.logosForPopularSitesAreBuilt : codeText.offItemsShowTheirFirstLetter}
      control={<Toggle label={strings.websiteIcons} checked={enabled} disabled={busy} onChange={(value) => void run(() => api.setSiteIcons(value), value ? codeText.websiteIconsOn : codeText.websiteIconsOff)} />}>
      {enabled && <div className="site-icons-extra"><Button size="sm" disabled={busy} onClick={() => void run(() => api.clearSiteIcons(), codeText.savedIconsRemoved)}>{strings.removeSavedIcons}</Button></div>}
    </SettingsRow>
  );
}

function QuickSearchRow() {
  const toast = useToast();
  const [status, setStatus] = useState<QuickSearchStatus | null>(null);
  const [busy, setBusy] = useState(false);
  useEffect(() => { api.quickSearchStatus().then(setStatus).catch(() => setStatus(null)); }, []);
  if (!status) return null;

  const change = async (enabled: boolean, preset?: string) => {
    setBusy(true);
    try {
      const next = await api.setQuickSearch(enabled, preset);
      setStatus(next);
      if (next.state === "inUse") toast.error(codeText.isInUseByAnotherApp(next.shortcut));
      else toast.success(next.enabled ? codeText.quickSearch(next.shortcut) : codeText.quickSearchShortcutOff);
    } catch (error) {
      toast.error(humanError(error));
    } finally {
      setBusy(false);
    }
  };

  const description = status.state === "inUse"
    ? <span className="row-inline"><StatusChip kind="warning" label={strings.inUseByAnotherApp} /><span className="muted">{codeText.pickAnotherShortcutOrCloseThe(status.shortcut)}</span></span>
    : status.enabled ? <span>Press <Kbd>{status.shortcut}</Kbd> in any app to open Nuvori's search. A locked vault asks for your password first.</span>
    : codeText.offNuvoriSSearchOpensOnly;
  return (
    <SettingsRow icon={Keyboard} title={strings.quickSearchShortcut} description={description}
      control={<span className="row-inline">
        {status.enabled && <select className="input select select-compact" aria-label={strings.quickSearchShortcut} value={status.preset} disabled={busy} onChange={(event) => void change(true, event.target.value)}>
          {status.presets.map((preset) => <option key={preset.id} value={preset.id}>{preset.label}</option>)}
        </select>}
        <Toggle label={strings.quickSearchShortcut} checked={status.enabled} disabled={busy} onChange={(on) => void change(on)} />
      </span>} />
  );
}

const PROVIDER_TEXT: Record<PasskeyProviderState, { description: string; chip?: [StatusKind, string] }> = {
  on: { description: codeText.windowsOffersYourNuvoriPasskeysIn, chip: ["success", "On"] },
  off: { description: codeText.turnOnNuvoriUnderPasskeyManagers },
  notRegistered: { description: codeText.windowsDidnTAcceptNuvoriAs, chip: ["error", codeText.notAvailable] },
  unsupported: { description: codeText.thisVersionOfWindowsCanT, chip: ["neutral", codeText.notAvailable] },
  installerBuild: { description: codeText.signingInWithPasskeysOnThis, chip: ["neutral", codeText.storeBuildOnly] },
};

function PasskeyProviderRow({ state }: { state: PasskeyProviderState }) {
  const toast = useToast();
  const text = PROVIDER_TEXT[state];
  const open = async () => {
    try {
      await api.openWindowsSettings("passkeys");
      toast.info(codeText.turnOnNuvoriUnderPasskeyManagers2);
    } catch (failure) {
      toast.error(failure, codeText.couldnTOpenWindowsSettings);
    }
  };
  const control = state === "off"
    ? <Button size="sm" icon={ExternalLink} onClick={() => void open()}>{strings.turnOn}</Button>
    : text.chip && <StatusChip kind={text.chip[0]} label={text.chip[1]} />;
  return <SettingsRow icon={KeyRound} title={strings.passkeysInWindows} description={text.description} control={control || undefined} />;
}

/** Store build only: the MSI or setup EXE build is installed too. */
function InstallerBuildRow() {
  const toast = useToast();
  const open = async () => {
    try {
      await api.openWindowsSettings("apps");
    } catch (failure) {
      toast.error(failure, codeText.couldnTOpenWindowsSettings);
    }
  };
  return (
    <SettingsRow icon={Package} title={strings.installerBuildAlsoInstalled}
      description={strings.startingItOpensThisStoreBuild}
      control={<Button size="sm" variant="ghost" icon={ExternalLink} onClick={() => void open()}>{strings.installedApps}</Button>} />
  );
}

/** One row per detected browser. Renders nothing when the backend has no `list_browsers` (older build). */
/** `onAvailable` tells the section whether this list replaces the older Chrome/Edge/Brave chips. */
function BrowsersList({ reloadKey, onAvailable }: { reloadKey: number; onAvailable: (available: boolean) => void }) {
  const toast = useToast();
  const [browsers, setBrowsers] = useState<Browser[] | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  useEffect(() => {
    api.listBrowsers()
      .then((list) => { setBrowsers(list); onAvailable(list.length > 0); })
      .catch(() => { setBrowsers(null); onAvailable(false); });
  }, [reloadKey, onAvailable]);
  if (!browsers || !browsers.length) return null;

  const change = async (browser: Browser, patch: { connected?: boolean; askAtStart?: boolean; family?: BrowserFamily }) => {
    const before = browsers;
    setBusy(browser.id);
    setBrowsers(before.map((item) => item.id === browser.id ? { ...item, ...patch } : item)); // optimistic
    try {
      setBrowsers(await api.setBrowser(browser.id, patch));
      if (patch.connected !== undefined) toast.success(patch.connected ? codeText.connectedRestartItToUseThe(browser.name) : codeText.disconnected(browser.name));
    } catch (failure) {
      setBrowsers(before);
      toast.error(failure, codeText.couldnTChange(browser.name));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="browser-list" role="group" aria-label={strings.browsers}>
      <div className="browser-list-title">{strings.browsers}</div>
      {browsers.map((browser) => {
        const unknown = browser.family === "unknown";
        const status = !browser.connected ? codeText.notConnected : browser.lastSeen ? `Used ${relativeTime(browser.lastSeen).toLowerCase()}` : codeText.connectedNotUsedYet;
        const off = busy === browser.id;
        return (
          <SettingsRow key={browser.id} icon={Globe} title={browser.name} description={status}
            control={<span className="row-inline">
              {unknown && <select className="input select select-compact" aria-label={codeText.isBuiltOn(browser.name)} value="" disabled={off}
                onChange={(event) => { if (event.target.value) void change(browser, { family: event.target.value as BrowserFamily }); }}>
                <option value="">{strings.builtOn}</option>
                <option value="chromium">{strings.builtOnChromium}</option>
                <option value="firefox">{strings.builtOnFirefox}</option>
              </select>}
              <Toggle label={codeText.connect(browser.name)} checked={browser.connected} disabled={off || unknown} onChange={(on) => void change(browser, { connected: on })} />
            </span>}>
            {browser.connected && <div className="browser-ask">
              <span id={`ask-${browser.id}`}>{strings.askForThePasswordWhenIt}</span>
              <Toggle label={codeText.askInWhenItStarts(browser.name)} checked={browser.askAtStart} disabled={off} onChange={(on) => void change(browser, { askAtStart: on })} />
            </div>}
          </SettingsRow>
        );
      })}
      <p className="browser-hint muted">{strings.restartABrowserAfterYouConnect}</p>
    </div>
  );
}

const BROWSER_NAMES: Record<string, string> = { chrome: "Chrome", edge: "Edge", brave: "Brave" };

function BrowserSection() {
  const { snapshot } = useVault();
  const toast = useToast();
  const [connecting, setConnecting] = useState(false);
  const [reloadKey, setReloadKey] = useState(0);
  const browser = useBrowserStatus(4000);
  const status: BrowserStatus | null = browser.data;
  const indicator = browserIndicator(snapshot, status, Boolean(browser.error));
  const hosts: Array<[keyof BrowserStatus["hosts"], string]> = [["chrome", "Chrome"], ["edge", "Edge"], ["brave", "Brave"]];
  // The Browsers list (newer apps) shows every browser; the old chips stay for older backends only.
  const [browserListShown, setBrowserListShown] = useState(false);
  const connect = async () => {
    setConnecting(true);
    try {
      const report = await api.connectBrowsers();
      const names = report.browsers.map((name) => BROWSER_NAMES[name] ?? name).join(", ");
      if (!report.browsers.length) toast.info(codeText.noChromeEdgeOrBraveWas);
      else if (report.changed) toast.success(codeText.connectedRestartTheBrowserToUse(names));
      else toast.success(codeText.alreadyConnected(names));
      await browser.reload?.();
      setReloadKey((key) => key + 1);
    } catch (failure) {
      toast.error(failure, codeText.couldnTConnectTheBrowsers);
    } finally {
      setConnecting(false);
    }
  };

  return (
    <SettingsGroup title={strings.browserExtension} id="settings-browser">
      <SettingsRow icon={Puzzle} title={strings.connection} description={browser.error ? codeText.statusIsUnavailableInThisVersion : status?.listening ? codeText.nuvoriIsListeningForTheExtension : codeText.nuvoriIsnTListeningForThe2}
        control={<StatusChip kind={indicator.kind} label={indicator.label} />} />
      <SettingsRow icon={PlugZap} title={strings.connectBrowsers} description={strings.letsTheNuvoriExtensionReachThis}
        control={<Button size="sm" busy={connecting} onClick={() => void connect()}>{strings.reconnectAll}</Button>} />
      <BrowsersList reloadKey={reloadKey} onAvailable={setBrowserListShown} />
      <SignInsSettingRow />
      {status && (
        <div className="settings-detail">
          {!browserListShown && <div className="chip-row" aria-label={strings.registeredBrowsers}>
            {hosts.map(([key, label]) => <StatusChip key={key} kind={status.hosts[key] ? "success" : "neutral"} label={`${label}${status.hosts[key] ? "" : " · not set up"}`} />)}
          </div>}
          <dl className="facts">
            <div><dt>{strings.lastContact}</dt><dd>{status.lastRequestAt ? relativeTime(status.lastRequestAt) : codeText.never}</dd></div>
            {status.lastAction && <div><dt>{strings.lastAction}</dt><dd>{status.lastAction}</dd></div>}
            <div><dt>{strings.requestsSinceUnlock}</dt><dd>{status.requestsSinceUnlock}</dd></div>
          </dl>
        </div>
      )}
      <details className="settings-detail guide">
        <summary>{strings.setUpTheExtension}</summary>
        <ol className="how-list">
          <li>Install <strong>{strings.nuvoriPasswordFill}</strong> from the Chrome Web Store. In Edge, first allow extensions from other stores. You can also choose <strong>{strings.loadUnpacked}</strong> on the extensions page and pick the <code>{strings.extension}</code> folder.</li>
          <li>Nuvori connects the browsers when it starts. If a browser above shows <strong>{strings.notSetUp}</strong>, choose <strong>{strings.reconnectAll}</strong>.</li>
          <li>{strings.restartTheBrowserKeepNuvoriOpen}</li>
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
    if (typed !== "RESET") { setError(codeText.typeResetExactlyToConfirm); return; }
    if (!password) { setError(driveBackupText.enterPassword); return; }
    setBusy(true); setError("");
    try {
      const next = await api.resetVault(password);
      closeReset();
      router.reset();
      setSnapshot(next);
      toast.success(strings.thisPcSVaultWasDeleted);
    } catch (failure) {
      setPassword("");
      setError(humanError(failure, codeText.couldnTResetTheVault));
    } finally {
      setBusy(false);
    }
  };

  return (
    <SettingsGroup title={strings.dangerZone} id={stopOnly ? undefined : "settings-danger"}>
      {snapshot.enrolled && !resetOnly && <SettingsRow icon={Unplug} title={strings.leaveGroup} description={strings.stopSyncingKeepThisPcS} danger control={<Button size="sm" variant="ghost" className="btn-danger-text" onClick={() => void leave.run(() => membership.reload())} busy={leave.busy}>{strings.leaveGroup}</Button>} />}
      {!snapshot.enrolled && !resetOnly && membership.data?.pendingLeave && <SettingsRow icon={Unplug} title={strings.leftTheSyncGroup} description={strings.yourPhoneIsToldTheNext} control={<PendingLeaveChip membership={membership.data} />} />}
      {!stopOnly && <SettingsRow icon={RotateCcw} title={strings.resetThisPcSVault} description={strings.deleteThisPcSVaultItems} danger
        control={<Button size="sm" variant="danger" onClick={() => setResetOpen(true)}>{strings.reset}</Button>} />}
      <Dialog open={resetOpen} onClose={closeReset} title={strings.resetThisPcSVault2} locked={busy} size="sm"
        description={strings.thisCanTBeUndoneOn}
        footer={<>
          <Button variant="ghost" onClick={closeReset} disabled={busy}>{strings.cancel}</Button>
          <Button variant="danger" type="submit" form="reset-form" icon={LogOut} busy={busy} disabled={typed !== "RESET" || !password}>{strings.deleteThisPcSVault}</Button>
        </>}>
        <form id="reset-form" className="form-stack" onSubmit={(event) => void reset(event)}>
          {error && <StatusBanner kind="error">{error}</StatusBanner>}
          <PasswordField label={strings.masterPassword} value={password} onValue={setPassword} autoComplete="current-password" disabled={busy} data-autofocus />
          <TextField label={strings.typeResetToConfirm} value={typed} onValue={setTyped} autoComplete="off" spellCheck={false} disabled={busy} />
        </form>
      </Dialog>
      {leave.dialog}
    </SettingsGroup>
  );
}
