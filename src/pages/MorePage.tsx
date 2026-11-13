import { Activity, CircleHelp, FileText, MonitorSmartphone, LockKeyhole, Settings, UserRound } from "lucide-react";
import { SettingsGroup, SettingsRow } from "../components/Display";
import { useLock } from "../app/hooks";
import { useRouter } from "../app/router";
import { useVault } from "../app/vault";
import { plural } from "../lib/format";

export function MorePage() {
  const router = useRouter();
  const { snapshot } = useVault();
  const lock = useLock();
  return (
    <div className="page page-narrow">
      <SettingsGroup title="Your vault">
        <SettingsRow icon={FileText} title="Notes" description={plural(snapshot.counts.notes, "private note")} onClick={() => void router.navigate({ page: "notes" })} />
        <SettingsRow icon={CircleHelp} title="Security questions" description={plural(snapshot.counts.questions, "saved question")} onClick={() => void router.navigate({ page: "list", category: "questions" })} />
        <SettingsRow icon={UserRound} title="Autofill details" description={plural(snapshot.counts.autofill, "saved profile")} onClick={() => void router.navigate({ page: "list", category: "autofill" })} />
      </SettingsGroup>
      <SettingsGroup title="Manage Nuvori">
        <SettingsRow icon={MonitorSmartphone} title="Devices & sync" description={snapshot.enrolled ? "Phone sync and status" : "Pair with your phone"} onClick={() => void router.navigate({ page: "sync" })} />
        <SettingsRow icon={Activity} title="Activity" description="Recent unlocks, saves, and syncs" onClick={() => void router.navigate({ page: "activity" })} />
        <SettingsRow icon={Settings} title="Settings" description="Theme, security, browser extension" onClick={() => void router.navigate({ page: "settings" })} />
        <SettingsRow icon={LockKeyhole} title="Lock vault" description="Ctrl+L" onClick={() => void lock()} />
      </SettingsGroup>
    </div>
  );
}
