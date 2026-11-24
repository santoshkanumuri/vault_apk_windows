import { Activity, ArchiveRestore, CircleHelp, FileText, LogIn, MonitorSmartphone, LockKeyhole, Settings, UserRound } from "lucide-react";
import { SettingsGroup, SettingsRow } from "../components/Display";
import { useLock } from "../app/hooks";
import { useRouter } from "../app/router";
import { useVault } from "../app/vault";
import { plural } from "../lib/format";
import { strings } from "../strings";

export function MorePage() {
  const router = useRouter();
  const { snapshot } = useVault();
  const lock = useLock();
  return (
    <div className="page page-narrow">
      <SettingsGroup title={strings.yourVault}>
        <SettingsRow icon={LogIn} title={strings.signIns} description={strings.whichContinueWithAccountYouUsed} onClick={() => void router.navigate({ page: "signins" })} />
        <SettingsRow icon={FileText} title={strings.notes} description={plural(snapshot.counts.notes, "private note")} onClick={() => void router.navigate({ page: "notes" })} />
        <SettingsRow icon={CircleHelp} title={strings.securityQuestions} description={plural(snapshot.counts.questions, "saved question")} onClick={() => void router.navigate({ page: "list", category: "questions" })} />
        <SettingsRow icon={UserRound} title={strings.autofillDetails} description={plural(snapshot.counts.autofill, "saved profile")} onClick={() => void router.navigate({ page: "list", category: "autofill" })} />
      </SettingsGroup>
      <SettingsGroup title={strings.manageNuvori}>
        <SettingsRow icon={MonitorSmartphone} title="Devices & sync" description={snapshot.enrolled ? "Phone sync and status" : "Pair with your phone"} onClick={() => void router.navigate({ page: "sync" })} />
        <SettingsRow icon={Activity} title={strings.activity} description={strings.recentUnlocksSavesAndSyncs} onClick={() => void router.navigate({ page: "activity" })} />
        <SettingsRow icon={ArchiveRestore} title={strings.recentlyDeleted} description={strings.restoreItemsDeletedInTheLast} onClick={() => void router.navigate({ page: "trash" })} />
        <SettingsRow icon={Settings} title={strings.settings} description={strings.themeSecurityBrowserExtension} onClick={() => void router.navigate({ page: "settings" })} />
        <SettingsRow icon={LockKeyhole} title={strings.lockVault} description={strings.ctrlL} onClick={() => void lock()} />
      </SettingsGroup>
    </div>
  );
}
