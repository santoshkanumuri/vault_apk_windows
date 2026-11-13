import { useCallback } from "react";
import { Copy, CreditCard, KeyRound, Mail, ShieldQuestion, Timer, UserRound } from "lucide-react";
import { IconButton } from "../../components/Button";
import { useCopy } from "../../app/clipboard";
import type { VaultEntry } from "../../lib/api";
import { profileFrom } from "../../lib/entries";
import { totpAt } from "../../lib/totp";
import { markUsed } from "../../app/recent";

export type QuickAction = { key: string; label: string; icon: typeof Copy; run: () => Promise<boolean> };

/** Copy actions for an entry. Secret values are read from the entry only at the moment of copying. */
export function useEntryActions() {
  const copy = useCopy();
  return useCallback((entry: VaultEntry): QuickAction[] => {
    switch (entry.type) {
      case "PASSWORD": return [
        ...(entry.primaryValue ? [{ key: "username", label: "Copy username", icon: UserRound, run: () => copy(entry.primaryValue, { label: "Username" }) }] : []),
        { key: "password", label: "Copy password", icon: KeyRound, run: () => copy(() => entry.secondaryValue, { label: "Password", secret: true }) }
      ];
      case "CARD": return [
        { key: "number", label: "Copy card number", icon: CreditCard, run: () => copy(() => entry.primaryValue.replace(/\D/g, ""), { label: "Card number", secret: true }) },
        ...(entry.fourthValue ? [{ key: "cvv", label: "Copy security code", icon: KeyRound, run: () => copy(() => entry.fourthValue, { label: "Security code", secret: true }) }] : [])
      ];
      case "AUTHENTICATOR": return [
        { key: "code", label: "Copy code", icon: Timer, run: () => copy(async () => (await totpAt(entry))?.value ?? null, { label: "Code", secret: true, message: "Code copied" }) }
      ];
      case "QUESTION": return [
        { key: "answer", label: "Copy answer", icon: ShieldQuestion, run: () => copy(() => entry.secondaryValue, { label: "Answer", secret: true }) }
      ];
      case "AUTOFILL": {
        const profile = profileFrom(entry.primaryValue);
        return profile.email ? [{ key: "email", label: "Copy email", icon: Mail, run: () => copy(profile.email, { label: "Email" }) }] : [];
      }
    }
  }, [copy]);
}

export function EntryQuickActions({ entry, max = 2 }: { entry: VaultEntry; max?: number }) {
  const actionsFor = useEntryActions();
  const actions = actionsFor(entry).slice(0, max);
  if (!actions.length) return null;
  return <>{actions.map((action) => <IconButton key={action.key} label={`${action.label} for ${entry.title}`} icon={action.icon} size="sm" onClick={(event) => { event.stopPropagation(); markUsed(entry.id); void action.run(); }} />)}</>;
}
