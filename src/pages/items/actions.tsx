import { useCallback } from "react";
import { Copy, CreditCard, KeyRound, Mail, ShieldQuestion, Timer, UserRound } from "lucide-react";
import { IconButton } from "../../components/Button";
import { useCopy } from "../../app/clipboard";
import type { VaultEntry } from "../../lib/api";
import { profileFrom } from "../../lib/entries";
import { totpAt } from "../../lib/totp";
import { markUsed } from "../../app/recent";
import { codeText, strings } from "../../strings";

export type QuickAction = { key: string; label: string; icon: typeof Copy; run: () => Promise<boolean> };

/** Copy actions for an entry. Secret values are read from the entry only at the moment of copying. */
export function useEntryActions() {
  const copy = useCopy();
  return useCallback((entry: VaultEntry): QuickAction[] => {
    switch (entry.type) {
      case "PASSWORD": return [
        ...(entry.primaryValue ? [{ key: "username", label: codeText.copyUsername, icon: UserRound, run: () => copy(entry.primaryValue, { label: strings.username }) }] : []),
        { key: "password", label: codeText.copyPassword, icon: KeyRound, run: () => copy(() => entry.secondaryValue, { label: strings.password, secret: true }) }
      ];
      case "CARD": return [
        { key: "number", label: codeText.copyCardNumber, icon: CreditCard, run: () => copy(() => entry.primaryValue.replace(/\D/g, ""), { label: strings.cardNumber, secret: true }) },
        ...(entry.fourthValue ? [{ key: "cvv", label: codeText.copySecurityCode, icon: KeyRound, run: () => copy(() => entry.fourthValue, { label: strings.securityCode, secret: true }) }] : [])
      ];
      case "AUTHENTICATOR": return [
        { key: "code", label: strings.copyCode, icon: Timer, run: () => copy(async () => (await totpAt(entry))?.value ?? null, { label: strings.code, secret: true, message: strings.codeCopied }) }
      ];
      case "QUESTION": return [
        { key: "answer", label: codeText.copyAnswer, icon: ShieldQuestion, run: () => copy(() => entry.secondaryValue, { label: strings.answer, secret: true }) }
      ];
      case "AUTOFILL": {
        const profile = profileFrom(entry.primaryValue);
        return profile.email ? [{ key: "email", label: codeText.copyEmail, icon: Mail, run: () => copy(profile.email, { label: codeText.email }) }] : [];
      }
    }
  }, [copy]);
}

export function EntryQuickActions({ entry, max = 2 }: { entry: VaultEntry; max?: number }) {
  const actionsFor = useEntryActions();
  const actions = actionsFor(entry).slice(0, max);
  if (!actions.length) return null;
  return <>{actions.map((action) => <IconButton key={action.key} label={codeText.for(action.label, entry.title)} icon={action.icon} size="sm" onClick={(event) => { event.stopPropagation(); markUsed(entry.id); void action.run(); }} />)}</>;
}
