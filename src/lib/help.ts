// The questions and answers on the Help page (pages/Help.tsx), the Windows counterpart of Android's
// in-app help (`ui/HelpUi.kt`). Android keeps its help text with the page rather than in its string
// resources, and this follows it: strings.ts holds the labels a screen shows, and this is a page of
// prose about how this app behaves. Every answer describes what Nuvori for Windows does today, and
// most carry a shortcut to the screen that does it, so an answer ends somewhere useful.
import type { Route } from "../app/router";
import { fold, tokenize } from "./text.ts";

export type HelpTopic = {
  /** The heading this question appears under. Topics of one section stay together, in this order. */
  section: string;
  question: string;
  answer: string;
  /** The screen that carries the answer out. */
  go?: { label: string; route: Route };
};

/** The Help page's own labels. */
export const helpText = {
  title: "Help",
  intro: "How this PC's vault, its shortcuts and sync with your phone work. Open a question for the steps.",
  row: "Unlocking, filling, sync and passkeys",
  search: "Search help",
  searchPlaceholder: "Search questions and answers",
  noAnswers: "No answer matches that",
  noAnswersBody: "Try a word from the question, like unlock, passkey, extension or sync.",
  oneAnswer: "1 answer",
  someAnswers: (count: number) => `${count} answers`,
} as const;

const SYNC: Route = { page: "sync" };
const SECURITY: Route = { page: "settings", section: "security" };

export const helpTopics: HelpTopic[] = [
  {
    section: "Getting started",
    question: "How do I add this PC to my phone's vault?",
    answer:
      "Create and unlock a vault on this PC first. Then put both devices on the same Wi-Fi and open Devices & sync. Either scan the QR your phone shows, or choose to show a QR for your phone to scan. Enter your phone vault's master password, then check that both screens show the same code before you confirm. This PC receives an encrypted copy and keeps any items it already had; items your phone already has are not added twice.",
    go: { label: "Open Devices & sync", route: SYNC },
  },
  {
    section: "Getting started",
    question: "Why does pairing ask for my phone's master password?",
    answer:
      "Your vault's key comes from that password, so this PC needs it to read the copy your phone sends. Devices that share a vault share the master password, and from then on this PC unlocks with it. The password itself never goes over the network: pairing proves both devices know it without sending it.",
  },
  {
    section: "Getting started",
    question: "Can I use Nuvori on this PC without a phone?",
    answer:
      "Yes. This PC keeps its own encrypted vault, and everything except sync works without pairing. You can pair later, and this PC keeps the items it already has when it does.",
  },
  {
    section: "Getting started",
    question: "Does Nuvori work without an internet connection?",
    answer:
      "Your vault is on this PC, so unlocking, searching, editing and filling all work offline. Only sync needs a connection: your local Wi-Fi for a direct exchange with your phone, or your own Google Drive when the devices are apart.",
  },
  {
    section: "Finding and filling",
    question: "How do I find an item quickly?",
    answer:
      "Press Ctrl+K inside Nuvori to search every item and note by name, website, username or card digits. To reach the same search from any other app, turn on the quick search shortcut in Settings under Security and pick the key combination you want. A locked vault asks for your password first.",
    go: { label: "Open Security settings", route: SECURITY },
  },
  {
    section: "Finding and filling",
    question: "How do I fill a login in my browser?",
    answer:
      "Install the Nuvori Password Fill extension, then open Settings and choose Reconnect all under Browser extension. Restart the browser afterwards and keep Nuvori open and unlocked. The extension never sees your master password or the whole vault: it receives one login at a time, and only after you pick it.",
    go: { label: "Open extension settings", route: { page: "settings", section: "browser" } },
  },
  {
    section: "Finding and filling",
    question: "Can Nuvori fill a login in a desktop app?",
    answer:
      "Yes, with auto-type. Turn it on in Settings under Security and choose a shortcut. Put the cursor in the app's sign-in box, press that shortcut, and pick a login: Nuvori types it into that window only. Turn on Press Enter after typing if you want it to sign in straight away.",
    go: { label: "Open Security settings", route: SECURITY },
  },
  {
    section: "Finding and filling",
    question: "Where are my authenticator codes?",
    answer:
      "Open Codes. Each code counts down to the next one, and the ring beside it shows how long that one lasts. Copy a code from the list, or from the item it belongs to.",
    go: { label: "Open Codes", route: { page: "codes" } },
  },
  {
    section: "Finding and filling",
    question: "What is the Sign-ins list for?",
    answer:
      "It remembers which “Continue with” account you used on each site, so you know whether you signed in with Google, Apple or a password before you try. The browser extension adds to it as you sign in.",
    go: { label: "Open Sign-ins", route: { page: "signins" } },
  },
  {
    section: "Locking and unlocking",
    question: "How do I lock Nuvori right now?",
    answer: "Press Ctrl+L, or choose Lock vault on the More page. Locking clears the vault from this PC's memory; nothing is lost.",
  },
  {
    section: "Locking and unlocking",
    question: "Can I unlock with my PIN, face or fingerprint?",
    answer:
      "Yes, if Windows Hello is set up in Windows Settings. Turn on Windows Hello in Settings under Security and confirm your master password once. After that the unlock screen offers Hello, and your master password still works and is still needed whenever Windows can't check it's you. Nuvori never stores the password: Windows Hello releases the vault's key only after your PIN, face or fingerprint, and only on this Windows account.",
    go: { label: "Open Security settings", route: SECURITY },
  },
  {
    section: "Locking and unlocking",
    question: "When does Nuvori lock itself?",
    answer:
      "After the time you choose for auto-lock, measured from your last mouse or keyboard activity. Choose Never to leave it unlocked until you lock it yourself or close Nuvori.",
    go: { label: "Open Security settings", route: SECURITY },
  },
  {
    section: "Locking and unlocking",
    question: "Does a copied password stay on the clipboard?",
    answer:
      "Only as long as you allow. Clear copied secrets in Settings under Security clears a copied password, code or card number after the seconds you choose, while Nuvori is open. With it off, what you copied stays until you copy something else.",
    go: { label: "Open Security settings", route: SECURITY },
  },
  {
    section: "Locking and unlocking",
    question: "I forgot my master password. What now?",
    answer:
      "Nuvori cannot reset or recover it: the vault's key comes from that password and nobody else holds it. If this PC is paired, your phone still has the vault, so you can reset this PC's vault in Settings under Danger zone and pair again. Your other devices keep their own copies.",
    go: { label: "Open Danger zone", route: { page: "settings", section: "danger" } },
  },
  {
    section: "Passkeys",
    question: "How do I sign in with a passkey saved in Nuvori?",
    answer:
      "On Windows 11, open Settings in Nuvori and look at Passkeys in Windows under Security. If it offers to turn on, choose it: Windows asks once, under Passkey managers. After that, pick Nuvori when a site asks for a passkey. This needs the Microsoft Store build; your passkeys still sync either way.",
    go: { label: "Open Security settings", route: SECURITY },
  },
  {
    section: "Passkeys",
    question: "Why wasn't Nuvori offered for a passkey?",
    answer:
      "Windows decides which managers a site's prompt shows. Check Passkeys in Windows under Security: it says whether Windows accepted Nuvori, whether this Windows version supports passkey managers at all, and whether this is the Store build. A locked vault, or a site with no passkey saved on this PC, also leaves Nuvori with nothing to offer.",
    go: { label: "Open Security settings", route: SECURITY },
  },
  {
    section: "Sync with your phone",
    question: "What do the sync words on the Devices & sync page mean?",
    answer:
      "Syncing changes means the devices are exchanging encrypted changes right now. Changes waiting to apply means this PC has received changes it will apply once you unlock. Up to date on a device card means that device has confirmed your latest change. Not checked yet means this PC has not reached it since it started.",
    go: { label: "Open Devices & sync", route: SYNC },
  },
  {
    section: "Sync with your phone",
    question: "Can this PC sync when it isn't on my phone's Wi-Fi?",
    answer:
      "Yes, through your own Google Drive. Connect it on the Devices & sync page and sign in to the same Google account on each device. Every change is encrypted on this PC before it is uploaded, into a hidden Nuvori folder that can't see your other Drive files.",
    go: { label: "Open Devices & sync", route: SYNC },
  },
  {
    section: "Sync with your phone",
    question: "Why can't this PC add or remove devices?",
    answer:
      "Only the managing device signs those changes, and that is a phone or tablet. This PC can sync edits, but invitations and removals happen on the managing phone. If a device is listed as removed here, your phone removed it and this PC was told at the next sync.",
    go: { label: "Open Devices & sync", route: SYNC },
  },
  {
    section: "Sync with your phone",
    question: "What does “changes need review” mean?",
    answer:
      "Two devices changed the same item before they could sync, so Nuvori kept both versions and asks you to choose. Open the review list, compare the two, and pick the one to keep. Nothing is discarded until you choose.",
    go: { label: "Open Devices & sync", route: SYNC },
  },
  {
    section: "Sync with your phone",
    question: "Nothing is syncing. What should I check?",
    answer:
      "Put both devices on the same Wi-Fi, unlock Nuvori on each, and choose Sync now. Some guest and work networks stop devices from reaching each other; if yours does, connect Google Drive instead, or enter the other device's local IP address under Optional device address.",
    go: { label: "Open Devices & sync", route: SYNC },
  },
  {
    section: "Sync with your phone",
    question: "How do I stop syncing this PC?",
    answer:
      "Open Settings and choose Leave group under Danger zone. You can keep this PC's items or start with an empty vault. Your phone is told the next time the devices reach each other, and your other devices are not touched.",
    go: { label: "Open Danger zone", route: { page: "settings", section: "danger" } },
  },
  {
    section: "Your items",
    question: "I deleted an item by mistake. Can I get it back?",
    answer:
      "Yes, for 30 days. Open Recently deleted and restore it. It comes back as a new item, in the folders that still exist, with its previous passwords, and your other devices get it at the next sync. Its photos are not kept, so add those again.",
    go: { label: "Open Recently deleted", route: { page: "trash" } },
  },
  {
    section: "Your items",
    question: "Can I bring in logins from another password manager?",
    answer:
      "Open Settings and choose Import from KeePass under Your data. It reads a KeePassXC or KeePass database (.kdbx) and brings in logins, codes and notes. You see what it found before anything is saved.",
    go: { label: "Open Your data settings", route: { page: "settings", section: "data" } },
  },
  {
    section: "Your items",
    question: "Why do some items show a logo and others a letter?",
    answer:
      "Logos for popular sites are built in. For anything else, the browser extension adds a site's icon the first time you sign in there, fetched from that site without cookies, and sync shares it with your other devices. Turn Website icons off in Settings to show first letters only.",
    go: { label: "Open App settings", route: { page: "settings", section: "appearance" } },
  },
  {
    section: "This PC",
    question: "Can I change the theme and colors?",
    answer:
      "Open Settings under App. The theme follows Windows unless you pick light or dark yourself, and you can choose an accent and a background. Colors are saved on this PC and reach your other devices after each has synced once.",
    go: { label: "Open App settings", route: { page: "settings", section: "appearance" } },
  },
  {
    section: "This PC",
    question: "What does the activity list show?",
    answer:
      "Recent unlocks, saves, syncs and browser requests from this PC, so you can see what happened while you were away. It never includes passwords, usernames or item names, and it stays on this PC.",
    go: { label: "Open Activity", route: { page: "activity" } },
  },
  {
    section: "This PC",
    question: "Where is my vault kept, and who can read it?",
    answer:
      "On this PC, encrypted with a key derived from your master password. Your phone keeps its own copy. Changes travel over your Wi-Fi, or through your own Google Drive if you connect it, encrypted on this PC before they leave it.",
    go: { label: "Open About", route: { page: "settings", section: "about" } },
  },
  {
    section: "This PC",
    question: "How do I remove Nuvori's vault from this PC?",
    answer:
      "Open Settings and choose Reset under Danger zone, then confirm with your master password. That deletes this PC's vault, items, photos and device identity. Your other devices keep their copies, and you can pair this PC again afterwards.",
    go: { label: "Open Danger zone", route: { page: "settings", section: "danger" } },
  },
];

/** The sections, in the order their first question appears. */
export function helpSections(topics: HelpTopic[] = helpTopics): string[] {
  const seen: string[] = [];
  for (const topic of topics) if (!seen.includes(topic.section)) seen.push(topic.section);
  return seen;
}

/**
 * The questions a search matches, in their own order. Every word typed has to appear somewhere in
 * the question, the answer or the section heading, so more words narrow the list. Accents and case
 * are ignored, as in the vault's own search.
 */
export function searchHelp(query: string, topics: HelpTopic[] = helpTopics): HelpTopic[] {
  const words = tokenize(query);
  if (!words.length) return topics;
  return topics.filter((topic) => {
    const haystack = fold(`${topic.section} ${topic.question} ${topic.answer}`);
    return words.every((word) => haystack.includes(word));
  });
}
