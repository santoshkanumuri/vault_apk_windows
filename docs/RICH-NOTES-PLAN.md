# Rich notes: plan and format (v1)

Notes become a real note-taking surface on the phone and the PC: formatted text, lists,
checklists, tables, colors and links, while staying ordinary vault data. This document is the
shared contract between the Android app (`vault_apk`) and the Windows app (`vault_apk_windows`).

## Goals

- Everyday rich notes: bold, italic, underline, strikethrough, inline code, text color,
  highlight (background) color, links, headings (3 levels), bulleted, numbered and check lists
  with nesting, quotes, code blocks, dividers and tables.
- Pinning, search over the note text, undo and redo, a formatting toolbar above the keyboard
  on the phone and a toolbar plus keyboard shortcuts on the PC.
- No change to the sync protocol, the payload encryption or the database schema, so the work
  merges cleanly beside the sync security work and older app versions keep working.
- Existing plain notes keep working untouched and become rich the first time they are edited.

## Where the document lives

A note is still a `VaultEntry` of type `NOTE`.

| Field | Holds |
| --- | --- |
| `notes` | The **plain-text fallback**: the whole note as readable text (see "Plain text"). Search, list previews, the watch, older app versions and backups all read this. |
| `fourthValue` | The **rich document** as JSON (below), or empty for a plain note. Cards use this field for the CVV; notes never did, so it is free for notes. |
| `favorite` | **Pinned**. Pinned notes sort first in the notes list. |

Both fields travel together in the same entry record, so every path that already carries an
entry carries the rich document: the encrypted SQLCipher database, LAN device sync, Google
Drive sync, encrypted backups and the Windows `local_note_details` copy of the entry. Nothing
new is written outside the vault, so the existing encryption covers it.

## Document format

```json
{
  "format": "nuvori.richnote",
  "version": 1,
  "plainHash": "3f1c…",
  "blocks": [
    {"type": "heading", "level": 1, "spans": [{"text": "Trip"}]},
    {"type": "paragraph", "spans": [
      {"text": "Bring "},
      {"text": "passport", "bold": true, "color": "red"},
      {"text": " and see ", "bg": "yellow"},
      {"text": "the booking", "link": "https://example.com/booking"}
    ]},
    {"type": "check", "checked": true, "indent": 0, "spans": [{"text": "Charger"}]},
    {"type": "bullet", "indent": 1, "spans": [{"text": "Nested item", "italic": true}]},
    {"type": "numbered", "indent": 0, "spans": [{"text": "First"}]},
    {"type": "quote", "spans": [{"text": "Quoted"}]},
    {"type": "code", "spans": [{"text": "ssh admin@10.0.0.1"}]},
    {"type": "divider"},
    {"type": "table", "header": true, "rows": [
      [{"spans": [{"text": "Account"}]}, {"spans": [{"text": "PIN hint"}]}],
      [{"spans": [{"text": "Bank"}]}, {"spans": [{"text": "Birthday", "bold": true}]}]
    ]}
  ]
}
```

- **Block types**: `paragraph`, `heading` (`level` 1 to 3), `bullet`, `numbered`, `check`
  (`checked`), `quote`, `code`, `divider`, `table` (`header`, `rows` of cells). `indent` (0 to 4)
  applies to list and check items.
- **Span marks**: `bold`, `italic`, `underline`, `strike`, `code` (booleans, omitted when false),
  `color` and `bg` (color tokens), `link` (URL).
- **Colors are tokens**, never raw values: `gray`, `red`, `orange`, `yellow`, `green`, `teal`,
  `blue`, `purple`, `pink`. Each app maps tokens to colors that read well in its light and dark
  themes, so a note looks right in either theme on either device.
- **Numbering** is not stored; a run of `numbered` items at the same indent counts from 1.
- **Limits** (enforced on read and on save): 4,000 blocks, 50 rows and 12 columns per table,
  200,000 characters of text, 512 KB of JSON. Larger documents are refused at save time and
  ignored (plain fallback shown) on read.

### Reading rules (both apps)

1. If `fourthValue` is empty, not JSON, has another `format`, or breaks a limit, the note is
   plain: show `notes`.
2. If `version` is newer than the app understands, show `notes` read-only formatting-free and
   warn before editing that formatting from the newer version will be replaced.
3. **Divergence check**: if `plainHash` does not match the hash of the current `notes`, the
   text was changed by something that does not understand rich notes (an older app version, an
   import). The plain text wins and is shown as plain paragraphs. This keeps an older Windows or
   Android build from silently losing an edit.
4. Unknown block types are skipped; unknown span keys and unknown color tokens are dropped.
5. Links are kept only for `http`, `https` and `mailto`, at most 2,048 characters, and are never
   opened automatically: tapping or clicking one asks first and shows the full address.
6. Text is cleaned of control characters other than line breaks and tabs, and of Unicode
   direction overrides, so a note cannot disguise its text.

`plainHash` is the lowercase hex SHA-256 of the UTF-8 plain fallback after normalizing it
(`\r\n` and `\r` to `\n`, then trimmed), cut to the first 32 hex characters. It is inside the
encrypted entry like the rest of the note.

### Plain text

The plain fallback is generated from the document on every save:

| Block | Plain text |
| --- | --- |
| paragraph, heading, quote, code | the text (`> ` before quote lines) |
| bullet | `• text` |
| numbered | `1. text` |
| check | `☐ text` or `☑ text` |
| nested items | two spaces per indent level before the marker |
| divider | `———` |
| table | one line per row, cells joined with ` | ` |

Old apps therefore show a readable note, and search, list previews and the watch keep working
with no change.

## Migration

- **No bulk rewrite.** An existing note has an empty `fourthValue` and is shown exactly as
  before (each line is a paragraph).
- The first time a plain note is opened in the new editor, each line becomes a paragraph. The
  plain fallback of that document is the original text, so saving without changes keeps the text
  byte for byte. Formatting is added only by the person editing.
- Older apps that edit a rich note keep working: they change `notes`, the divergence check sees
  the change and the newer app shows their text (formatting from before that edit is dropped).

## Sync and conflicts

- Rich notes need **no protocol change**: the document rides inside the existing encrypted
  entry payload and is versioned and signed with the rest of the entry.
- A note edited on two devices before they sync is already raised as a conflict for review. On
  Android the review sheet for a note adds **Keep both edits**: `RichNoteMerge.combine` keeps the
  blocks both versions share once and each side's own blocks in document order. A plain line from
  an older app that matches a formatted line counts as the same line, and the formatted one wins.
  The conflict labels name the fields "Note text" and "Formatting". The Windows conflict screen
  keeps its existing choices (this PC's version or the other device's) for now.
- **Size budget.** Peers refuse a sync payload over 1 MiB, so a note's text and JSON together
  (as JSON-escaped UTF-8) must stay under 900,000 bytes. Both apps refuse to save a larger note
  with "This note is too long. Split it into two notes." and keep the editor open.
- The watch only shows codes today, so it needs nothing. If notes ever reach the watch, they
  should use the plain fallback.

## Design

### Phone (Compose)

- The note editor keeps the existing screen (title, folders, tags, photos) and replaces the
  single text box with a rich body.
- A formatting toolbar sits above the keyboard: undo, redo, text style (normal, heading 1 to 3,
  quote, code block), bold, italic, underline, strikethrough, text color, highlight, bullets,
  numbers, checklist, indent, outdent, link, inline code, table, divider and clear formatting.
  It scrolls sideways and its buttons show their on state for the current selection.
- Colors and highlight open a bottom sheet of the nine color tokens plus "Default". Table
  insertion opens a bottom sheet to pick rows, columns and a header row; tables are edited in
  place with add or remove row and column actions.
- Lists continue on Enter; Enter on an empty item ends the list (or outdents a nested one).
- The note view renders the document with tappable checkboxes (saved straight away), tables
  that scroll sideways, and links that ask before opening.
- Colors come from one shared palette so light and dark both read well (text color / highlight):

  | Token  | Light text | Light highlight | Dark text | Dark highlight |
  |--------|-----------|-----------------|-----------|----------------|
  | gray   | #5F6368 | #E8EAED | #B0B4BA | #3C4043 |
  | red    | #C62828 | #FFDAD6 | #FF8A80 | #5C1F1B |
  | orange | #E65100 | #FFE0B2 | #FFB74D | #5A3300 |
  | yellow | #9A6700 | #FFF59D | #FFE082 | #524800 |
  | green  | #2E7D32 | #C8E6C9 | #81C784 | #1E4620 |
  | teal   | #00796B | #B2DFDB | #80CBC4 | #0E3F3A |
  | blue   | #1565C0 | #BBDEFB | #90CAF9 | #173A5E |
  | purple | #6A1B9A | #E1BEE7 | #CE93D8 | #3E2050 |
  | pink   | #AD1457 | #F8BBD0 | #F48FB1 | #561D38 |

### PC (Tauri + React)

- A wider editor with a sticky toolbar and the same tools.
- Shortcuts: Ctrl+B, Ctrl+I, Ctrl+U, Ctrl+Shift+X (strike), Ctrl+E (inline code), Ctrl+K
  (link), Ctrl+Alt+0 to 3 (normal, headings), Ctrl+Shift+7/8/9 (numbers, bullets, checklist),
  Tab and Shift+Tab (indent), Ctrl+Z and Ctrl+Y or Ctrl+Shift+Z (undo, redo), Ctrl+S (save).
- Pasted content is read as HTML through an allow list that only produces the document format
  (no raw HTML is ever inserted or stored); anything else is pasted as plain text.
- How it works: the document is the source of truth. `richNoteHtml.ts` draws it as editor
  markup and reads the markup back after each keystroke; formatting, Enter, Backspace at a line
  start, paste and undo are operations on the document (`richNoteEdit.ts`). Copying puts plain
  text on the clipboard; a copy pasted back into a note keeps its formatting from memory.
- The note is stored in the entry's `fourthValue` (`save_note` takes `rich`; leaving it out keeps
  what the note had). Links open only through `open_note_link`, which checks the address again
  and opens web and mail links only, after the person confirms.

## Security

- Notes stay vault data: the document only lives inside the encrypted entry, the same way the
  text always has. Nothing is written to logs, caches or temporary files.
- Copying a note from the view marks the clip sensitive on Android (it is kept out of
  clipboard history previews), like other vault copies.
- Links never open on their own, are limited to safe schemes and show the full address first.
- Imported and pasted rich content is rebuilt through the document model, which is the only
  thing rendered; the PC never renders stored HTML.

## Testing

- Format tests on both apps: encode and decode, limits, sanitizing, plain fallback, hash and
  divergence check, migration of plain notes, and the merge helper.
- Shared fixtures in `docs/rich-notes/fixtures.json` are read by both test suites (Kotlin, the
  Windows `npm test` and a Rust vault test), so the apps agree on the format: both encode each
  fixture to the same bytes and apply the same link rules. Keep the file identical in both repos.
- Round trip Android → Windows → Android: the Windows tests load each fixture as Android wrote
  it, draw it in the editor's markup, read it back and save it, and check that the saved text and
  JSON are byte-identical to what Android wrote, for every mark, color, list, checklist, table
  and divider.
