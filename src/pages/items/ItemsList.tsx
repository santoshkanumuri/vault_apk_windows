import { useMemo, useState } from "react";
import { CreditCard, List, Plus, SearchX } from "lucide-react";
import { Button } from "../../components/Button";
import { CardFace } from "../../components/CardFace";
import { Avatar, EmptyState } from "../../components/Display";
import { Segmented } from "../../components/Field";
import { ListRow, useNewIds } from "../../components/ListRow";
import { Spinner } from "../../components/Spinner";
import { useRouteState, useRouter } from "../../app/router";
import { useVault } from "../../app/vault";
import type { VaultGroup } from "../../lib/api";
import { categories, foldersFor, sortItems, type Category, type SortMode } from "../../lib/entries";
import { iconHints } from "../../lib/siteIcons";
import { cx, plural } from "../../lib/format";
import { buildIndex, matchesFilter } from "../../lib/search";
import { FolderDialog } from "../FolderDialog";
import { EntryQuickActions } from "./actions";
import { FilterInput, FolderPicker, SortPicker } from "./Toolbar";
import { codeText, strings } from "../../strings";

export function ItemsListPage({ category }: { category: Exclude<Category, "codes"> }) {
  const info = categories[category];
  const { entries, groups, passkeyIds, loaded } = useVault();
  const router = useRouter();
  const [filter, setFilter] = useRouteState("filter", "");
  const [folderId, setFolderId] = useRouteState("folder", "");
  const [sort, setSort] = useRouteState<SortMode>("sort", "recent");
  // Cards show as a wallet of card faces by default; the compact list stays one click away.
  const [view, setView] = useRouteState<"cards" | "list">("view", "cards");
  const wallet = info.type === "CARD" && view === "cards";
  const [folderDialog, setFolderDialog] = useState<{ folder: VaultGroup | null } | null>(null);

  const folders = foldersFor(groups, info.type);
  const ofType = useMemo(() => entries.filter((entry) => entry.type === info.type), [entries, info.type]);
  const docs = useMemo(() => buildIndex(ofType, []), [ofType]);
  const subtitles = useMemo(() => new Map(docs.map((doc) => [doc.id, doc.subtitle])), [docs]);
  const visible = useMemo(() => {
    const matched = docs.filter((doc) => doc.kind === "entry" && (!folderId || doc.entry.groupIds?.includes(folderId)) && matchesFilter(doc, filter));
    return sortItems(matched.map((doc) => doc.kind === "entry" ? doc.entry : null).filter((entry) => entry !== null), sort);
  }, [docs, folderId, filter, sort]);

  const fresh = useNewIds(visible.map((entry) => entry.id));
  const add = () => void router.navigate({ page: "edit", category });

  return (
    <div className="page">
      <div className="toolbar">
        <FilterInput value={filter} onChange={setFilter} placeholder={codeText.filter(info.label.toLowerCase())} />
        <div className="toolbar-group">
          <FolderPicker folders={folders} value={folderId} onChange={setFolderId} allLabel={codeText.allFolders}
            onNew={() => setFolderDialog({ folder: null })}
            onEdit={() => setFolderDialog({ folder: folders.find((folder) => folder.id === folderId) ?? null })} />
          <SortPicker value={sort} onChange={setSort} />
          <Button variant="primary" icon={Plus} onClick={add} className="toolbar-add">{codeText.add(info.singular)}</Button>
        </div>
      </div>

      {!loaded ? <div className="card card-padded center"><Spinner label={strings.loading} /></div>
        : ofType.length === 0 ? (
          <div className="card"><EmptyState icon={info.icon} title={codeText.noYet(info.label.toLowerCase())} body={codeText.addYourFirstToKeepIt(info.singular)} action={<Button variant="primary" icon={Plus} onClick={add}>{codeText.add(info.singular)}</Button>} /></div>
        ) : visible.length === 0 ? (
          <div className="card"><EmptyState icon={SearchX} title={strings.noMatches} body={codeText.tryAnotherWordOrClearThe} action={<Button onClick={() => { setFilter(""); setFolderId(""); }}>{strings.clearFilters}</Button>} /></div>
        ) : (
          <>
            <div className="list-head">
              <p className="list-count">{plural(visible.length, info.singular)}{visible.length !== ofType.length ? codeText.of(ofType.length) : ""}</p>
              {info.type === "CARD" && <Segmented label={strings.view} size="sm" value={view} onChange={setView}
                options={[{ value: "cards", label: codeText.cards, icon: CreditCard }, { value: "list", label: codeText.list, icon: List }]} />}
            </div>
            {wallet ? (
              <ul className="card-grid" aria-label={info.label}>
                {visible.map((entry) => (
                  <li key={entry.id} className={cx("card-grid-item", router.highlight === entry.id && "is-highlighted")} data-row-id={entry.id}>
                    <CardFace entry={entry} onOpen={() => void router.navigate({ page: "item", id: entry.id })} />
                    <div className="card-grid-actions"><EntryQuickActions entry={entry} /></div>
                  </li>
                ))}
              </ul>
            ) : (
            <ul className="card list" aria-label={info.label}>
              {visible.map((entry) => {
                const subtitle = subtitles.get(entry.id);
                return (
                  <ListRow key={entry.id} id={entry.id} title={entry.title || codeText.untitled} subtitle={subtitle} favorite={entry.favorite}
                    passkey={entry.type === "PASSWORD" && passkeyIds.has(entry.id)}
                    leading={<Avatar title={entry.title || info.label} cardColor={entry.type === "CARD" ? entry.color : undefined} {...iconHints(entry, entries)} />}
                    highlighted={router.highlight === entry.id}
                    entering={fresh.has(entry.id)}
                    openLabel={codeText.open2(entry.title)}
                    onOpen={() => void router.navigate({ page: "item", id: entry.id })}
                    actions={<EntryQuickActions entry={entry} />} />
                );
              })}
            </ul>
            )}
          </>
        )}

      <FolderDialog open={folderDialog !== null} folder={folderDialog?.folder} onClose={() => setFolderDialog(null)} scope={info.type} scopeLabel={info.label}
        onSaved={(folder) => { if (!folderDialog?.folder) setFolderId(folder.id); }}
        onDeleted={(id) => { if (folderId === id) setFolderId(""); }} />
    </div>
  );
}
