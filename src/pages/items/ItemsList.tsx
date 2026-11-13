import { useMemo, useState } from "react";
import { Plus, SearchX } from "lucide-react";
import { Button } from "../../components/Button";
import { Avatar, EmptyState } from "../../components/Display";
import { ListRow, useNewIds } from "../../components/ListRow";
import { Spinner } from "../../components/Spinner";
import { useRouteState, useRouter } from "../../app/router";
import { useVault } from "../../app/vault";
import type { VaultGroup } from "../../lib/api";
import { categories, foldersFor, sortItems, type Category, type SortMode } from "../../lib/entries";
import { plural } from "../../lib/format";
import { buildIndex, matchesFilter } from "../../lib/search";
import { FolderDialog } from "../FolderDialog";
import { EntryQuickActions } from "./actions";
import { FilterInput, FolderPicker, SortPicker } from "./Toolbar";

export function ItemsListPage({ category }: { category: Exclude<Category, "codes"> }) {
  const info = categories[category];
  const { entries, groups, loaded } = useVault();
  const router = useRouter();
  const [filter, setFilter] = useRouteState("filter", "");
  const [folderId, setFolderId] = useRouteState("folder", "");
  const [sort, setSort] = useRouteState<SortMode>("sort", "recent");
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
        <FilterInput value={filter} onChange={setFilter} placeholder={`Filter ${info.label.toLowerCase()}`} />
        <div className="toolbar-group">
          <FolderPicker folders={folders} value={folderId} onChange={setFolderId} allLabel="All folders"
            onNew={() => setFolderDialog({ folder: null })}
            onEdit={() => setFolderDialog({ folder: folders.find((folder) => folder.id === folderId) ?? null })} />
          <SortPicker value={sort} onChange={setSort} />
          <Button variant="primary" icon={Plus} onClick={add} className="toolbar-add">Add {info.singular}</Button>
        </div>
      </div>

      {!loaded ? <div className="card card-padded center"><Spinner label="Loading" /></div>
        : ofType.length === 0 ? (
          <div className="card"><EmptyState icon={info.icon} title={`No ${info.label.toLowerCase()} yet`} body={`Add your first ${info.singular} to keep it in your encrypted vault.`} action={<Button variant="primary" icon={Plus} onClick={add}>Add {info.singular}</Button>} /></div>
        ) : visible.length === 0 ? (
          <div className="card"><EmptyState icon={SearchX} title="No matches" body="Try another word, or clear the folder filter." action={<Button onClick={() => { setFilter(""); setFolderId(""); }}>Clear filters</Button>} /></div>
        ) : (
          <>
            <p className="list-count">{plural(visible.length, info.singular)}{visible.length !== ofType.length ? ` of ${ofType.length}` : ""}</p>
            <ul className="card list" aria-label={info.label}>
              {visible.map((entry) => {
                const subtitle = subtitles.get(entry.id);
                return (
                  <ListRow key={entry.id} id={entry.id} title={entry.title || "Untitled"} subtitle={subtitle} favorite={entry.favorite}
                    leading={<Avatar title={entry.title || info.label} />}
                    highlighted={router.highlight === entry.id}
                    entering={fresh.has(entry.id)}
                    openLabel={`Open ${entry.title}`}
                    onOpen={() => void router.navigate({ page: "item", id: entry.id })}
                    actions={<EntryQuickActions entry={entry} />} />
                );
              })}
            </ul>
          </>
        )}

      <FolderDialog open={folderDialog !== null} folder={folderDialog?.folder} onClose={() => setFolderDialog(null)} scope={info.type} scopeLabel={info.label}
        onSaved={(folder) => { if (!folderDialog?.folder) setFolderId(folder.id); }}
        onDeleted={(id) => { if (folderId === id) setFolderId(""); }} />
    </div>
  );
}
