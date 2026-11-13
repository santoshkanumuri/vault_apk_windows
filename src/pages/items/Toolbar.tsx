import { FolderPen, FolderPlus, Search, X } from "lucide-react";
import { IconButton } from "../../components/Button";
import type { VaultGroup } from "../../lib/api";
import type { SortMode } from "../../lib/entries";

export function FilterInput({ value, onChange, placeholder }: { value: string; onChange: (value: string) => void; placeholder: string }) {
  return (
    <label className="filter-input">
      <Search aria-hidden="true" />
      <span className="sr-only">{placeholder}</span>
      <input type="search" value={value} placeholder={placeholder} onChange={(event) => onChange(event.target.value)} onKeyDown={(event) => { if (event.key === "Escape" && value) { event.stopPropagation(); onChange(""); } }} spellCheck={false} autoComplete="off" />
      {value && <button type="button" className="filter-clear" aria-label="Clear filter" onClick={() => onChange("")}><X aria-hidden="true" /></button>}
    </label>
  );
}

export function FolderPicker({ folders, value, onChange, onNew, onEdit, allLabel }: { folders: VaultGroup[]; value: string; onChange: (id: string) => void; onNew: () => void; onEdit: () => void; allLabel: string }) {
  return (
    <div className="folder-picker">
      <label className="sr-only" htmlFor="folder-filter">Folder</label>
      <select id="folder-filter" className="input select select-compact" value={value} onChange={(event) => onChange(event.target.value)}>
        <option value="">{allLabel}</option>
        {folders.map((folder) => <option key={folder.id} value={folder.id}>{folder.name}</option>)}
      </select>
      {value ? <IconButton label="Edit folder" icon={FolderPen} onClick={onEdit} variant="secondary" /> : <IconButton label="New folder" icon={FolderPlus} onClick={onNew} variant="secondary" />}
    </div>
  );
}

export function SortPicker({ value, onChange, withFavorites = true }: { value: SortMode; onChange: (value: SortMode) => void; withFavorites?: boolean }) {
  return (
    <>
      <label className="sr-only" htmlFor="sort-mode">Sort</label>
      <select id="sort-mode" className="input select select-compact" value={value} onChange={(event) => onChange(event.target.value as SortMode)}>
        <option value="recent">Recent first</option>
        <option value="name">Name A–Z</option>
        {withFavorites && <option value="favorites">Favorites first</option>}
      </select>
    </>
  );
}
