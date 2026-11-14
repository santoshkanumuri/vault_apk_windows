import { useRef, type KeyboardEvent, type ReactNode } from "react";
import { Check } from "lucide-react";
import { accentChoices, surfaceChoices, type ResolvedTheme } from "../app/theme";

type Choice = { id: string; name: string };

/** A radio group with a roving tab stop: arrows move and select, Enter and Space select. */
function RadioGrid<T extends Choice>({ label, items, value, onSelect, render, className }: {
  label: string; items: readonly T[]; value: string; onSelect: (id: string) => void;
  render: (item: T, selected: boolean) => ReactNode; className: string;
}) {
  const refs = useRef<Array<HTMLButtonElement | null>>([]);
  const selectedIndex = Math.max(0, items.findIndex((item) => item.id === value));

  const move = (event: KeyboardEvent, index: number) => {
    const last = items.length - 1;
    let next = index;
    if (event.key === "ArrowRight" || event.key === "ArrowDown") next = index === last ? 0 : index + 1;
    else if (event.key === "ArrowLeft" || event.key === "ArrowUp") next = index === 0 ? last : index - 1;
    else if (event.key === "Home") next = 0;
    else if (event.key === "End") next = last;
    else return;
    event.preventDefault();
    refs.current[next]?.focus();
    onSelect(items[next].id);
  };

  return (
    <div className={className} role="radiogroup" aria-label={label}>
      {items.map((item, index) => {
        const selected = item.id === value;
        return (
          <button key={item.id} type="button" role="radio" aria-checked={selected} aria-label={item.name} title={item.name}
            tabIndex={index === selectedIndex ? 0 : -1} ref={(node) => { refs.current[index] = node; }}
            className={selected ? "swatch is-selected" : "swatch"} onClick={() => onSelect(item.id)} onKeyDown={(event) => move(event, index)}>
            {render(item, selected)}
          </button>
        );
      })}
    </div>
  );
}

export function AccentPicker({ value, onSelect }: { value: string; onSelect: (id: string) => void }) {
  return (
    <RadioGrid label="Accent color" className="swatch-grid" items={accentChoices} value={value} onSelect={onSelect}
      render={(item, selected) => (
        <span className="swatch-dot" style={{ background: item.swatch }}>{selected && <Check aria-hidden="true" />}</span>
      )} />
  );
}

export function SurfacePicker({ value, accent, mode, onSelect }: { value: string; accent: string; mode: ResolvedTheme; onSelect: (id: string) => void }) {
  const colors = accentChoices.find((item) => item.id === accent)?.[mode];
  return (
    <RadioGrid label="Background" className="swatch-grid swatch-grid-tiles" items={surfaceChoices} value={value} onSelect={onSelect}
      render={(item, selected) => (
        <span className="swatch-tile" style={{ background: item[mode].background, borderColor: item[mode].hairline }}>
          <span className="swatch-tile-card" style={{ background: item[mode].container }} />
          <span className="swatch-tile-dot" style={{ background: colors?.primary }}>
            {selected && <Check aria-hidden="true" style={{ color: colors?.onPrimary }} />}
          </span>
        </span>
      )} />
  );
}

/** Live preview: a primary button, a line of text and a chip. Uses the page's current tokens. */
export function AppearancePreview() {
  return (
    <div className="appearance-preview" aria-hidden="true">
      <span className="appearance-preview-button">Unlock</span>
      <span className="appearance-preview-text">Sample text on this background</span>
      <span className="appearance-preview-chip">Chip</span>
    </div>
  );
}
