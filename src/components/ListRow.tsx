import { useEffect, useMemo, useRef, type ReactNode } from "react";
import { ChevronRight, Star } from "lucide-react";
import { cx } from "../lib/format";

type ListRowProps = {
  id: string;
  title: ReactNode;
  subtitle?: ReactNode;
  leading?: ReactNode;
  favorite?: boolean;
  onOpen: () => void;
  /** Quick actions, shown on hover or keyboard focus. */
  actions?: ReactNode;
  trailing?: ReactNode;
  highlighted?: boolean;
  /** Animate in: the row was just added while the list was showing. */
  entering?: boolean;
  openLabel?: string;
  chevron?: boolean;
};

export function ListRow({ id, title, subtitle, leading, favorite, onOpen, actions, trailing, highlighted, entering, openLabel, chevron = true }: ListRowProps) {
  return (
    <li className={cx("list-row", highlighted && "is-highlighted", entering && "is-entering")} data-row-id={id}>
      <button type="button" className="list-row-main" onClick={onOpen} aria-label={openLabel}>
        {leading}
        <span className="list-row-text">
          <span className="list-row-title">
            <span className="truncate">{title}</span>
            {favorite && <Star className="fav-star" aria-label="Favorite" />}
          </span>
          {subtitle && <span className="list-row-subtitle truncate">{subtitle}</span>}
        </span>
      </button>
      {actions && <div className="list-row-actions">{actions}</div>}
      {trailing}
      {chevron && <ChevronRight className="list-row-chevron" aria-hidden="true" />}
    </li>
  );
}

/** Ids that appeared since the previous render (never on first render), for a cheap insert animation. */
export function useNewIds(ids: string[]): Set<string> {
  const previous = useRef<Set<string> | null>(null);
  const key = ids.join("|");
  const fresh = useMemo(() => {
    const before = previous.current;
    return before ? new Set(ids.filter((id) => !before.has(id))) : new Set<string>();
  }, [key]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => { previous.current = new Set(ids); }, [key]); // eslint-disable-line react-hooks/exhaustive-deps
  return fresh;
}
