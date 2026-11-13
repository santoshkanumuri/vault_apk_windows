import { createContext, useContext } from "react";

export const SearchContext = createContext<() => void>(() => undefined);
/** Opens the global search palette (Ctrl+K). */
export const useOpenSearch = () => useContext(SearchContext);
