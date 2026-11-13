import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";
import { Button } from "../components/Button";
import { Dialog } from "../components/Dialog";

export type ConfirmOptions = {
  title: string;
  message?: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
};

type ConfirmFn = (options: ConfirmOptions) => Promise<boolean>;
const ConfirmContext = createContext<ConfirmFn | null>(null);

/** In-app replacement for window.confirm. */
export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [options, setOptions] = useState<ConfirmOptions | null>(null);
  const resolver = useRef<((value: boolean) => void) | null>(null);

  const confirm = useCallback<ConfirmFn>((next) => new Promise<boolean>((resolve) => {
    resolver.current?.(false);
    resolver.current = resolve;
    setOptions(next);
  }), []);

  const finish = (value: boolean) => {
    resolver.current?.(value);
    resolver.current = null;
    setOptions(null);
  };

  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      <Dialog open={options !== null} title={options?.title ?? ""} description={options?.message} onClose={() => finish(false)} initialFocus="[data-confirm-default]"
        footer={<>
          <Button variant="ghost" onClick={() => finish(false)} data-confirm-default={options?.danger ? "" : undefined}>{options?.cancelLabel ?? "Cancel"}</Button>
          <Button variant={options?.danger ? "danger" : "primary"} onClick={() => finish(true)} data-confirm-default={options?.danger ? undefined : ""}>{options?.confirmLabel ?? "Confirm"}</Button>
        </>} />
    </ConfirmContext.Provider>
  );
}

export function useConfirm(): ConfirmFn {
  const context = useContext(ConfirmContext);
  if (!context) throw new Error("useConfirm outside ConfirmProvider");
  return context;
}
