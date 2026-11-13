import type { ComponentPropsWithRef, ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { cx } from "../lib/format";
import { Spinner } from "./Spinner";

type Variant = "primary" | "secondary" | "ghost" | "danger" | "tonal";

type ButtonProps = ComponentPropsWithRef<"button"> & {
  variant?: Variant;
  size?: "sm" | "md" | "lg";
  icon?: LucideIcon;
  trailingIcon?: LucideIcon;
  busy?: boolean;
  block?: boolean;
  children?: ReactNode;
};

export function Button({ variant = "secondary", size = "md", icon: Icon, trailingIcon: Trailing, busy, block, className, children, type = "button", disabled, ...rest }: ButtonProps) {
  return (
    <button {...rest} type={type} disabled={disabled || busy} aria-busy={busy || undefined} className={cx("btn", `btn-${variant}`, size !== "md" && `btn-${size}`, block && "btn-block", className)}>
      {busy ? <Spinner size={16} /> : Icon && <Icon aria-hidden="true" />}
      {children !== undefined && <span>{children}</span>}
      {Trailing && <Trailing aria-hidden="true" className="btn-trailing" />}
    </button>
  );
}

type IconButtonProps = Omit<ComponentPropsWithRef<"button">, "children"> & {
  label: string;
  icon: LucideIcon;
  variant?: "ghost" | "secondary" | "primary" | "danger";
  size?: "sm" | "md";
  busy?: boolean;
  tooltip?: boolean;
};

export function IconButton({ label, icon: Icon, variant = "ghost", size = "md", busy, tooltip = true, className, type = "button", disabled, ...rest }: IconButtonProps) {
  return (
    <button {...rest} type={type} aria-label={label} title={tooltip ? label : undefined} disabled={disabled || busy} className={cx("icon-btn", `icon-btn-${variant}`, size === "sm" && "icon-btn-sm", className)}>
      {busy ? <Spinner size={16} /> : <Icon aria-hidden="true" />}
    </button>
  );
}
