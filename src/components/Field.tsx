import { useEffect, useId, useState, type ComponentPropsWithRef, type ComponentType, type KeyboardEvent, type ReactNode } from "react";
import { Eye, EyeOff, TriangleAlert } from "lucide-react";
import { cx } from "../lib/format";

type FieldShellProps = { label: string; hint?: ReactNode; error?: string; id: string; children: ReactNode; className?: string; trailing?: ReactNode };

function FieldShell({ label, hint, error, id, children, className, trailing }: FieldShellProps) {
  return (
    <div className={cx("field", error && "has-error", className)}>
      <div className="field-label-row">
        <label htmlFor={id}>{label}</label>
        {trailing}
      </div>
      {children}
      {error ? <p className="field-error" id={`${id}-error`}>{error}</p> : hint ? <p className="field-hint" id={`${id}-hint`}>{hint}</p> : null}
    </div>
  );
}

type TextFieldProps = Omit<ComponentPropsWithRef<"input">, "onChange"> & { label: string; hint?: ReactNode; error?: string; onValue?: (value: string) => void; onChange?: ComponentPropsWithRef<"input">["onChange"]; trailing?: ReactNode; fieldClassName?: string };

export function TextField({ label, hint, error, id, onValue, onChange, trailing, fieldClassName, ...rest }: TextFieldProps) {
  const auto = useId();
  const fieldId = id ?? auto;
  return (
    <FieldShell label={label} hint={hint} error={error} id={fieldId} trailing={trailing} className={fieldClassName}>
      <input {...rest} id={fieldId} className={cx("input", rest.className)} aria-invalid={error ? true : undefined} aria-describedby={error ? `${fieldId}-error` : hint ? `${fieldId}-hint` : undefined}
        onChange={(event) => { onChange?.(event); onValue?.(event.target.value); }} />
    </FieldShell>
  );
}

type TextAreaProps = Omit<ComponentPropsWithRef<"textarea">, "onChange"> & { label: string; hint?: ReactNode; error?: string; onValue: (value: string) => void; fieldClassName?: string };

export function TextArea({ label, hint, error, id, onValue, fieldClassName, rows = 4, ...rest }: TextAreaProps) {
  const auto = useId();
  const fieldId = id ?? auto;
  return (
    <FieldShell label={label} hint={hint} error={error} id={fieldId} className={fieldClassName}>
      <textarea {...rest} rows={rows} id={fieldId} className={cx("input", "textarea", rest.className)} aria-invalid={error ? true : undefined} onChange={(event) => onValue(event.target.value)} />
    </FieldShell>
  );
}

type SelectFieldProps = Omit<ComponentPropsWithRef<"select">, "onChange"> & { label: string; hint?: ReactNode; onValue: (value: string) => void; options: ReadonlyArray<{ value: string; label: string }>; fieldClassName?: string };

export function SelectField({ label, hint, id, onValue, options, fieldClassName, ...rest }: SelectFieldProps) {
  const auto = useId();
  const fieldId = id ?? auto;
  return (
    <FieldShell label={label} hint={hint} id={fieldId} className={fieldClassName}>
      <select {...rest} id={fieldId} className={cx("input", "select", rest.className)} onChange={(event) => onValue(event.target.value)}>
        {options.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
      </select>
    </FieldShell>
  );
}

type PasswordInputProps = Omit<ComponentPropsWithRef<"input">, "type"> & { label: string; capsLockWarning?: boolean; revealable?: boolean };

/** Password input with a reveal toggle and an optional Caps Lock warning. Reveal resets when cleared or disabled. */
export function PasswordInput({ label, capsLockWarning, revealable = true, className, ...props }: PasswordInputProps) {
  const [visible, setVisible] = useState(false);
  const [caps, setCaps] = useState(false);
  useEffect(() => { if (props.value === "" || props.disabled) setVisible(false); }, [props.value, props.disabled]);
  const checkCaps = (event: KeyboardEvent<HTMLInputElement>) => {
    if (capsLockWarning && typeof event.getModifierState === "function") setCaps(event.getModifierState("CapsLock"));
  };
  return (
    <>
      <div className="secret-input">
        <input {...props} className={cx("input", className)} type={visible && !props.disabled ? "text" : "password"} spellCheck={false}
          onKeyDown={(event) => { checkCaps(event); props.onKeyDown?.(event); }}
          onKeyUp={(event) => { checkCaps(event); props.onKeyUp?.(event); }}
          onBlur={(event) => { setCaps(false); props.onBlur?.(event); }} />
        {revealable && <button className="secret-toggle" type="button" disabled={props.disabled} aria-label={`${visible ? "Hide" : "Show"} ${label}`} title={visible ? "Hide" : "Show"} aria-pressed={visible} aria-controls={props.id} onClick={() => setVisible((current) => !current)}>
          {visible ? <EyeOff aria-hidden="true" /> : <Eye aria-hidden="true" />}
        </button>}
      </div>
      {capsLockWarning && caps && <p className="caps-warning" role="status"><TriangleAlert aria-hidden="true" /> Caps Lock is on</p>}
    </>
  );
}

type PasswordFieldProps = PasswordInputProps & { hint?: ReactNode; error?: string; fieldClassName?: string; trailing?: ReactNode; onValue?: (value: string) => void };

export function PasswordField({ label, hint, error, id, fieldClassName, trailing, onValue, onChange, ...rest }: PasswordFieldProps) {
  const auto = useId();
  const fieldId = id ?? auto;
  return (
    <FieldShell label={label} hint={hint} error={error} id={fieldId} className={fieldClassName} trailing={trailing}>
      <PasswordInput {...rest} id={fieldId} label={label.toLowerCase()} aria-invalid={error ? true : undefined}
        onChange={(event) => { onChange?.(event); onValue?.(event.target.value); }} />
    </FieldShell>
  );
}

export function Toggle({ checked, onChange, label, disabled, id, describedBy }: { checked: boolean; onChange: (value: boolean) => void; label: string; disabled?: boolean; id?: string; describedBy?: string }) {
  return (
    <button type="button" role="switch" id={id} aria-checked={checked} aria-label={label} aria-describedby={describedBy} disabled={disabled} className={cx("switch", checked && "is-on")} onClick={() => onChange(!checked)}>
      <span className="switch-thumb" aria-hidden="true" />
    </button>
  );
}

export function Checkbox({ checked, onChange, label, disabled }: { checked: boolean; onChange: (value: boolean) => void; label: ReactNode; disabled?: boolean }) {
  return (
    <label className="checkbox">
      <input type="checkbox" checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} />
      <span>{label}</span>
    </label>
  );
}

export function Segmented<T extends string>({ value, onChange, options, label, size }: { value: T; onChange: (value: T) => void; options: ReadonlyArray<{ value: T; label: string; icon?: ComponentType<{ "aria-hidden"?: boolean | "true" }> }>; label: string; size?: "sm" }) {
  return (
    <div className={cx("segmented", size === "sm" && "segmented-sm")} role="radiogroup" aria-label={label}>
      {options.map(({ value: optionValue, label: optionLabel, icon: Icon }) => (
        <button key={optionValue} type="button" role="radio" aria-checked={value === optionValue} className={cx(value === optionValue && "is-selected")} onClick={() => onChange(optionValue)}>
          {Icon && <Icon aria-hidden="true" />}<span>{optionLabel}</span>
        </button>
      ))}
    </div>
  );
}
