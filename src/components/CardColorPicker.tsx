import { useEffect, useRef, useState, type KeyboardEvent, type PointerEvent } from "react";
import { Check } from "lucide-react";
import { argbToHsv, css, hsvToArgb, inkFor, needsOutline, parseHex, toHex } from "../lib/cardColors";
import { TextField } from "./Field";
import { strings } from "../strings";

type Props = {
  /** Opaque ARGB, 0xFFRRGGBB. */
  value: number;
  onChange: (color: number) => void;
  /** Colors on the user's other cards, most used first. */
  used: number[];
  title: string;
  lastDigits: string;
};

/**
 * Any card color: a live card preview, a saturation and brightness square, a hue slider, an exact
 * #RRGGBB field, and the colors already on the user's other cards.
 */
export function CardColorPicker({ value, onChange, used, title, lastDigits }: Props) {
  // Hue is kept here, not derived from the color, so moving through grays and black keeps it.
  const [hsv, setHsv] = useState<[number, number, number]>(() => argbToHsv(value));
  const [hexText, setHexText] = useState(toHex(value));
  useEffect(() => {
    if (hsvToArgb(...hsv) !== value) setHsv(argbToHsv(value));
    setHexText(toHex(value));
  }, [value]); // eslint-disable-line react-hooks/exhaustive-deps

  const pick = (next: [number, number, number]) => {
    const clamped: [number, number, number] = [Math.min(360, Math.max(0, next[0])), Math.min(1, Math.max(0, next[1])), Math.min(1, Math.max(0, next[2]))];
    setHsv(clamped);
    onChange(hsvToArgb(...clamped));
  };

  const pad = useRef<HTMLDivElement>(null);
  const fromPointer = (event: PointerEvent<HTMLDivElement>) => {
    const box = pad.current?.getBoundingClientRect();
    if (!box) return;
    pick([hsv[0], (event.clientX - box.left) / box.width, 1 - (event.clientY - box.top) / box.height]);
  };
  const padKeys = (event: KeyboardEvent<HTMLDivElement>) => {
    const step = event.shiftKey ? 0.1 : 0.01;
    const moves: Record<string, [number, number]> = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, step], ArrowDown: [0, -step] };
    const move = moves[event.key];
    if (!move) return;
    event.preventDefault();
    pick([hsv[0], hsv[1] + move[0], hsv[2] + move[1]]);
  };

  const typedValid = parseHex(hexText) !== null;
  const hueColor = css(hsvToArgb(hsv[0], 1, 1));
  const ink = inkFor(value);
  return (
    <div className="color-picker">
      <span className="color-picker-label">{strings.cardColor}</span>
      <div className={"color-preview" + (needsOutline(value) ? " outlined" : "")} style={{ background: css(value), color: ink }} aria-hidden="true">
        <strong>{title.trim() || "Card"}</strong>
        <span className="mono">{lastDigits ? `•••• ${lastDigits}` : "•••• ••••"}</span>
      </div>
      <div
        ref={pad}
        className="color-pad"
        role="group"
        tabIndex={0}
        aria-label={`Saturation and brightness. Saturation ${Math.round(hsv[1] * 100)} percent, brightness ${Math.round(hsv[2] * 100)} percent. Use the arrow keys.`}
        onPointerDown={(event) => { event.currentTarget.setPointerCapture(event.pointerId); fromPointer(event); }}
        onPointerMove={(event) => { if (event.currentTarget.hasPointerCapture(event.pointerId)) fromPointer(event); }}
        onKeyDown={padKeys}
      >
        {/* The rounded gradient is its own layer: rounded corners would otherwise not take clicks,
            and the corners hold white, the full color and black. */}
        <span className="color-pad-fill" style={{ backgroundColor: hueColor }} aria-hidden="true" />
        <span className="color-pad-marker" style={{ left: `${hsv[1] * 100}%`, top: `${(1 - hsv[2]) * 100}%`, background: css(value) }} />
      </div>
      <input
        className="color-hue"
        type="range"
        min={0}
        max={360}
        step={1}
        value={Math.round(hsv[0])}
        aria-label={strings.hue}
        aria-valuetext={`${Math.round(hsv[0])} degrees`}
        style={{ ["--hue-thumb" as string]: hueColor }}
        onChange={(event) => pick([Number(event.target.value), hsv[1], hsv[2]])}
      />
      <div className="color-hex-row">
        <span className={"color-dot" + (needsOutline(value) ? " outlined" : "")} style={{ background: css(value) }} aria-hidden="true" />
        <TextField
          label={strings.hex}
          value={hexText}
          className="mono"
          spellCheck={false}
          autoComplete="off"
          maxLength={7}
          error={!typedValid && hexText.length > 1 ? "Use 6 hex digits, 0 to 9 and A to F." : undefined}
          hint={typedValid || hexText.length <= 1 ? "Any color, for example #2E7034." : undefined}
          onValue={(typed) => {
            const cleaned = "#" + typed.replace(/^#/, "").replace(/[^0-9a-fA-F]/g, "").slice(0, 6).toUpperCase();
            setHexText(cleaned);
            const exact = parseHex(cleaned);
            if (exact !== null && (cleaned.length === 7 || cleaned.length === 4)) { setHsv(argbToHsv(exact)); onChange(exact); }
          }}
        />
      </div>
      {used.length > 0 && (
        <div className="color-used">
          <span className="color-picker-label">{strings.onYourOtherCards}</span>
          <div className="swatch-grid" role="radiogroup" aria-label={strings.colorsOnYourOtherCards}>
            {used.map((color) => {
              const selected = color === value;
              return (
                <button key={color} type="button" role="radio" aria-checked={selected} aria-label={toHex(color)} title={toHex(color)}
                  className={"swatch" + (selected ? " is-selected" : "")} onClick={() => { setHsv(argbToHsv(color)); onChange(color); }}>
                  <span className={"swatch-dot" + (needsOutline(color) ? " outlined" : "")} style={{ background: css(color), color: inkFor(color) }}>
                    {selected && <Check aria-hidden="true" />}
                  </span>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
