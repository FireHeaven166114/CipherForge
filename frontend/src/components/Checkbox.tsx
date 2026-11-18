import { useEffect, useRef } from "react";

interface CheckboxProps {
  checked: boolean;
  /** Shows a dash instead of a tick: some of what this box stands for is ticked, not all of it. */
  mixed?: boolean;
  /** Names the box for assistive technology. It has no visible label. */
  label: string;
  /** `range` is true when Shift was held, which asks for a run of boxes rather than just this one. */
  onToggle: (checked: boolean, range: boolean) => void;
}

/**
 * A tick box drawn to match the console. The real input lies over the drawing, invisible and a
 * comfortable size to hit, so the keyboard, assistive technology and the pointer all deal with an
 * ordinary checkbox.
 */
export default function Checkbox({ checked, mixed = false, label, onToggle }: CheckboxProps) {
  const input = useRef<HTMLInputElement>(null);

  // "Indeterminate" is a property of the element, not an attribute, so React cannot set it.
  useEffect(() => {
    if (input.current) input.current.indeterminate = mixed;
  }, [mixed]);

  return (
    <span className="relative inline-flex size-7 shrink-0 items-center justify-center">
      <input
        ref={input}
        type="checkbox"
        aria-label={label}
        checked={checked}
        onChange={(event) => {
          // React raises this from the click, so the click's modifier keys are still at hand.
          const { nativeEvent } = event;
          onToggle(event.target.checked, nativeEvent instanceof MouseEvent && nativeEvent.shiftKey);
        }}
        className="peer absolute inset-0 size-full cursor-pointer opacity-0"
      />
      <span
        aria-hidden="true"
        className="pointer-events-none flex size-4.5 items-center justify-center rounded border border-ink-400 bg-ink-950/70 text-void transition peer-hover:border-cipher peer-checked:border-cipher peer-checked:bg-cipher peer-indeterminate:border-cipher peer-indeterminate:bg-cipher peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-cipher"
      >
        <svg
          viewBox="0 0 16 16"
          fill="none"
          stroke="currentColor"
          strokeWidth="2.4"
          strokeLinecap="round"
          strokeLinejoin="round"
          focusable="false"
          className={`size-3 ${checked || mixed ? "" : "invisible"}`}
        >
          <path d={mixed ? "M4 8h8" : "m3.5 8.5 3 3 6-7"} />
        </svg>
      </span>
    </span>
  );
}
