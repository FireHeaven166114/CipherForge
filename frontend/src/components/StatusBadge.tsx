import type { ReactNode } from "react";

export type Tone = "ok" | "warn" | "bad" | "neutral";

const TONE_STYLES: Record<Tone, { classes: string; symbol: string }> = {
  ok: { classes: "border-emerald-700 bg-emerald-950 text-emerald-200", symbol: "✓" },
  warn: { classes: "border-amber-700 bg-amber-950 text-amber-200", symbol: "▲" },
  bad: { classes: "border-red-700 bg-red-950 text-red-200", symbol: "✕" },
  neutral: { classes: "border-slate-600 bg-slate-800 text-slate-200", symbol: "…" },
};

/** Status is always conveyed by a symbol and a text label, never by colour alone. */
export default function StatusBadge({ tone, children }: { tone: Tone; children: ReactNode }) {
  const { classes, symbol } = TONE_STYLES[tone];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-sm font-medium ${classes}`}
    >
      <span aria-hidden="true">{symbol}</span>
      {children}
    </span>
  );
}
