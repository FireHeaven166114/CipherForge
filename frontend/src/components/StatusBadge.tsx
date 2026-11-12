import type { ReactNode } from "react";

export type Tone = "ok" | "warn" | "bad" | "neutral";

const TONE_STYLES: Record<Tone, { classes: string; symbol: string }> = {
  ok: { classes: "border-ok/60 cf-plate text-ok", symbol: "✓" },
  warn: { classes: "border-warn/60 cf-plate text-warn", symbol: "▲" },
  bad: { classes: "border-bad/60 cf-plate text-bad", symbol: "✕" },
  neutral: { classes: "border-ink-500 bg-ink-800/70 text-ink-200", symbol: "…" },
};

/** Status is always conveyed by a symbol and a text label, never by colour alone. */
export default function StatusBadge({ tone, children }: { tone: Tone; children: ReactNode }) {
  const { classes, symbol } = TONE_STYLES[tone];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-chip border px-2.5 py-1 text-xs font-semibold uppercase tracking-[0.12em] ${classes}`}
    >
      <span aria-hidden="true">{symbol}</span>
      {children}
    </span>
  );
}
