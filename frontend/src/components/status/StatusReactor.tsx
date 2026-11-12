import { ticksPath } from "../charts/geometry";
import type { Tone } from "../StatusBadge";

const OUTER_TICKS = ticksPath(80, 80, 67, 75, 60);
const INNER_TICKS = ticksPath(80, 80, 49, 54, 24);

const TONES: Record<Tone, { stroke: string; wash: string }> = {
  ok: { stroke: "stroke-ok", wash: "fill-ok/10" },
  warn: { stroke: "stroke-warn", wash: "fill-warn/10" },
  bad: { stroke: "stroke-bad", wash: "fill-bad/10" },
  neutral: { stroke: "stroke-cipher", wash: "fill-cipher/10" },
};

/** The mark in the core differs by state, so the state is never carried by colour alone. */
const CORE_MARKS: Record<Tone, string> = {
  ok: "M64 82 76 94 98 66",
  warn: "M80 62V84M80 96V98",
  bad: "M66 66 94 94M94 66 66 94",
  neutral: "M64 80h1M80 80h1M96 80h1",
};

interface StatusReactorProps {
  tone: Tone;
  /** Turns the rings while a check is running or the system is healthy. */
  spinning?: boolean;
  className?: string;
}

/** A reactor-style ring that shows the overall state. Decorative: the state is also written out. */
export default function StatusReactor({ tone, spinning = false, className = "size-44" }: StatusReactorProps) {
  const { stroke, wash } = TONES[tone];
  return (
    <svg viewBox="0 0 160 160" fill="none" aria-hidden="true" focusable="false" className={className}>
      <circle cx="80" cy="80" r="42" className={wash} />
      <g className={spinning ? "origin-center animate-orbit" : undefined}>
        <circle cx="80" cy="80" r="77" className="stroke-ink-600" strokeWidth="1" />
        <path d={OUTER_TICKS} className={stroke} strokeWidth="1.4" />
      </g>
      <g className={spinning ? "origin-center animate-orbit-reverse" : undefined}>
        <circle
          cx="80"
          cy="80"
          r="59"
          className={stroke}
          strokeWidth="1.6"
          strokeDasharray="24 12"
          strokeLinecap="round"
          opacity="0.75"
        />
        <path d={INNER_TICKS} className="stroke-ink-400" strokeWidth="1" />
      </g>
      <circle cx="80" cy="80" r="38" className={stroke} strokeWidth="2" />
      {tone === "ok" ? (
        <circle cx="80" cy="80" r="38" className={`origin-center animate-pulse-ring ${stroke}`} strokeWidth="1.4" />
      ) : null}
      <path d={CORE_MARKS[tone]} className={stroke} strokeWidth="5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
