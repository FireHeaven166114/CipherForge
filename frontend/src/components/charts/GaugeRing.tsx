import { CLASSIFICATION_META } from "../../features/intel/classification";
import type { Classification } from "../../types/intel";
import AnimatedNumber from "../hud/AnimatedNumber";
import { ticksPath } from "./geometry";

const DIAL = ticksPath(60, 60, 52, 56, 60);

interface GaugeRingProps {
  /** 0 to 100, or null when no provider answered and there is nothing to show. */
  score: number | null;
  /** The risk band, or null when there is no verdict. */
  band: Classification | null;
  label?: string;
  className?: string;
}

/** A ring that fills with the risk score, coloured and shaped by the risk band. */
export default function GaugeRing({ score, band, label = "Risk score", className = "size-44" }: GaugeRingProps) {
  const meta = band === null ? null : CLASSIFICATION_META[band];
  const share = score === null ? 0 : Math.min(1, Math.max(0, score / 100));
  const tone = meta === null ? "text-ink-300" : meta.text;

  return (
    <div className={`relative shrink-0 ${className}`}>
      <svg viewBox="0 0 120 120" aria-hidden="true" focusable="false" className="size-full">
        <path d={DIAL} className="stroke-ink-600" strokeWidth="1" />
        <g className="origin-center animate-orbit-reverse">
          <circle
            cx="60"
            cy="60"
            r="35"
            fill="none"
            strokeWidth="1.2"
            strokeDasharray="0.5 5"
            strokeLinecap="round"
            className="stroke-ink-400"
          />
        </g>
        <g transform="rotate(-90 60 60)">
          <circle cx="60" cy="60" r="44" fill="none" strokeWidth="8" className="stroke-ink-800" />
          {share > 0 ? (
            <circle
              cx="60"
              cy="60"
              r="44"
              fill="none"
              strokeWidth="8"
              strokeLinecap="round"
              pathLength={1}
              strokeDasharray={`${share} 1`}
              className={`${meta === null ? "stroke-cipher" : meta.stroke} animate-gauge`}
            />
          ) : null}
        </g>
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
        <span className="text-[0.6rem] font-semibold uppercase tracking-[0.18em] text-ink-300">{label}</span>
        {score === null ? (
          <span className="font-mono text-4xl font-bold text-ink-300">—</span>
        ) : (
          <AnimatedNumber value={score} className={`font-mono text-4xl font-bold ${tone}`} />
        )}
        <span className={`mt-0.5 text-xs font-semibold uppercase tracking-[0.12em] ${tone}`}>
          {meta === null ? (
            "Not assessed"
          ) : (
            <>
              <span aria-hidden="true">{meta.symbol} </span>
              {meta.label}
            </>
          )}
        </span>
      </div>
    </div>
  );
}
