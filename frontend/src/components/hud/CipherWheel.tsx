import { ticksPath } from "../charts/geometry";

const OUTER_TICKS = ticksPath(32, 32, 26, 30, 48);
const INNER_TICKS = ticksPath(32, 32, 19, 22, 24);

interface CipherWheelProps {
  className?: string;
  /** Rotates the two rings slowly in opposite directions. */
  spinning?: boolean;
}

/**
 * The CipherForge mark: a cipher wheel (two rings of tick marks) around a forged core.
 * It is decorative; callers put the product name next to it as text.
 */
export default function CipherWheel({ className = "size-8", spinning = false }: CipherWheelProps) {
  return (
    <svg viewBox="0 0 64 64" fill="none" aria-hidden="true" focusable="false" className={className}>
      <g className={spinning ? "origin-center animate-orbit" : undefined}>
        <circle cx="32" cy="32" r="30.5" className="stroke-cipher-deep" strokeWidth="1" />
        <path d={OUTER_TICKS} className="stroke-cipher" strokeWidth="1.2" />
      </g>
      <g className={spinning ? "origin-center animate-orbit-reverse" : undefined}>
        <circle
          cx="32"
          cy="32"
          r="16.5"
          className="stroke-arc"
          strokeWidth="1.6"
          strokeDasharray="14 7"
          strokeLinecap="round"
        />
        <path d={INNER_TICKS} className="stroke-arc" strokeWidth="1" opacity="0.7" />
      </g>
      <path
        d="M32 21.5 41.1 26.75v10.5L32 42.5l-9.1-5.25v-10.5L32 21.5Z"
        className="fill-cipher/15 stroke-cipher"
        strokeWidth="1.6"
        strokeLinejoin="round"
      />
      <path d="M32 27.5 36.2 32 32 36.5 27.8 32 32 27.5Z" className="fill-cipher" />
    </svg>
  );
}
