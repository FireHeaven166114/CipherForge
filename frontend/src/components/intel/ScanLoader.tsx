import LoadingNote from "../LoadingNote";

const RINGS = [14, 26, 38, 50] as const;

/** A radar that sweeps while the providers are asked. It shows waiting, not progress. */
export default function ScanLoader({ indicator }: { indicator: string }) {
  return (
    <div className="hud-panel relative flex flex-wrap items-center gap-6 overflow-hidden rounded-[3px] p-5">
      <svg viewBox="0 0 120 120" aria-hidden="true" focusable="false" className="size-28 shrink-0">
        {RINGS.map((radius) => (
          <circle key={radius} cx="60" cy="60" r={radius} fill="none" strokeWidth="1" className="stroke-ink-600" />
        ))}
        <path d="M60 8V112M8 60H112" strokeWidth="1" className="stroke-ink-700" />
        <g className="origin-center animate-sweep">
          <path d="M60 60 60 8A52 52 0 0 1 93.4 20.2Z" className="fill-cipher/20" />
          <path d="M60 60 93.4 20.2" strokeWidth="1.4" strokeLinecap="round" className="stroke-cipher" />
        </g>
        <circle cx="60" cy="60" r="3" className="fill-cipher" />
      </svg>
      <div className="min-w-0 flex-1 space-y-1.5">
        <LoadingNote>
          Asking the providers about {indicator}. This can take up to 30 seconds.
        </LoadingNote>
        <p className="text-xs text-ink-300">
          Each provider is asked separately. Nothing is shown until their answers arrive.
        </p>
      </div>
    </div>
  );
}
