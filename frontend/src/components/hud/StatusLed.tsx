export type LedTone = "ok" | "warn" | "bad" | "idle" | "cipher";

const TONES: Record<LedTone, string> = {
  ok: "bg-ok shadow-[0_0_8px_1px_rgb(74_232_176/0.7)]",
  warn: "bg-warn shadow-[0_0_8px_1px_rgb(255_215_90/0.6)]",
  bad: "bg-bad shadow-[0_0_8px_1px_rgb(255_107_134/0.7)]",
  idle: "bg-ink-400",
  cipher: "bg-cipher shadow-[0_0_8px_1px_rgb(46_230_255/0.7)]",
};

/** A small glowing dot. It is decorative: the state is always also written out as text. */
export default function StatusLed({ tone, pulsing = false }: { tone: LedTone; pulsing?: boolean }) {
  return (
    <span
      aria-hidden="true"
      className={`inline-block size-2 shrink-0 rounded-full ${TONES[tone]} ${pulsing ? "animate-beacon" : ""}`}
    />
  );
}
