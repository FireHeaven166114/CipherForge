import type { ReactNode } from "react";

export type NoticeTone = "info" | "warn" | "bad";

interface ToneStyle {
  box: string;
  title: string;
  symbol: string;
}

// Written out in full, so the build finds every class.
const TONES: Readonly<Record<NoticeTone, ToneStyle>> = {
  info: { box: "border-cipher/40 [--plate:var(--color-cipher)]", title: "text-cipher", symbol: "◆" },
  warn: { box: "border-warn/50 [--plate:var(--color-warn)]", title: "text-warn", symbol: "▲" },
  bad: { box: "border-bad/60 [--plate:var(--color-bad)]", title: "text-bad", symbol: "✕" },
};

interface NoticeProps {
  tone: NoticeTone;
  title: string;
  /** "alert" is read out at once: use it for a failure the analyst has just met. */
  role?: "note" | "alert";
  className?: string;
  children?: ReactNode;
}

/** A note beside the data. Its tone is a symbol and a word as well as a colour. */
export default function Notice({ tone, title, role = "note", className = "", children }: NoticeProps) {
  const style = TONES[tone];
  return (
    <div
      role={role}
      className={`cf-plate rounded-ui border p-3 text-sm text-ink-100 ${style.box} ${className}`}
    >
      <p className={`flex items-start gap-2 font-semibold ${style.title}`}>
        <span aria-hidden="true">{style.symbol}</span>
        <span>{title}</span>
      </p>
      {children === undefined ? null : <div className="mt-1 space-y-1.5">{children}</div>}
    </div>
  );
}
