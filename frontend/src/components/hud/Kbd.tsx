import type { ReactNode } from "react";

/** A keyboard key cap, for showing shortcuts. */
export default function Kbd({ children }: { children: ReactNode }) {
  return (
    <kbd className="rounded-chip border border-white/15 bg-ink-800/80 px-1.5 py-0.5 font-mono text-[0.68rem] leading-none text-ink-200">
      {children}
    </kbd>
  );
}
