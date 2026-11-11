import type { ReactNode } from "react";

/** A "still working" message that assistive technology announces politely. */
export default function LoadingNote({ children }: { children: ReactNode }) {
  return (
    <p role="status" className="text-sm text-slate-400">
      {children}
    </p>
  );
}
