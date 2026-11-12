import type { ReactNode } from "react";

interface PanelProps {
  title?: string;
  /** Heading level. Panels inside a section that already has an h2 use h3. */
  as?: "h2" | "h3";
  /** A short tag printed before the title, such as "SYS-01". Decorative. */
  code?: string;
  /** Controls or a badge shown at the right of the header. */
  actions?: ReactNode;
  /** "alert" lights the panel red; use it only for a critical condition. */
  tone?: "default" | "alert";
  className?: string;
  bodyClassName?: string;
  children: ReactNode;
}

const MARKERS = { default: "from-cipher to-arc", alert: "from-crit to-ember" } as const;

/**
 * A frosted-glass panel with an optional titled header. The glass, its lit top edge and the light
 * that follows the pointer are drawn by .hud-panel (see index.css); the panel joins the page's
 * entrance through data-reveal (see motion/reveal.ts).
 */
export default function Panel({
  title,
  as: Heading = "h2",
  code,
  actions,
  tone = "default",
  className = "",
  bodyClassName = "p-4",
  children,
}: PanelProps) {
  return (
    <section
      data-reveal
      className={`hud-panel relative min-w-0 rounded-ui ${tone === "alert" ? "shadow-glow-crit" : ""} ${className}`}
    >
      {title !== undefined || actions !== undefined ? (
        <header className="flex min-h-11 flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b border-white/10 px-4 py-2">
          {title !== undefined ? (
            <Heading className="flex min-w-0 items-center gap-2.5 text-[0.8rem] font-semibold uppercase tracking-[0.14em] text-ink-100 wrap-anywhere">
              <span aria-hidden="true" className={`h-4 w-1 shrink-0 rounded-full bg-gradient-to-b ${MARKERS[tone]}`} />
              {code ? (
                <span aria-hidden="true" className="font-mono text-[0.68rem] font-normal text-ink-300">
                  {code}
                </span>
              ) : null}
              {title}
            </Heading>
          ) : (
            <span />
          )}
          {actions}
        </header>
      ) : null}
      <div className={`text-sm text-ink-200 ${bodyClassName}`}>{children}</div>
    </section>
  );
}
