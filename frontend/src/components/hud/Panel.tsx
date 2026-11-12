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

const BRACKET = "pointer-events-none absolute size-2.5";

/** A glass HUD panel with corner brackets and an optional titled header. */
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
  const bracket = tone === "alert" ? "border-crit" : "border-cipher/80";
  return (
    <section
      className={`hud-panel relative min-w-0 rounded-[3px] ${tone === "alert" ? "shadow-glow-crit" : ""} ${className}`}
    >
      <span aria-hidden="true" className={`${BRACKET} -left-px -top-px border-l-2 border-t-2 ${bracket}`} />
      <span aria-hidden="true" className={`${BRACKET} -right-px -top-px border-r-2 border-t-2 ${bracket}`} />
      <span aria-hidden="true" className={`${BRACKET} -bottom-px -left-px border-b-2 border-l-2 ${bracket}`} />
      <span aria-hidden="true" className={`${BRACKET} -bottom-px -right-px border-b-2 border-r-2 ${bracket}`} />
      {title !== undefined || actions !== undefined ? (
        <header className="flex min-h-11 flex-wrap items-center justify-between gap-x-3 gap-y-1 border-b border-ink-700/70 px-4 py-2">
          {title !== undefined ? (
            <Heading className="flex min-w-0 items-center gap-2 text-[0.8rem] font-semibold uppercase tracking-[0.14em] text-ink-100 wrap-anywhere">
              <span aria-hidden="true" className="size-1.5 shrink-0 rotate-45 bg-cipher" />
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
