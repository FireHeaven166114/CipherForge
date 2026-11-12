import type { ReactNode } from "react";

import DecodeText from "./DecodeText";

interface PageHeaderProps {
  /** A short module tag printed above the title, such as "MOD-01". Decorative. */
  code: string;
  title: string;
  description?: ReactNode;
  /** Buttons and readouts shown at the right. */
  actions?: ReactNode;
}

/** The title block every page starts with. It holds the page's one h1. */
export default function PageHeader({ code, title, description, actions }: PageHeaderProps) {
  return (
    <header data-reveal className="relative pb-5">
      <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-3">
        <div className="min-w-0">
          <p
            aria-hidden="true"
            className="flex items-center gap-2 font-mono text-[0.68rem] uppercase tracking-[0.24em] text-cipher/80"
          >
            <span className="h-px w-8 bg-gradient-to-r from-cipher to-arc" />
            {code}
          </p>
          <h1 className="text-gradient animate-aurora mt-1 text-3xl font-semibold tracking-tight @lg:text-4xl">
            <DecodeText text={title} />
          </h1>
          {description !== undefined ? (
            <p className="mt-1.5 max-w-3xl text-sm text-ink-200">{description}</p>
          ) : null}
        </div>
        {actions !== undefined ? <div className="flex flex-wrap items-center gap-3">{actions}</div> : null}
      </div>
      <div
        aria-hidden="true"
        className="absolute inset-x-0 bottom-0 h-px bg-gradient-to-r from-cipher/60 via-arc/30 to-transparent"
      />
    </header>
  );
}
