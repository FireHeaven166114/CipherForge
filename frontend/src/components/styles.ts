/**
 * Shared class lists, written out in full so Tailwind can find every class in the source.
 *
 * A button that is busy is marked `aria-disabled` rather than `disabled`. A `disabled` button
 * cannot keep focus, so a keyboard user who pressed it would lose their place until the work
 * ended. The click handler of such a button must do nothing while it is busy.
 */

export const BUTTON =
  "inline-flex items-center justify-center gap-2 rounded-[3px] border border-ink-600 bg-ink-800/70 px-3 py-1.5 text-sm font-medium text-ink-100 transition hover:border-cipher/60 hover:bg-ink-700/80 hover:text-ink-50 disabled:cursor-not-allowed disabled:opacity-50 aria-disabled:cursor-not-allowed aria-disabled:opacity-50";

export const PRIMARY_BUTTON =
  "inline-flex items-center justify-center gap-2 rounded-[3px] border border-cipher bg-cipher/15 px-4 py-2 text-sm font-semibold uppercase tracking-[0.12em] text-cipher shadow-glow transition hover:bg-cipher hover:text-void disabled:cursor-not-allowed disabled:opacity-50 disabled:shadow-none aria-disabled:cursor-not-allowed aria-disabled:opacity-50 aria-disabled:shadow-none";

export const LINK =
  "rounded-sm text-cipher underline decoration-cipher/40 underline-offset-2 transition hover:text-ink-50 hover:decoration-cipher";

export const FIELD =
  "block w-full rounded-[3px] border border-ink-600 bg-ink-950/80 px-3 py-2 text-sm text-ink-50 placeholder:text-ink-300 transition focus:border-cipher";

/** The small caps label that sits above a field or a metric. */
export const LABEL = "text-[0.7rem] font-semibold uppercase tracking-[0.16em] text-ink-300";
