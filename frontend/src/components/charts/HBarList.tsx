import { CLASSIFICATION_META, classificationForScore } from "../../features/intel/classification";
import { plural } from "../../features/intel/format";
import Count from "../Count";

export interface HBarItem {
  key: string;
  label: string;
  count: number;
  /** The highest risk score behind the count, or null when there is none to show. */
  maxRisk: number | null;
}

interface HBarListProps {
  items: readonly HBarItem[];
  /** Names the list for assistive technology. */
  label: string;
  /** What is counted, in the singular: "indicator". */
  noun: string;
  emptyText: string;
  /** When given, every row is a button that opens more detail. */
  onSelect?: (key: string) => void;
  /** Show at most this many rows. */
  limit?: number;
}

const ROW =
  "grid w-full grid-cols-[1.75rem_minmax(0,1fr)_auto] items-center gap-x-2 gap-y-1 rounded-control px-2 py-1.5 text-left";
const ROW_BUTTON = `${ROW} transition hover:bg-cipher/[0.06] focus-visible:bg-cipher/[0.06]`;

/** Ranked horizontal bars. Each bar is coloured by the highest risk behind it, never by colour alone. */
export default function HBarList({ items, label, noun, emptyText, onSelect, limit }: HBarListProps) {
  const shown = limit === undefined ? items : items.slice(0, limit);
  if (shown.length === 0) {
    return <p className="py-6 text-center text-sm text-ink-300">{emptyText}</p>;
  }
  const top = Math.max(1, ...shown.map((item) => item.count));

  return (
    <ul aria-label={label} className="space-y-0.5">
      {shown.map((item, index) => {
        const band = item.maxRisk === null ? null : CLASSIFICATION_META[classificationForScore(item.maxRisk)];
        const description = `${plural(item.count, noun)}${band ? `, highest risk ${band.label}` : ""}`;
        const content = (
          <>
            <span aria-hidden="true" className="font-mono text-[0.68rem] text-ink-300">
              {String(index + 1).padStart(2, "0")}
            </span>
            {/* "relative" makes this the box that clips the hidden description below. Without it the
                description, placed after a long label, would sit far off to the right and widen the page. */}
            <span className="relative min-w-0 truncate text-ink-100" title={item.label}>
              {item.label}
              <span className="sr-only">: {description}</span>
            </span>
            <span aria-hidden="true" className="flex items-center gap-1.5 font-mono text-xs tabular-nums">
              {band ? <span className={band.text}>{band.symbol}</span> : null}
              <Count value={item.count} className="text-ink-50" />
            </span>
            <svg
              aria-hidden="true"
              focusable="false"
              viewBox="0 0 100 6"
              preserveAspectRatio="none"
              className="col-span-3 h-1.5 w-full rounded-full"
            >
              <rect width="100" height="6" className="fill-ink-800" />
              <rect
                width={Math.max(2, (item.count / top) * 100)}
                height="6"
                className={`${band ? band.bar : "fill-ink-400"} origin-left animate-grow-x [transform-box:fill-box]`}
              />
            </svg>
          </>
        );
        return (
          <li key={item.key}>
            {onSelect ? (
              <button type="button" aria-haspopup="dialog" onClick={() => onSelect(item.key)} className={ROW_BUTTON}>
                {content}
              </button>
            ) : (
              <div className={ROW}>{content}</div>
            )}
          </li>
        );
      })}
    </ul>
  );
}
