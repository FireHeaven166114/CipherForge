const MAX_CHIPS = 20;

/** Short labels such as tags and malware families. Always plain text, never markup or links. */
export default function ChipList({ items, label }: { items: readonly string[]; label: string }) {
  if (items.length === 0) return null;
  const shown = items.slice(0, MAX_CHIPS);
  const hidden = items.length - shown.length;
  return (
    <ul role="list" aria-label={label} className="flex flex-wrap gap-1.5">
      {shown.map((item, index) => (
        <li
          key={`${item}:${index}`}
          className="max-w-full break-words rounded border border-slate-600 bg-slate-800 px-2 py-0.5 text-xs text-slate-200"
        >
          {item}
        </li>
      ))}
      {hidden > 0 ? <li className="px-1 py-0.5 text-xs text-slate-400">+{hidden} more</li> : null}
    </ul>
  );
}
