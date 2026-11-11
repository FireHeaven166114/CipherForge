import { Fragment, type ReactNode } from "react";

export interface Fact {
  label: string;
  value: ReactNode;
}

/** Label and value pairs. A fact whose value is null, undefined or false is left out. */
export default function FactList({ facts }: { facts: readonly Fact[] }) {
  return (
    <dl className="grid grid-cols-[minmax(7rem,max-content)_minmax(0,1fr)] gap-x-4 gap-y-1.5">
      {facts
        .filter(({ value }) => value !== null && value !== undefined && value !== false)
        .map(({ label, value }) => (
          <Fragment key={label}>
            <dt className="text-slate-400">{label}</dt>
            <dd className="break-words">{value}</dd>
          </Fragment>
        ))}
    </dl>
  );
}
