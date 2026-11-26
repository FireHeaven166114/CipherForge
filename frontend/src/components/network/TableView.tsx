import type { ReactNode } from "react";

import { LABEL } from "../styles";

export interface TableViewColumn {
  label: string;
  /** Right-aligned, in figures. */
  numeric?: boolean;
}

export interface TableViewRow {
  key: string;
  /** One per column. The first names the row. */
  cells: readonly ReactNode[];
}

interface TableViewProps {
  /** Names the table for assistive technology. */
  caption: string;
  columns: readonly TableViewColumn[];
  rows: readonly TableViewRow[];
}

/** The figures behind a chart as a table, for anyone who cannot read the chart. */
export default function TableView({ caption, columns, rows }: TableViewProps) {
  return (
    <details className="mt-3 text-sm">
      <summary className="w-fit cursor-pointer rounded-chip text-cipher underline decoration-cipher/40 underline-offset-2 hover:text-ink-50">
        Table view<span className="sr-only">: {caption}</span>
      </summary>
      <div className="relative mt-2 overflow-x-auto">
        <table className="w-full min-w-[18rem] text-left text-sm">
          <caption className="sr-only">{caption}</caption>
          <thead className="border-b border-ink-600 bg-ink-900/70">
            <tr>
              {columns.map((column) => (
                <th
                  key={column.label}
                  scope="col"
                  className={`px-3 py-2 ${LABEL} ${column.numeric ? "text-right" : ""}`}
                >
                  {column.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-ink-700/60">
            {rows.map((row) => (
              <tr key={row.key} className="align-top">
                {row.cells.map((cell, index) =>
                  index === 0 ? (
                    <th key={columns[index]?.label ?? index} scope="row" className="px-3 py-2 font-normal text-ink-100">
                      {cell}
                    </th>
                  ) : (
                    <td
                      key={columns[index]?.label ?? index}
                      className={`px-3 py-2 font-mono tabular-nums ${columns[index]?.numeric ? "text-right" : ""}`}
                    >
                      {cell}
                    </td>
                  ),
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </details>
  );
}
