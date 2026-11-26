import { actionLabel, reasonLabel, resultMeta, shortId } from "../../features/files/labels";
import type { ActivityItem } from "../../types/files";
import DateTime from "../DateTime";
import StatusBadge from "../StatusBadge";
import { LABEL } from "../styles";

const HEADER = `px-4 py-3 ${LABEL}`;

/** What happened to a file, newest first. The API records no addresses, so none are shown. */
export default function ActivityList({ items }: { items: readonly ActivityItem[] }) {
  return (
    <div
      className="relative overflow-x-auto"
      role="region"
      aria-label="Activity for this file, scrolls sideways"
      tabIndex={0}
    >
      <table className="w-full min-w-[40rem] text-left text-sm">
        <caption className="sr-only">Activity for this file, newest first</caption>
        <thead className="border-b border-ink-600 bg-ink-900/70">
          <tr>
            <th scope="col" className={HEADER}>
              When
            </th>
            <th scope="col" className={HEADER}>
              Event
            </th>
            <th scope="col" className={HEADER}>
              Result
            </th>
            <th scope="col" className={HEADER}>
              Link
            </th>
            <th scope="col" className={HEADER}>
              Detail
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-ink-700/60">
          {items.map((item, index) => {
            const result = resultMeta(item.result);
            const reason = reasonLabel(item.reason);
            return (
              <tr key={`${item.timestamp}-${item.action}-${index}`} className="align-top transition hover:bg-cipher/5">
                <td className="px-4 py-3">
                  <DateTime value={item.timestamp} stacked />
                </td>
                <th scope="row" className="px-4 py-3 font-normal text-ink-50">
                  {actionLabel(item.action)}
                </th>
                <td className="px-4 py-3">
                  <StatusBadge tone={result.tone}>{result.label}</StatusBadge>
                </td>
                <td className="px-4 py-3 font-mono text-xs">
                  {item.share_id === null ? (
                    <span className="text-ink-300">
                      <span aria-hidden="true">&mdash;</span>
                      <span className="sr-only">No link</span>
                    </span>
                  ) : (
                    shortId(item.share_id)
                  )}
                </td>
                <td className="px-4 py-3">
                  {reason === null ? (
                    <span className="text-ink-300">
                      <span aria-hidden="true">&mdash;</span>
                      <span className="sr-only">None</span>
                    </span>
                  ) : (
                    reason
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
