import { formatCount } from "../../features/intel/format";
import { formatBytes } from "../../features/units";
import type { TalkerStat } from "../../types/network";
import HBarList from "../charts/HBarList";
import Panel from "../hud/Panel";
import { talkerItems } from "./chartData";
import Notice from "./Notice";
import TableView from "./TableView";

interface TopTalkersProps {
  sources: readonly TalkerStat[];
  destinations: readonly TalkerStat[];
  /** The monitor dropped the quietest addresses from its tallies, so the lists can undercount. */
  truncated: boolean;
  className?: string;
}

const LIMIT = 10;

interface TalkerListProps {
  title: string;
  talkers: readonly TalkerStat[];
  emptyText: string;
}

function TalkerList({ title, talkers, emptyText }: TalkerListProps) {
  return (
    <div className="min-w-0">
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-[0.14em] text-ink-100">{title}</h3>
      <HBarList items={talkerItems(talkers)} label={`${title} by bytes`} noun="byte" emptyText={emptyText} limit={LIMIT} />
      {talkers.length > 0 ? (
        <TableView
          caption={`${title}, with packets and data`}
          columns={[{ label: "Address" }, { label: "Packets", numeric: true }, { label: "Data", numeric: true }]}
          rows={talkers.slice(0, LIMIT).map((talker) => ({
            key: talker.address,
            cells: [talker.address, formatCount(talker.packets), formatBytes(talker.bytes)],
          }))}
        />
      ) : null}
    </div>
  );
}

/** The addresses that sent and received the most data in the session. */
export default function TopTalkers({ sources, destinations, truncated, className }: TopTalkersProps) {
  return (
    <Panel title="Top talkers" code="SES-03" className={className}>
      <p className="mb-3 text-xs text-ink-300">
        Ranked by bytes. The bars count bytes; the table view gives packets and sizes in full units.
      </p>
      {truncated ? (
        <Notice tone="warn" title="These lists may undercount" className="mb-3">
          <p>
            So many addresses were seen that those with the least traffic were left out of the
            tallies. An address missing here may still have appeared in the traffic.
          </p>
        </Notice>
      ) : null}
      <div className="grid gap-6 @split:grid-cols-2">
        <TalkerList title="Top source IPs" talkers={sources} emptyText="No source addresses yet." />
        <TalkerList title="Top destination IPs" talkers={destinations} emptyText="No destination addresses yet." />
      </div>
    </Panel>
  );
}
