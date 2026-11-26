import { formatCount } from "../../features/intel/format";
import { protocolLabel } from "../../features/network/labels";
import { formatBytes } from "../../features/units";
import type { ProtocolStat } from "../../types/network";
import Donut from "../charts/Donut";
import Panel from "../hud/Panel";
import { protocolSlices, rankProtocols } from "./chartData";
import TableView from "./TableView";

interface ProtocolPanelProps {
  protocols: readonly ProtocolStat[];
  className?: string;
}

/** Which protocols the packets used, as a ring with a legend and, behind it, a table. */
export default function ProtocolPanel({ protocols, className }: ProtocolPanelProps) {
  const ranked = rankProtocols(protocols);
  return (
    <Panel title="Protocol distribution" code="SES-02" className={className}>
      <Donut
        slices={protocolSlices(protocols)}
        noun="packet"
        label="Packets by protocol"
        centerCaption="packets"
        emptyText="No packets have been analysed yet."
      />
      {ranked.length > 0 ? (
        <TableView
          caption="Packets and data by protocol"
          columns={[{ label: "Protocol" }, { label: "Packets", numeric: true }, { label: "Data", numeric: true }]}
          rows={ranked.map((entry) => ({
            key: entry.protocol,
            cells: [protocolLabel(entry.protocol), formatCount(entry.packets), formatBytes(entry.bytes)],
          }))}
        />
      ) : null}
    </Panel>
  );
}
