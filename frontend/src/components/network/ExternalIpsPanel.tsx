import { useState } from "react";

import { formatCount } from "../../features/intel/format";
import { summaryRows } from "../../features/network/enrichment";
import { protocolLabel, yesNo } from "../../features/network/labels";
import { ADDRESSES_PAGE_SIZE } from "../../features/network/paging";
import { formatBytes } from "../../features/units";
import type { ExternalIp, SessionDetail } from "../../types/network";
import ChipList from "../ChipList";
import DateTime from "../DateTime";
import FactList from "../FactList";
import Panel from "../hud/Panel";
import Pagination from "../Pagination";
import EnrichmentDetail from "./EnrichmentDetail";
import Notice from "./Notice";

interface ExternalIpsPanelProps {
  session: Pick<SessionDetail, "external_ips" | "enrichment">;
  className?: string;
}

const NOT_RECORDED = "Not recorded";

function chips(items: readonly string[], label: string) {
  return items.length === 0 ? null : <ChipList items={items} label={label} />;
}

function AddressCard({ entry }: { entry: ExternalIp }) {
  const { address } = entry;
  return (
    <li className="space-y-3 rounded-control border border-white/10 bg-ink-900/50 p-4">
      <h3 className="break-all font-mono text-sm font-semibold text-ink-50">{address}</h3>
      <FactList
        facts={[
          { label: "First seen", value: <DateTime value={entry.first_seen} fallback={NOT_RECORDED} /> },
          { label: "Last seen", value: <DateTime value={entry.last_seen} fallback={NOT_RECORDED} /> },
          { label: "Packets", value: entry.packets === null ? NOT_RECORDED : formatCount(entry.packets) },
          { label: "Data", value: entry.bytes === null ? NOT_RECORDED : formatBytes(entry.bytes) },
          { label: "Traffic sent to it", value: yesNo(entry.sent_to) },
          { label: "Raised an alert", value: yesNo(entry.alerted) },
          { label: "Ports", value: chips(entry.ports.map(String), `Ports seen with ${address}`) },
          { label: "Protocols", value: chips(entry.protocols.map(protocolLabel), `Protocols seen with ${address}`) },
          { label: "Peers", value: chips(entry.peers, `Peers of ${address}`) },
        ]}
      />
      <EnrichmentDetail enrichment={entry.enrichment} showAddress={false} />
    </li>
  );
}

/** The public addresses the traffic involved, and what is known about them. Nothing else is ever looked up. */
export default function ExternalIpsPanel({ session, className }: ExternalIpsPanelProps) {
  const [page, setPage] = useState(1);
  const { external_ips: addresses, enrichment } = session;
  const lastPage = Math.max(1, Math.ceil(addresses.length / ADDRESSES_PAGE_SIZE));
  const current = Math.min(page, lastPage);
  const shown = addresses.slice((current - 1) * ADDRESSES_PAGE_SIZE, current * ADDRESSES_PAGE_SIZE);

  return (
    <Panel title="External IP addresses" code="SES-05" className={className}>
      <div className="space-y-4">
        <p className="text-sm text-ink-100">
          Only deduplicated public addresses are ever looked up, never every packet, and never private
          addresses. Private, loopback and other non-public addresses are not listed here and are never
          sent anywhere.
        </p>

        {enrichment.enabled ? (
          <>
            <dl aria-label="Lookup summary" className="flex flex-wrap gap-x-8 gap-y-2">
              {summaryRows(enrichment).map((row) => (
                <div key={row.key}>
                  <dt className="text-xs text-ink-300">{row.label}</dt>
                  <dd className="font-mono text-lg tabular-nums text-ink-50">{formatCount(row.value)}</dd>
                </div>
              ))}
            </dl>
            <p className="text-xs text-ink-300">
              The server looks up the addresses involved in alerts first, then the busiest ones, up to a
              limit for each session. An address that is part of an alert can be looked up again from that
              alert. At most 100 addresses are listed, alerted ones first.
            </p>
          </>
        ) : (
          <Notice tone="info" title="External enrichment is switched off on this server">
            <p>The addresses below are still listed, but none is looked up or sent to any provider.</p>
          </Notice>
        )}

        {addresses.length === 0 ? (
          <p className="py-4 text-center text-sm text-ink-200">
            No public addresses were seen in this session&apos;s traffic.
          </p>
        ) : (
          <>
            <ul aria-label="External IP addresses" className="grid grid-cols-1 gap-3 @deck:grid-cols-2">
              {shown.map((entry) => (
                <AddressCard key={entry.address} entry={entry} />
              ))}
            </ul>
            <Pagination
              page={current}
              pageSize={ADDRESSES_PAGE_SIZE}
              total={addresses.length}
              label="External IP addresses pagination"
              onPageChange={setPage}
            />
          </>
        )}
      </div>
    </Panel>
  );
}
