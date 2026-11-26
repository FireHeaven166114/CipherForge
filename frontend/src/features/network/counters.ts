import type { SessionDetail } from "../../types/network";
import { formatCount } from "../intel/format";

export interface CounterNote {
  key: string;
  label: string;
  /** The figure, already formatted. */
  display: string;
  explanation: string;
  /** True when the figure means some of the picture is missing. */
  attention: boolean;
}

function count(
  key: string,
  label: string,
  value: number,
  explanation: string,
  attentionWhenPositive: boolean,
): CounterNote {
  return {
    key,
    label,
    display: formatCount(value),
    explanation,
    attention: attentionWhenPositive && value > 0,
  };
}

/**
 * The counters that say what the totals leave out, each with its meaning. A drop or a loss is
 * always shown, and a zero is not presented as proof that nothing went missing.
 */
export function sessionCounters(detail: SessionDetail): CounterNote[] {
  return [
    count(
      "packets_dropped",
      "Packets dropped by the monitor",
      detail.packets_dropped,
      detail.packets_dropped > 0
        ? "The monitor's bounded queue overflowed, so these packets were never analysed and the totals run lower than the real traffic. This is not the operating system's drop count: packets the system or network card dropped earlier cannot be seen from here."
        : "The monitor kept up with the traffic. Packets dropped earlier by the operating system or network card cannot be seen from here, so zero does not prove none were lost.",
      true,
    ),
    count(
      "non_ip_packets",
      "Non-IP packets",
      detail.non_ip_packets,
      "Packets without an IP header, such as ARP. They are counted here, not in the packet total or in any flow.",
      false,
    ),
    count(
      "malformed_packets",
      "Malformed packets",
      detail.malformed_packets,
      "Packets that could not be read. They are counted here, not analysed, and not part of the packet total.",
      true,
    ),
    count(
      "flows_evicted",
      "Flows closed early",
      detail.flows_evicted,
      "Flows closed early because the table of open flows was full. Later packets of the same connection start a new flow, so the flow count can run high.",
      true,
    ),
    count(
      "flows_stored",
      "Flows stored",
      detail.flows_stored,
      "Finished flows saved with the session. They are listed in the flows table.",
      false,
    ),
    count(
      "flows_not_stored",
      "Flows not stored",
      detail.flows_not_stored,
      "Finished flows beyond the limit kept for one session. They are counted in the totals but are not in the flows table.",
      true,
    ),
    count(
      "alerts_suppressed",
      "Repeat alerts suppressed",
      detail.alerts_suppressed,
      "Alerts that repeated while their rule was cooling down. They are counted here and not listed again.",
      false,
    ),
    count(
      "alerts_lost",
      "Alerts lost",
      detail.alerts_lost,
      "Alerts that were raised but could not be kept because a cap was reached, so the list can hold fewer alerts than the alert total.",
      true,
    ),
    {
      key: "talkers_truncated",
      label: "Top talkers truncated",
      display: detail.talkers_truncated ? "Yes" : "No",
      explanation: detail.talkers_truncated
        ? "So many addresses were seen that those with the least traffic were dropped from the tallies. The top talker lists can undercount."
        : "Every address seen is in the tallies behind the top talker lists.",
      attention: detail.talkers_truncated,
    },
  ];
}
