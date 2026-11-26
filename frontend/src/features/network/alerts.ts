import { SEVERITIES, type NetworkAlert, type Severity } from "../../types/network";
import { CLASSIFICATION_META, type ClassificationMeta } from "../intel/classification";
import { formatCount, plural } from "../intel/format";
import { formatEndpoint, protocolLabel } from "./labels";

/** The alert severities are the first four intelligence bands, so they share their looks. */
export function severityMeta(severity: Severity): ClassificationMeta {
  return CLASSIFICATION_META[severity];
}

/** Adds or removes one severity from a filter, keeping the order low to critical. */
export function toggleSeverity(selected: readonly Severity[], severity: Severity): Severity[] {
  const next = new Set(selected);
  if (next.has(severity)) next.delete(severity);
  else next.add(severity);
  return SEVERITIES.filter((candidate) => next.has(candidate));
}

// The rules name their units in the plural; a count of exactly one reads "1 packet", not "1 packets".
const SINGULAR_UNITS: Readonly<Record<string, string>> = {
  ports: "port",
  connections: "connection",
  attempts: "attempt",
  packets: "packet",
};

/** "40 ports", "1 packet", "51.3 MB": a measurement with its unit. Whole numbers are grouped, fractions get one decimal. */
export function formatMeasure(value: number, unit: string): string {
  const number =
    Number.isInteger(value) || Math.abs(value) >= 1000
      ? formatCount(value)
      : String(Math.round(value * 10) / 10);
  if (unit === "") return number;
  const named = value === 1 && Object.hasOwn(SINGULAR_UNITS, unit) ? (SINGULAR_UNITS[unit] ?? unit) : unit;
  return `${number} ${named}`;
}

/** "60 seconds", or "No time window" for a rule that is not about a span of time. */
export function formatWindow(seconds: number | null): string {
  return seconds === null ? "No time window" : plural(seconds, "second");
}

/** "Observed 40 ports against a threshold of 20 ports, within 60 seconds." */
export function describeObservation(
  alert: Pick<NetworkAlert, "observed_value" | "threshold" | "unit" | "window_seconds">,
): string {
  const observed = formatMeasure(alert.observed_value, alert.unit);
  const threshold = formatMeasure(alert.threshold, alert.unit);
  const within = alert.window_seconds === null ? "" : `, within ${formatWindow(alert.window_seconds)}`;
  return `Observed ${observed} against a threshold of ${threshold}${within}.`;
}

export interface Traffic {
  source: string | null;
  destination: string | null;
  protocol: string | null;
}

/** Who talked to whom: the parts of an alert that name addresses, ports and protocol. */
export function describeTraffic(
  alert: Pick<NetworkAlert, "src_ip" | "dst_ip" | "dst_port" | "protocol">,
): Traffic {
  return {
    source: alert.src_ip,
    destination: alert.dst_ip === null ? null : formatEndpoint(alert.dst_ip, alert.dst_port),
    protocol: alert.protocol === null ? null : protocolLabel(alert.protocol),
  };
}
