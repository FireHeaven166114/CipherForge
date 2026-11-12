import { formatPoints } from "../intel/format";

export interface Trend {
  direction: "up" | "down" | "flat";
  /** Always written out, so the change never depends on an arrow or a colour. */
  text: string;
}

/**
 * Compares a count with the same count for the period before it. More lookups or more new
 * indicators is neither good nor bad on its own, so the wording stays neutral.
 */
export function describeTrend(current: number, previous: number): Trend {
  const change = current - previous;
  if (change === 0) {
    return {
      direction: "flat",
      text: previous === 0 ? "None in the last 48 hours" : `No change from ${previous} in the previous 24 hours`,
    };
  }
  return {
    direction: change > 0 ? "up" : "down",
    text: `${formatPoints(change)} vs ${previous} in the previous 24 hours`,
  };
}
