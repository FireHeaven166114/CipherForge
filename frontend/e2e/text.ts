import type { Classification } from "../src/types/intel";

/**
 * The words and numbers the pages should show, written out here without the app's own helpers so
 * that a mistake in the app's formatting shows up as a failing test.
 */

export function must<T>(value: T | null | undefined, what = "value"): T {
  if (value === null || value === undefined) throw new Error(`Expected ${what} to exist`);
  return value;
}

export function sum(values: readonly number[]): number {
  return values.reduce((total, value) => total + value, 0);
}

export function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** A pattern that matches the whole text and nothing around it. */
export function exactly(text: string): RegExp {
  return new RegExp(`^${escapeRegExp(text)}$`);
}

const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"] as const;
const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"] as const;

/** "Thu 29 Oct 2026" for a `YYYY-MM-DD` day of the IST calendar. */
export function longDay(day: string): string {
  const date = new Date(`${day}T00:00:00Z`);
  return `${must(WEEKDAYS[date.getUTCDay()])} ${date.getUTCDate()} ${must(MONTHS[date.getUTCMonth()])} ${date.getUTCFullYear()}`;
}

/** "14:00" for an hour of the IST day. */
export function hourText(hour: number): string {
  return `${String(hour).padStart(2, "0")}:00`;
}

/** Seconds past midnight in the "hh:mm:ss AM IST" a page prints, found anywhere in `text`. */
export function istClockSeconds(text: string): number {
  const match = must(/(\d{2}):(\d{2}):(\d{2}) (AM|PM) IST/.exec(text), "an IST time");
  const [hours, minutes, seconds] = match.slice(1, 4).map(Number);
  return ((must(hours) % 12) + (match[4] === "PM" ? 12 : 0)) * 3600 + must(minutes) * 60 + must(seconds);
}

/** The risk band of a score, by the API's own cut-offs (intel-risk-v1). */
export function bandOf(score: number): Classification {
  if (score <= 20) return "informational";
  if (score <= 40) return "low";
  if (score <= 60) return "medium";
  if (score <= 80) return "high";
  return "critical";
}

/** A share of a total as the charts print it: whole percent, or "<1%" for a sliver. */
export function share(count: number, total: number): string {
  const fraction = (count / total) * 100;
  return fraction > 0 && fraction < 1 ? "<1%" : `${Math.round(fraction)}%`;
}

/** How the headline tiles word a change against the previous 24 hours. */
export function trendText(current: number, previous: number): string {
  const change = current - previous;
  if (change === 0) {
    return previous === 0 ? "None in the last 48 hours" : `No change from ${previous} in the previous 24 hours`;
  }
  return `${change > 0 ? "+" : "-"}${Math.abs(change)} vs ${previous} in the previous 24 hours`;
}
