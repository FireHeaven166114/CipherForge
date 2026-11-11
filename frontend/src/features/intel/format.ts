const MINUTE_MS = 60_000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

const RELATIVE_UNITS: readonly { unit: Intl.RelativeTimeFormatUnit; ms: number }[] = [
  { unit: "year", ms: 365 * DAY_MS },
  { unit: "month", ms: 30 * DAY_MS },
  { unit: "day", ms: DAY_MS },
  { unit: "hour", ms: HOUR_MS },
  { unit: "minute", ms: MINUTE_MS },
];

const relativeFormat = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
const signedFormat = new Intl.NumberFormat("en", { signDisplay: "exceptZero" });

// A timestamp without a zone would be read as local time, so assume UTC like the API does.
const NO_ZONE = /^\d{4}-\d{2}-\d{2}T[\d:.]+$/;

/** Parses an API timestamp; null for missing or unreadable values. */
export function parseTimestamp(value: string | null | undefined): Date | null {
  if (!value) return null;
  const date = new Date(NO_ZONE.test(value) ? `${value}Z` : value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** "2026-05-01 12:00 UTC". Analysts correlate across systems, so time is always UTC. */
export function formatUtc(date: Date): string {
  return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
}

/** "3 days ago" or "in 5 hours"; anything under a minute is "just now". */
export function formatRelative(target: Date, now: Date): string {
  const difference = target.getTime() - now.getTime();
  const distance = Math.abs(difference);
  for (const { unit, ms } of RELATIVE_UNITS) {
    if (distance >= ms) return relativeFormat.format(Math.trunc(difference / ms), unit);
  }
  return "just now";
}

/** "+45", "-12" or "0", so a deduction is visibly different from a contribution. */
export function formatPoints(points: number): string {
  return signedFormat.format(points);
}

/** Two decimals for a 0..1 strength; "Not available" when the provider gave none. */
export function formatStrength(signal: number | null): string {
  return signal === null ? "Not available" : signal.toFixed(2);
}

/** "1 provider", "2 providers". Regular nouns only. */
export function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

/** "a moment", "30 seconds" or "2 minutes": how long to wait, rounded up. */
export function formatWait(seconds: number): string {
  if (seconds <= 0) return "a moment";
  return seconds < 60 ? plural(seconds, "second") : plural(Math.ceil(seconds / 60), "minute");
}
