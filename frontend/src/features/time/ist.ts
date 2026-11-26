/**
 * The one place the console turns a timestamp into something a person reads.
 *
 * The API sends machine-readable UTC (ISO 8601). Everything shown to a user is Indian Standard
 * Time, taken from the IANA zone `Asia/Kolkata` rather than a hand-added +05:30, and from a fixed
 * locale, so neither the browser's language nor its own time zone can change the result.
 */

export const IST_TIME_ZONE = "Asia/Kolkata";
export const IST_LABEL = "IST";

// The range the backend accepts, so a value one side reads is a value the other side reads.
const MIN_YEAR = 1970;
const MAX_YEAR = 2200;

const FIELDS = new Intl.DateTimeFormat("en-GB", {
  timeZone: IST_TIME_ZONE,
  year: "numeric",
  month: "2-digit",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
  hourCycle: "h23",
});

// `YYYY-MM-DDTHH:MM[:SS[.ffffff]]`, then nothing (read as UTC, like the API does), `Z` or an offset.
const TIMESTAMP =
  /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?(Z|[+-]\d{2}(?::?\d{2})?)?$/i;

function offsetMinutes(zone: string | undefined): number | null {
  if (zone === undefined || zone.toUpperCase() === "Z") return 0;
  const digits = zone.slice(1).replace(":", "");
  const hours = Number(digits.slice(0, 2));
  const minutes = Number(digits.slice(2) || "0");
  if (hours > 23 || minutes > 59) return null;
  const total = hours * 60 + minutes;
  return zone.startsWith("-") ? -total : total;
}

/** Parses an API timestamp to an instant; null for a missing, unreadable or out-of-range value. */
export function parseTimestamp(value: string | null | undefined): Date | null {
  if (!value) return null;
  const match = TIMESTAMP.exec(value.trim());
  if (match === null) return null;

  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6] ?? "0");
  const millisecond = Number((match[7] ?? "").slice(0, 3).padEnd(3, "0"));
  if (year < MIN_YEAR || year > MAX_YEAR || hour > 23 || minute > 59 || second > 59) return null;

  const offset = offsetMinutes(match[8]);
  if (offset === null) return null;

  const wall = new Date(Date.UTC(year, month - 1, day, hour, minute, second, millisecond));
  // Date.UTC rolls a day that does not exist (31 February) over, so check that the day survived.
  const real =
    wall.getUTCFullYear() === year && wall.getUTCMonth() === month - 1 && wall.getUTCDate() === day;
  return real ? new Date(wall.getTime() - offset * 60_000) : null;
}

interface IstFields {
  year: string;
  month: string;
  day: string;
  hour: number;
  minute: string;
  second: string;
}

function toDate(value: Date | string | null | undefined): Date | null {
  const date = typeof value === "string" ? parseTimestamp(value) : (value ?? null);
  return date === null || Number.isNaN(date.getTime()) ? null : date;
}

function istFields(value: Date | string | null | undefined): IstFields | null {
  const date = toDate(value);
  if (date === null) return null;
  const parts: Record<string, string> = {};
  for (const part of FIELDS.formatToParts(date)) parts[part.type] = part.value;
  const { year, month, day, hour, minute, second } = parts;
  if (
    year === undefined ||
    month === undefined ||
    day === undefined ||
    hour === undefined ||
    minute === undefined ||
    second === undefined
  ) {
    return null;
  }
  // Some engines write midnight as "24" even when the cycle starts at 0.
  return { year, month, day, hour: Number(hour) % 24, minute, second };
}

function clock(fields: IstFields): string {
  const twelve = fields.hour % 12 === 0 ? 12 : fields.hour % 12;
  const meridiem = fields.hour < 12 ? "AM" : "PM";
  return `${String(twelve).padStart(2, "0")}:${fields.minute}:${fields.second} ${meridiem} ${IST_LABEL}`;
}

/**
 * "25-11-2026 09:49:00 AM IST" for "2026-11-25T04:19:00Z".
 * Takes an instant or an API timestamp, and shows `fallback` when there is no readable value.
 */
export function formatIst(value: Date | string | null | undefined, fallback = "Unknown"): string {
  const fields = istFields(value);
  return fields === null ? fallback : `${fields.day}-${fields.month}-${fields.year} ${clock(fields)}`;
}

/** "09:49:00 AM IST": the time of day alone, for a view that says when its data last arrived. */
export function formatIstTime(value: Date | string | null | undefined, fallback = "Unknown"): string {
  const fields = istFields(value);
  return fields === null ? fallback : clock(fields);
}
