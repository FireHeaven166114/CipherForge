/** Formatting for the UTC calendar days the overview API sends (`YYYY-MM-DD`). Deterministic: no locale data. */

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"] as const;
const WEEKDAYS = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"] as const;

const DAY = /^(\d{4})-(\d{2})-(\d{2})$/;

/** The day as a UTC date, or null when it is not a real calendar day. */
export function parseDay(day: string): Date | null {
  const match = DAY.exec(day);
  if (match === null) return null;
  const [year, month, date] = [Number(match[1]), Number(match[2]), Number(match[3])];
  const parsed = new Date(Date.UTC(year, month - 1, date));
  const real =
    parsed.getUTCFullYear() === year && parsed.getUTCMonth() === month - 1 && parsed.getUTCDate() === date;
  return real ? parsed : null;
}

/** "14 May" */
export function shortDay(day: string): string {
  const parsed = parseDay(day);
  return parsed === null ? day : `${parsed.getUTCDate()} ${MONTHS[parsed.getUTCMonth()] ?? ""}`;
}

/** "Thu 14" */
export function weekdayAndDate(day: string): string {
  const parsed = parseDay(day);
  return parsed === null ? day : `${WEEKDAYS[parsed.getUTCDay()] ?? ""} ${parsed.getUTCDate()}`;
}

/** "Thu 14 May 2026" */
export function longDay(day: string): string {
  const parsed = parseDay(day);
  return parsed === null
    ? day
    : `${WEEKDAYS[parsed.getUTCDay()] ?? ""} ${parsed.getUTCDate()} ${MONTHS[parsed.getUTCMonth()] ?? ""} ${parsed.getUTCFullYear()}`;
}

/** "09:00" for an hour of the UTC day, 0 to 23. */
export function hourLabel(hour: number): string {
  return `${String(hour).padStart(2, "0")}:00`;
}
