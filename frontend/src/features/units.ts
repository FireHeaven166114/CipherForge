const groupedFormat = new Intl.NumberFormat("en-US");

const BYTE_UNITS = ["B", "KB", "MB", "GB", "TB"] as const;
const STEP = 1024;

/** "812 B", "1.50 KB", "24.0 MB": sizes in steps of 1024, with three significant digits. */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "Unknown size";
  if (bytes < STEP) return `${groupedFormat.format(Math.round(bytes))} B`;
  let value = bytes;
  let unit = 0;
  while (value >= STEP && unit < BYTE_UNITS.length - 1) {
    value /= STEP;
    unit += 1;
  }
  const digits = value >= 100 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(digits)} ${BYTE_UNITS[unit]}`;
}

/** "0.4 s", "42 s", "3 min 05 s" or "2 h 05 min": how long something lasted or will last. */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "Unknown";
  if (seconds < 10) return `${(Math.round(seconds * 10) / 10).toFixed(1)} s`;
  const whole = Math.round(seconds);
  if (whole < 60) return `${whole} s`;
  const minutes = Math.floor(whole / 60);
  if (minutes < 60) return `${minutes} min ${String(whole % 60).padStart(2, "0")} s`;
  return `${Math.floor(minutes / 60)} h ${String(minutes % 60).padStart(2, "0")} min`;
}

/** "1 hour", "24 hours", "3 days": a lifetime given in hours, in the largest whole unit. */
export function formatHours(hours: number): string {
  if (hours >= 24 && hours % 24 === 0) {
    const days = hours / 24;
    return `${days} ${days === 1 ? "day" : "days"}`;
  }
  return `${hours} ${hours === 1 ? "hour" : "hours"}`;
}
