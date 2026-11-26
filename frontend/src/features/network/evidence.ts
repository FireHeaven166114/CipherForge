import { formatCount } from "../intel/format";
import { formatIst, parseTimestamp } from "../time/ist";
import { formatBytes, formatDuration } from "../units";
import { humanize } from "./labels";

export interface EvidenceRow {
  /** Unique within one alert. */
  key: string;
  label: string;
  value: string;
}

export interface Evidence {
  rows: EvidenceRow[];
  /** True when more detail existed than was listed. */
  truncated: boolean;
}

type Primitive = string | number | boolean | null;

const MAX_ROWS = 60;
const MAX_DEPTH = 3;
const MAX_LIST = 20;
const MAX_TEXT = 200;
const TIMESTAMP = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/;
const TOO_DEEP = "More detail than is shown here.";

function isPrimitive(value: unknown): value is Primitive {
  return value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The name of a value says how to read its number: bytes, seconds, a port, or a plain count. */
function formatNumber(value: number, name: string): string {
  if (!Number.isFinite(value)) return String(value);
  if (/(^|_)bytes$/.test(name)) return formatBytes(value);
  if (/(^|_)seconds$/.test(name)) return formatDuration(value);
  if (/(^|_)ports?$/.test(name)) return String(value);
  return Number.isInteger(value) ? formatCount(value) : String(Math.round(value * 100) / 100);
}

function formatPrimitive(value: Primitive, name: string): string {
  if (value === null) return "None";
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (typeof value === "number") return formatNumber(value, name);
  if (TIMESTAMP.test(value) && parseTimestamp(value) !== null) return formatIst(value);
  return value.length > MAX_TEXT ? `${value.slice(0, MAX_TEXT)}…` : value;
}

function isFlat(value: Record<string, unknown>): boolean {
  const values = Object.values(value);
  return values.length > 0 && values.every(isPrimitive);
}

/** "Address: 203.0.113.45, Port: 22": a small record of plain values on one line. */
function describeFlat(value: Record<string, unknown>): string {
  return Object.entries(value)
    .map(([name, entry]) => `${humanize(name)}: ${formatPrimitive(isPrimitive(entry) ? entry : null, name)}`)
    .join(", ");
}

interface Collector {
  rows: EvidenceRow[];
  truncated: boolean;
}

function add(out: Collector, path: readonly string[], value: string): void {
  if (out.rows.length >= MAX_ROWS) {
    out.truncated = true;
    return;
  }
  out.rows.push({ key: path.join("."), label: path.map(humanize).join(" › "), value });
}

function walkList(out: Collector, path: readonly string[], list: readonly unknown[]): void {
  const name = path.at(-1) ?? "";
  if (list.length === 0) return add(out, path, "None");
  if (list.every(isPrimitive)) {
    const shown = list.slice(0, MAX_LIST).map((item) => formatPrimitive(item, name));
    const hidden = list.length - shown.length;
    return add(out, path, hidden > 0 ? `${shown.join(", ")} and ${formatCount(hidden)} more` : shown.join(", "));
  }
  list.slice(0, MAX_LIST).forEach((item, index) => walk(out, [...path, String(index + 1)], item));
  if (list.length > MAX_LIST) {
    const left = list.length - MAX_LIST;
    add(
      out,
      [...path, "more"],
      left === 1 ? "1 more entry is not shown." : `${formatCount(left)} more entries are not shown.`,
    );
  }
}

function walk(out: Collector, path: readonly string[], value: unknown): void {
  const name = path.at(-1) ?? "";
  if (isPrimitive(value)) return add(out, path, formatPrimitive(value, name));
  if (Array.isArray(value)) {
    return path.length >= MAX_DEPTH ? add(out, path, TOO_DEEP) : walkList(out, path, value);
  }
  if (isRecord(value)) {
    if (Object.keys(value).length === 0) return add(out, path, "None");
    if (isFlat(value) && path.length > 1) return add(out, path, describeFlat(value));
    if (path.length >= MAX_DEPTH) return add(out, path, TOO_DEEP);
    for (const [entry, child] of Object.entries(value)) walk(out, [...path, entry], child);
    return;
  }
  add(out, path, TOO_DEEP);
}

/**
 * Turns an alert's evidence into rows of label and value, to show as plain text. The evidence is
 * whatever the detection rule recorded, so any shape is handled: nested records, lists, numbers
 * named for what they count. Nothing here is ever treated as markup.
 */
export function flattenEvidence(evidence: Record<string, unknown>): Evidence {
  const out: Collector = { rows: [], truncated: false };
  for (const [name, value] of Object.entries(evidence)) walk(out, [name], value);
  return out;
}
