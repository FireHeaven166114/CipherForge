// Building blocks for the runtime checks in the *Guards.ts files. A 200 response with the wrong
// shape is reported as an invalid response instead of crashing a page halfway through rendering.

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function isString(value: unknown): value is string {
  return typeof value === "string";
}

export function isNullableString(value: unknown): value is string | null {
  return value === null || typeof value === "string";
}

export function isFiniteNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

export function isNullableNumber(value: unknown): value is number | null {
  return value === null || isFiniteNumber(value);
}

/** A whole number that is not negative: counts, sizes, ports. */
export function isCount(value: unknown): value is number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0;
}

export function isNullableCount(value: unknown): value is number | null {
  return value === null || isCount(value);
}

export function isArrayOf<T>(guard: (item: unknown) => item is T): (value: unknown) => value is T[] {
  return (value): value is T[] => Array.isArray(value) && value.every(guard);
}

export function isOneOf<T extends string>(allowed: readonly T[]): (value: unknown) => value is T {
  return (value): value is T =>
    typeof value === "string" && (allowed as readonly string[]).includes(value);
}

export const isStringArray = isArrayOf(isString);

export function isCountRecord(value: unknown): value is Record<string, number> {
  return isRecord(value) && Object.values(value).every(isCount);
}
