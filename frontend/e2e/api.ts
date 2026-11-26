import { createHash, randomBytes } from "node:crypto";

import type { APIRequestContext, Page } from "@playwright/test";

import type {
  Classification,
  DeleteResult,
  Indicator,
  IndicatorPage,
  IndicatorType,
  Investigation,
  Overview,
  ProviderReason,
  ProviderStatus,
  ProviderVerdict,
} from "../src/types/intel";

/** The words the console prints, written out here so a wrong label in the app fails a test. */
export const CLASSIFICATION_LABELS: Record<Classification, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Informational",
};

export const TYPE_LABELS: Record<IndicatorType, string> = {
  ipv4: "IPv4",
  ipv6: "IPv6",
  domain: "Domain",
  url: "URL",
  md5: "MD5",
  sha1: "SHA-1",
  sha256: "SHA-256",
};

export const PROVIDER_STATUS_LABELS: Record<ProviderStatus, string> = {
  ok: "Answered",
  no_data: "No data",
  not_configured: "Not configured",
  unsupported: "Not supported",
  rate_limited: "Rate limited",
  error: "Error",
  not_queried: "Not queried",
};

/** What a provider itself concluded. "Harmless" and "Not found" are never shown as a safe result. */
export const PROVIDER_VERDICT_LABELS: Record<ProviderVerdict, string> = {
  malicious: "Malicious",
  suspicious: "Suspicious",
  harmless: "Harmless",
  unknown: "Unknown",
  not_found: "Not found",
};

/** Why a lookup gave no answer, as the card words it next to the status. */
export const PROVIDER_REASON_LABELS: Record<ProviderReason, string> = {
  not_configured: "Not configured",
  invalid_input: "Invalid input",
  auth_failed: "Authentication failure",
  rate_limited: "Rate limited",
  timeout: "Timeout",
  unavailable: "Provider unavailable",
  malformed_response: "Malformed response",
};

export function countOf(count: number, noun = "indicator"): string {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

/** Most to least severe, the order the risk-band list uses. */
export const CLASSIFICATION_ORDER = ["critical", "high", "medium", "low", "informational"] as const;
export const TYPE_ORDER = ["ipv4", "ipv6", "domain", "url", "md5", "sha1", "sha256"] as const;

/**
 * Reads of the API, made through the same front door as the browser. The specs use them as an
 * oracle ("the page shows what the API says") so they never hard-code the seeded demo data.
 */
async function getJson<T>(request: APIRequestContext, path: string): Promise<T> {
  const response = await request.get(path);
  if (!response.ok()) throw new Error(`GET ${path} answered ${response.status()}`);
  return (await response.json()) as T;
}

export function fetchOverview(request: APIRequestContext): Promise<Overview> {
  return getJson<Overview>(request, "/api/v1/intel/overview");
}

/** The stored dossier for one indicator: its record, each provider's answer and the score. */
export function fetchIndicator(request: APIRequestContext, id: string): Promise<Investigation> {
  return getJson<Investigation>(request, `/api/v1/intel/indicators/${id}`);
}

export function fetchIndicators(
  request: APIRequestContext,
  params: Record<string, string | number | readonly string[]> = {},
): Promise<IndicatorPage> {
  const query = new URLSearchParams({ limit: "25" });
  for (const [key, value] of Object.entries(params)) {
    query.delete(key);
    for (const item of typeof value === "object" ? value : [value]) query.append(key, String(item));
  }
  return getJson<IndicatorPage>(request, `/api/v1/intel/indicators?${query.toString()}`);
}

export async function firstIndicator(
  request: APIRequestContext,
  filter: { classification?: Classification; type?: IndicatorType; sort?: "recent" | "risk" } = {},
): Promise<Indicator> {
  const page = await fetchIndicators(request, { ...filter, limit: 1 });
  const found = page.items[0];
  if (!found) throw new Error(`The demo data has no indicator for ${JSON.stringify(filter)}`);
  return found;
}

export async function investigateViaApi(
  request: APIRequestContext,
  indicator: string,
): Promise<Investigation> {
  const response = await request.post("/api/v1/intel/investigate", {
    data: { indicator, refresh: false },
  });
  if (!response.ok()) throw new Error(`POST investigate answered ${response.status()}`);
  return (await response.json()) as Investigation;
}

/** A value that no earlier run, test or seed can have used, so a lookup always starts fresh. */
export function uniqueSuffix(): string {
  return `${Date.now().toString(36)}${Math.floor(Math.random() * 1296).toString(36)}`;
}

/** A hextet without a leading zero, so the normalised address reads exactly as it was typed. */
function hextet(): string {
  return (0x1000 + Math.floor(Math.random() * 0xf000)).toString(16);
}

/** Fresh, valid, public-looking values for each indicator type. */
export const fresh = {
  ipv6: (): string => `2100:${hextet()}:${hextet()}::${hextet()}`,
  domain: (): string => `e2e-${uniqueSuffix()}.example.net`,
  url: (): string => `https://e2e-${uniqueSuffix()}.example.net/path/${uniqueSuffix()}`,
  md5: (): string => createHash("md5").update(randomBytes(16)).digest("hex"),
  sha1: (): string => createHash("sha1").update(randomBytes(16)).digest("hex"),
  sha256: (): string => createHash("sha256").update(randomBytes(16)).digest("hex"),
} as const;

/** The stored record the API holds for a value, or an error when it holds none. */
export async function storedIndicator(request: APIRequestContext, value: string): Promise<Indicator> {
  const page = await fetchIndicators(request, { q: value, limit: 10 });
  const found = page.items.find((item) => item.indicator_value === value);
  if (!found) throw new Error(`The API has no stored indicator for ${value}`);
  return found;
}

/** Deletes indicators the way a script would, to set a test up or to clear up after it. */
export async function deleteViaApi(request: APIRequestContext, ids: readonly string[]): Promise<DeleteResult> {
  const response = await request.post("/api/v1/intel/indicators/bulk-delete", { data: { indicator_ids: ids } });
  if (!response.ok()) throw new Error(`POST bulk-delete answered ${response.status()}`);
  return (await response.json()) as DeleteResult;
}

/** New domain indicators that share a search text, so searching for it finds exactly them. */
export interface SeededIndicators {
  search: string;
  items: Indicator[];
}

/** Stores `count` new domain indicators, none of which any earlier run, test or seed can have used. */
export async function seedIndicators(request: APIRequestContext, count: number): Promise<SeededIndicators> {
  const search = `e2e-del-${uniqueSuffix()}-`;
  const items: Indicator[] = [];
  for (let number = 1; number <= count; number += 1) {
    items.push((await investigateViaApi(request, `${search}${number}.example.net`)).indicator);
  }
  return { search, items };
}

/** Deletes every indicator whose value contains the text, so a test leaves the shared database as it found it. */
export async function purgeIndicators(request: APIRequestContext, search: string): Promise<void> {
  for (let round = 0; round < 10; round += 1) {
    const found = await fetchIndicators(request, { q: search, limit: 100 });
    if (found.items.length === 0) return;
    await deleteViaApi(
      request,
      found.items.map((item) => item.indicator_id),
    );
  }
}

/** Counts the requests the page makes from now on whose URL matches the pattern (and, if given, the method). */
export function countRequests(page: Page, pattern: RegExp, method?: string): { readonly count: number } {
  const counter = { count: 0 };
  page.on("request", (request) => {
    if (pattern.test(request.url()) && (method === undefined || request.method() === method)) counter.count += 1;
  });
  return counter;
}
