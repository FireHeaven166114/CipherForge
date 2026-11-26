import { act, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, vi } from "vitest";

import NetworkPage from "../pages/NetworkPage";
import type { SessionDetail } from "../types/network";
import { type NetworkHandlers, networkApi, requested } from "./networkApi";
import { SESSION_ID, makeAlertPage, makeFlowPage, makeSessionDetail } from "./networkFixtures";
import { renderRoute } from "./router";

// Helpers shared by the tests of the Network page. They read the page the way a person does: by
// its panels, its labels and its words.

export const API = "/api/v1/network";
export const SESSION_URL = `${API}/sessions/${SESSION_ID}`;
export const SESSION_LINK = `/network?session=${SESSION_ID}`;
export const OTHER_ALERT_ID = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";

export type NetworkFetch = ReturnType<typeof networkApi>;

/** A session whose traffic has not produced any flow or alert yet, as a capture just started. */
export const NO_TRAFFIC: NetworkHandlers = {
  alerts: () => makeAlertPage([]),
  flows: () => makeFlowPage([]),
};

/** The enrichment summary of a session that has no public address to look up. */
export const NO_LOOKUPS: SessionDetail["enrichment"] = {
  enabled: true,
  total: 0,
  completed: 0,
  pending: 0,
  failed: 0,
  unavailable: 0,
  skipped: 0,
};

export function renderPage(url = "/network") {
  return renderRoute(<NetworkPage />, { url, path: "/network" });
}

/** Where the router is: the path and the query of the address. */
export const address = () => screen.getByTestId("location").textContent;

/** The panel with this title, so a text that also appears elsewhere is read in the right place. */
export function panel(title: string): HTMLElement {
  const section = screen.getByRole("heading", { level: 2, name: title }).closest("section");
  if (section === null) throw new Error(`The "${title}" heading is not inside a panel.`);
  return section;
}

/** The value shown next to a label of a definition list. */
export function valueOf(root: HTMLElement, label: string): HTMLElement {
  const value = within(root).getByText(label, { selector: "dt" }).nextElementSibling;
  if (!(value instanceof HTMLElement)) throw new Error(`"${label}" has no value next to it.`);
  return value;
}

/** The text of every cell of a table, row by row, also when the table sits in a closed disclosure. */
export function cellTexts(table: HTMLElement): string[][] {
  return within(table)
    .getAllByRole("row", { hidden: true })
    .map((row) => Array.from(row.querySelectorAll("th, td"), (cell) => (cell.textContent ?? "").trim()));
}

/** The list item that holds a heading, such as one alert or one detection rule. */
export function itemOf(heading: HTMLElement): HTMLElement {
  const item = heading.closest("li");
  if (item === null) throw new Error(`"${heading.textContent ?? ""}" is not in a list item.`);
  return item;
}

/** How many times an address was read, whatever its query. */
export function reads(fetchMock: NetworkFetch, path: string): number {
  return requested(fetchMock, "GET").filter((url) => url === path || url.startsWith(`${path}?`)).length;
}

/** The latest read of an address, with its query. */
export function lastRead(fetchMock: NetworkFetch, path: string): string | undefined {
  return requested(fetchMock, "GET")
    .filter((url) => url === path || url.startsWith(`${path}?`))
    .at(-1);
}

/** What the page sent to an address with a method other than GET. */
export function sentTo(fetchMock: NetworkFetch, path: string, method = "POST"): RequestInit | undefined {
  const call = fetchMock.mock.calls.find(
    ([input, init]) => String(input) === path && (init?.method ?? "GET") === method,
  );
  return call?.[1];
}

/** Opens the page once its first panel is there. */
export async function openPage(handlers: NetworkHandlers = {}, url = "/network"): Promise<NetworkFetch> {
  const fetchMock = networkApi(handlers);
  renderPage(url);
  await screen.findByRole("heading", { level: 2, name: "Live capture" });
  return fetchMock;
}

/** Opens the page once the interface list has arrived, as the controls depend on it. */
export async function openCapture(handlers: NetworkHandlers = {}): Promise<NetworkFetch> {
  const fetchMock = await openPage(handlers);
  await screen.findByRole("combobox", { name: "Interface" });
  return fetchMock;
}

/** Opens the page on a session, once its summary is there. */
export async function openSession(
  handlers: NetworkHandlers = {},
  url = SESSION_LINK,
): Promise<NetworkFetch> {
  const fetchMock = await openPage(handlers, url);
  await screen.findByRole("heading", { level: 2, name: "Session summary" });
  return fetchMock;
}

export async function alertItem(title = "Port scan"): Promise<HTMLElement> {
  // The detection rules below have headings of their own, some of them with the same words.
  return itemOf(await within(panel("Alerts")).findByRole("heading", { level: 3, name: title }));
}

/** A live capture that is still running: a few seconds of traffic, no alert yet. */
export function liveSession(overrides: Partial<SessionDetail> = {}): SessionDetail {
  return makeSessionDetail({
    source_kind: "live",
    interface: "eth0",
    source_label: "eth0",
    status: "running",
    ended_at: null,
    duration_seconds: 12.4,
    packets_total: 120,
    bytes_total: 7_200,
    flows_total: 6,
    active_flows: 3,
    alerts_total: 0,
    alerts_by_rule: {},
    external_ips: [],
    enrichment: NO_LOOKUPS,
    ...overrides,
  });
}

/** Moves the clock and lets every answer that is waiting settle, as polling tests cannot wait for real. */
export async function flush(ms = 0): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
    for (let pass = 0; pass < 10; pass += 1) await vi.advanceTimersByTimeAsync(0);
  });
}

/** 14:05 IST on 20 May 2026 (08:35 UTC), with the tab in view so that polling runs. */
export function withFakeClock(): void {
  beforeEach(() => {
    vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-05-20T08:35:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });
}
