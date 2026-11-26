import { createHash, randomBytes } from "node:crypto";
import { readFile as readBytes, readdir, stat, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

import AxeBuilder from "@axe-core/playwright";
import {
  type APIRequestContext,
  type Browser,
  type BrowserContext,
  type Download,
  type Page,
  type Request as NetworkRequest,
  expect,
} from "@playwright/test";

import type {
  ActivityItem,
  ActivityList,
  FileList as StoredFiles,
  Share,
  ShareCreated,
  ShareRequest,
  StoredFile,
  StoredFileDetail,
} from "../src/types/files";
import { type Violation, settle, summarise } from "./axe";
import { must } from "./text";

/**
 * What the Files and Share journeys need besides the page: reads and writes of the API (used only
 * to set a test up, to clean up after it and as an oracle for what the page should show), the
 * encrypted blobs on disk, an independent working-out of India Standard Time, a visitor who
 * has nothing but a link, and the accessibility audit. Nothing here imports the app's own helpers,
 * so a mistake in the app shows up as a failing test.
 */

const API = "/api/v1";

/** The demo server's own folder: its database, its master key and the encrypted blobs. */
const DEMO_DIR = resolve(import.meta.dirname, "..", "..", "backend", ".demo");
/** One `<32 hex>.bin` per stored file: the ciphertext and its 16-byte authentication tag. */
const BLOB_DIR = resolve(DEMO_DIR, "e2e-files");
const DEMO_DB = resolve(DEMO_DIR, "e2e.db");

// ---- India Standard Time, worked out by hand ------------------------------------------------

const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31] as const;

function daysIn(year: number, month: number): number {
  const leap = (year % 4 === 0 && year % 100 !== 0) || year % 400 === 0;
  return month === 2 && leap ? 29 : must(DAYS_IN_MONTH[month - 1], "a month between 1 and 12");
}

/**
 * "DD-MM-YYYY hh:mm:ss AM IST" for a UTC timestamp from the API, found by adding five hours and thirty
 * minutes and carrying through the clock and the calendar. Fractions of a second are dropped.
 */
export function istText(utc: string): string {
  const match = must(
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|\+00:00)$/.exec(utc),
    `a UTC timestamp, got ${utc}`,
  );
  const [yearText, monthText, dayText, hourText, minuteText, secondText] = match.slice(1, 7).map(Number);
  let year = must(yearText);
  let month = must(monthText);
  let day = must(dayText);
  let hour = must(hourText) + 5;
  let minute = must(minuteText) + 30;
  if (minute >= 60) {
    minute -= 60;
    hour += 1;
  }
  if (hour >= 24) {
    hour -= 24;
    day += 1;
  }
  if (day > daysIn(year, month)) {
    day = 1;
    month += 1;
  }
  if (month > 12) {
    month = 1;
    year += 1;
  }
  const pad = (value: number): string => String(value).padStart(2, "0");
  const clock = hour % 12 === 0 ? 12 : hour % 12;
  return `${pad(day)}-${pad(month)}-${year} ${pad(clock)}:${pad(minute)}:${pad(must(secondText))} ${hour < 12 ? "AM" : "PM"} IST`;
}

// ---- Bytes ----------------------------------------------------------------------------------

/** Letters and digits that no earlier run can have used, so names and searches never collide. */
export function uniqueTag(): string {
  return `${Date.now().toString(36)}${randomBytes(3).toString("hex")}`;
}

/** A well-formed share token (43 URL-safe characters) that no link was ever made with. */
export function unknownToken(): string {
  return randomBytes(32).toString("base64url");
}

/** The same seed always gives the same bytes, and they look like random ones. */
export function bytesOf(seed: string, length: number): Buffer {
  const blocks: Buffer[] = [];
  for (let counter = 0; blocks.length * 32 < length; counter += 1) {
    blocks.push(createHash("sha256").update(`${seed}:${counter}`).digest());
  }
  return Buffer.concat(blocks).subarray(0, length);
}

export function sha256(data: Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

/** The bytes the browser saved for a download. */
export async function savedBytes(download: Download): Promise<Buffer> {
  return readBytes(must(await download.path(), "a path for the saved download"));
}

// ---- The API, as an oracle and for setting up and clearing away ------------------------------

async function getJson<T>(request: APIRequestContext, path: string): Promise<T> {
  const response = await request.get(path);
  if (!response.ok()) throw new Error(`GET ${path} answered ${response.status()}`);
  return (await response.json()) as T;
}

/** Stores a file the way a script would. The server cleans the name, so read the stored one from the result. */
export async function storeFile(request: APIRequestContext, name: string, data: Buffer): Promise<StoredFile> {
  const response = await request.post(`${API}/files`, {
    headers: { "content-type": "application/octet-stream", "x-file-name": encodeURIComponent(name) },
    data,
  });
  if (response.status() !== 201) throw new Error(`POST /files answered ${response.status()}`);
  return (await response.json()) as StoredFile;
}

/** Every stored file of the signed-in owner, newest first. */
export async function fetchFiles(request: APIRequestContext): Promise<StoredFile[]> {
  const found: StoredFile[] = [];
  for (let offset = 0; ; offset += 200) {
    const page = await getJson<StoredFiles>(request, `${API}/files?limit=200&offset=${offset}`);
    found.push(...page.items);
    if (page.items.length === 0 || found.length >= page.total) return found;
  }
}

/** The stored file with exactly this (already cleaned) name. */
export async function storedFile(request: APIRequestContext, name: string): Promise<StoredFile> {
  const matches = (await fetchFiles(request)).filter((file) => file.name === name);
  if (matches.length !== 1) throw new Error(`Expected one stored file named ${name}, found ${matches.length}`);
  return must(matches[0]);
}

export function fetchFile(request: APIRequestContext, id: string): Promise<StoredFileDetail> {
  return getJson<StoredFileDetail>(request, `${API}/files/${id}`);
}

/** What the audit log holds for a file, newest first. */
export async function fetchActivity(request: APIRequestContext, id: string): Promise<ActivityItem[]> {
  return (await getJson<ActivityList>(request, `${API}/files/${id}/activity`)).items;
}

export async function makeShare(
  request: APIRequestContext,
  fileId: string,
  body: ShareRequest = {},
): Promise<ShareCreated> {
  const response = await request.post(`${API}/files/${fileId}/shares`, { data: body });
  if (response.status() !== 201) throw new Error(`POST shares answered ${response.status()}`);
  return (await response.json()) as ShareCreated;
}

export async function revokeViaApi(request: APIRequestContext, fileId: string, shareId: string): Promise<Share> {
  const response = await request.post(`${API}/files/${fileId}/shares/${shareId}/revoke`);
  if (!response.ok()) throw new Error(`POST revoke answered ${response.status()}`);
  return (await response.json()) as Share;
}

/** Deletes a file, and is happy when a test has already deleted it through the page. */
export async function removeFile(request: APIRequestContext, id: string): Promise<void> {
  const response = await request.delete(`${API}/files/${id}`);
  if (response.status() !== 204 && response.status() !== 404) {
    throw new Error(`DELETE /files answered ${response.status()}`);
  }
}

/** The HTTP status the API gives a GET, such as 404 for a file that is gone. */
export async function statusOf(request: APIRequestContext, path: string): Promise<number> {
  return (await request.get(path)).status();
}

// ---- The encrypted blobs on disk ------------------------------------------------------------

/** The names of the encrypted blobs the demo server holds right now. */
export async function blobNames(): Promise<string[]> {
  try {
    return (await readdir(BLOB_DIR)).filter((name) => name.endsWith(".bin")).sort();
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return [];
    throw error;
  }
}

/** The path of the one blob that is not in `before`: the one a file stored since then lives in. */
export async function newBlob(before: readonly string[]): Promise<string> {
  const added = (await blobNames()).filter((name) => !before.includes(name));
  if (added.length !== 1) throw new Error(`Expected one new encrypted blob on disk, found ${added.length}`);
  return resolve(BLOB_DIR, must(added[0]));
}

/** Changes one byte in the middle of a blob. The size stays exactly the same. */
export async function flipOneByte(path: string): Promise<number> {
  const data = await readBytes(path);
  const offset = Math.floor(data.length / 2);
  data[offset] = must(data[offset]) ^ 0xff;
  await writeFile(path, data);
  const { size } = await stat(path);
  if (size !== data.length) throw new Error(`The blob changed size from ${data.length} to ${size} bytes`);
  return size;
}

// ---- A link that has really expired -----------------------------------------------------------

const LONG_AGO = "2000-01-01 00:00:00.000000";
const A_DAY_LATER = "2000-01-02 00:00:00.000000";

/**
 * The API will not make a link that lasts less than an hour, and a test may not wait that long. So this
 * moves a link's creation and expiry to the year 2000 in the throwaway end-to-end database (the
 * database insists that a link expires after it was made, so both move). The server then judges
 * the link for itself, with its own clock and its own rules.
 */
export async function expireShare(shareId: string): Promise<void> {
  // Loaded when needed, so a Node that lacks the module only breaks the test that uses it.
  const { DatabaseSync } = await import("node:sqlite");
  const database = new DatabaseSync(DEMO_DB);
  try {
    database.exec("PRAGMA busy_timeout = 5000");
    const move = database.prepare("UPDATE file_shares SET created_at = ?, expires_at = ? WHERE id = ?");
    // The server stores an id as 32 hex digits without hyphens.
    let changed = Number(move.run(LONG_AGO, A_DAY_LATER, shareId.replaceAll("-", "")).changes);
    if (changed === 0) changed = Number(move.run(LONG_AGO, A_DAY_LATER, shareId).changes);
    if (changed !== 1) throw new Error(`Expected to move one share into the past, moved ${changed}`);
  } finally {
    database.close();
  }
}

// ---- Where a share token may and may not be ---------------------------------------------------

/** A token is a secret to anyone who reads a log, so it never goes into a failure message. */
function hideToken(text: string): string {
  return text.replace(/(\/shares?\/)[A-Za-z0-9_-]{20,}/g, "$1<token>");
}

/** Every place in the page that could hold the token, other than the address bar. */
export function whereIsToken(page: Page, token: string): Promise<string[]> {
  return page.evaluate((secret) => {
    const found: string[] = [];
    if (document.title.includes(secret)) found.push("the document title");
    if (document.documentElement.outerHTML.includes(secret)) found.push("the page markup");
    if (document.cookie.includes(secret)) found.push("a cookie");
    if (window.name.includes(secret)) found.push("the window name");
    for (const [name, store] of [
      ["localStorage", window.localStorage],
      ["sessionStorage", window.sessionStorage],
    ] as const) {
      for (let index = 0; index < store.length; index += 1) {
        const key = store.key(index) ?? "";
        if (key.includes(secret) || (store.getItem(key) ?? "").includes(secret)) found.push(name);
      }
    }
    for (const field of document.querySelectorAll<HTMLInputElement | HTMLTextAreaElement>("input, textarea")) {
      if (field.value.includes(secret)) found.push("a field's value");
    }
    if (JSON.stringify(window.history.state ?? null).includes(secret)) found.push("the history state");
    return [...new Set(found)];
  }, token);
}

/** Passes when the token is nowhere in the page, except in the places the caller allows. */
export async function expectTokenAbsent(
  page: Page,
  token: string,
  what: string,
  allowed: readonly string[] = [],
): Promise<void> {
  const places = (await whereIsToken(page, token)).filter((place) => !allowed.includes(place));
  expect(places, `${what}: the share token was found in`).toEqual([]);
}

// ---- A visitor who has only the link ----------------------------------------------------------

/** A browser that shares nothing with the console, and a record of everything that happened in it. */
export interface Visitor {
  readonly context: BrowserContext;
  /** The first page of the visit. */
  readonly page: Page;
  /** Every request any page of the visit made. */
  readonly requests: readonly NetworkRequest[];
  /** Every download any page of the visit started. */
  readonly downloads: readonly Download[];
  /** Console errors, uncaught errors, failed requests, unexpected HTTP errors and CSP violations. */
  readonly problems: readonly string[];
  /** HTTP statuses the visit provokes on purpose. */
  expectStatus(...statuses: number[]): void;
  newPage(): Promise<Page>;
  close(): Promise<void>;
}

/**
 * Opens a new browser context with the same settings the specs run with (the shared fixtures give
 * a fresh context none of them), and watches it the way the `guard` fixture watches the console's
 * page: a console error, an uncaught error, a failed request, an unexpected HTTP error status or a
 * CSP violation is a problem.
 */
export async function openVisitor(browser: Browser, origin: string): Promise<Visitor> {
  const context = await browser.newContext({
    baseURL: origin,
    locale: "en-US",
    timezoneId: "UTC",
    colorScheme: "dark",
    reducedMotion: "reduce",
    serviceWorkers: "block",
    viewport: { width: 1440, height: 900 },
  });
  const requests: NetworkRequest[] = [];
  const downloads: Download[] = [];
  const problems: string[] = [];
  const statuses = new Set<number>();

  await context.exposeFunction("__cfReportCsp", (detail: string) => {
    problems.push(`CSP violation: ${hideToken(detail)}`);
  });
  await context.addInitScript(() => {
    document.addEventListener("securitypolicyviolation", (event) => {
      const report = window as unknown as { __cfReportCsp(detail: string): void };
      report.__cfReportCsp(`${event.violatedDirective}: ${event.blockedURI || "inline"}`);
    });
  });

  context.on("request", (request) => {
    requests.push(request);
  });
  context.on("console", (message) => {
    if (message.type() !== "error" && message.type() !== "warning") return;
    // After a download the browser opens its own downloads page in this context and logs its own
    // warnings there. Those come from the browser's pages, not from the site under test.
    if (message.location().url.startsWith("edge://")) return;
    const text = message.text();
    if (text.startsWith("Failed to load resource:")) return;
    problems.push(`console ${message.type()}: ${hideToken(text)}`);
  });
  context.on("weberror", (webError) => {
    problems.push(`uncaught error: ${hideToken(webError.error().message)}`);
  });
  context.on("requestfailed", (request) => {
    const reason = request.failure()?.errorText ?? "unknown";
    if (reason === "net::ERR_ABORTED") return;
    problems.push(`request failed: ${request.method()} ${hideToken(request.url())} (${reason})`);
  });
  context.on("response", (response) => {
    const status = response.status();
    if (status >= 400 && !statuses.has(status)) {
      problems.push(`HTTP ${status}: ${response.request().method()} ${hideToken(response.url())}`);
    }
  });

  const track = (page: Page): Page => {
    page.on("download", (download) => {
      downloads.push(download);
    });
    return page;
  };

  return {
    context,
    page: track(await context.newPage()),
    requests,
    downloads,
    problems,
    expectStatus: (...expected) => {
      for (const status of expected) statuses.add(status);
    },
    newPage: async () => track(await context.newPage()),
    close: () => context.close(),
  };
}

const SHARE_API = /^\/api\/v1\/shares\/[A-Za-z0-9_-]+(?:\/download)?$/;
const SHARE_PAGE = /^\/share\/[A-Za-z0-9_-]+$/;
const STATIC_FILE = /^\/(?:assets\/[\w.-]+|favicon\.svg)$/;

/**
 * Passes when everything the visitor's browser asked for is this site's share API, the share page
 * itself or one of its static files, and none of it carried an `Authorization` header, a cookie or a
 * referrer, and the browser holds no cookie at all.
 */
export async function expectPublicTraffic(visitor: Visitor, origin: string): Promise<void> {
  const strays: string[] = [];
  const leaks: string[] = [];
  let apiCalls = 0;
  for (const request of visitor.requests) {
    const url = new URL(request.url());
    // Data and blob addresses never leave the browser.
    if (url.protocol !== "http:" && url.protocol !== "https:") continue;
    const what = `${request.method()} ${hideToken(url.origin + url.pathname)}`;
    if (url.origin !== new URL(origin).origin) {
      strays.push(`${what} (another site)`);
      continue;
    }
    if (SHARE_API.test(url.pathname)) apiCalls += 1;
    else if (!SHARE_PAGE.test(url.pathname) && !STATIC_FILE.test(url.pathname)) strays.push(what);
    const headers = await request.allHeaders();
    for (const name of ["authorization", "cookie", "referer"]) {
      // A request answered from the browser's cache reports an empty Referer, which sends nothing.
      if ((headers[name] ?? "") !== "") leaks.push(`${what} carries a ${name} header`);
    }
  }
  expect(strays, "requests the public page made to anything but the share API and its own files").toEqual([]);
  expect(leaks, "credentials or a referrer sent by the public page").toEqual([]);
  expect(apiCalls, "calls the public page made to the share API").toBeGreaterThan(0);
  expect(await visitor.context.cookies(), "cookies kept by the public page").toEqual([]);
}

// ---- Accessibility ------------------------------------------------------------------------------

// WCAG 2.2 level AA, plus axe's own best-practice rules (landmarks, heading order, ...).
const AXE_TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa", "best-practice"];

// axe cannot work out the colour behind text that sits on a gradient or beside a decorative
// pseudo-element, and reports those checks as "incomplete" instead of failing them. So the contrast
// audit paints the glass one flat colour that is lighter than the glass ever gets (light text that
// clears 4.5:1 on it clears it on the real, darker panels) and hides the decoration.
const FLAT_GLASS = "#1a2244";
const FLATTEN = `
  .cf-atmosphere, .cf-lamp, .cf-sweep { display: none !important; }
  *::before, *::after { display: none !important; }
  .hud-panel { background: ${FLAT_GLASS} !important; box-shadow: none !important; }
  .text-gradient { background: none !important; color: var(--color-arc) !important; }
`;

type AxeNode = Violation["nodes"][number];

// Short text and symbols are skipped by default because they may be icons. Here they are all text.
// Per-check options work at run time; axe's typings only list the options for rules.
const MEASURE_EVERYTHING = {
  checks: { "color-contrast": { options: { ignoreLength: true, ignoreUnicode: false } } },
} as unknown as Parameters<AxeBuilder["options"]>[0];

interface Measured {
  fgColor?: string;
  bgColor?: string;
  contrastRatio?: number;
  expectedContrastRatio?: string;
}

function dimness(node: AxeNode): string {
  const { fgColor, bgColor, contrastRatio, expectedContrastRatio } = (node.any[0]?.data ?? {}) as Measured;
  return `${node.target.join(" > ")}: ${fgColor} on ${bgColor} is ${contrastRatio}:1, needs ${expectedContrastRatio}\n      ${node.html.slice(0, 160)}`;
}

/** The text colour of each element against the flat glass, for the text axe could not measure. */
function dimOnGlass(page: Page, selectors: readonly string[]): Promise<string[]> {
  return page.evaluate(
    ({ selectors: targets, glass }) => {
      const painter = document.createElement("canvas").getContext("2d");
      if (!painter) throw new Error("There is no canvas to read colours with.");
      // The canvas turns any CSS colour (these are often color-mix() results) into plain sRGB.
      const read = (css: string): number[] => {
        painter.fillStyle = "#000000";
        painter.fillStyle = css;
        const value = painter.fillStyle;
        if (value.startsWith("#")) {
          return [1, 3, 5].map((start) => parseInt(value.slice(start, start + 2), 16)).concat(1);
        }
        const [r = 0, g = 0, b = 0, a = 1] = value
          .replace(/^rgba?\(|\)$/g, "")
          .split(",")
          .map(Number);
        return [r, g, b, a];
      };
      const channel = (value: number): number => {
        const part = value / 255;
        return part <= 0.03928 ? part / 12.92 : ((part + 0.055) / 1.055) ** 2.4;
      };
      const luminance = (colour: readonly number[]): number =>
        0.2126 * channel(colour[0] ?? 0) + 0.7152 * channel(colour[1] ?? 0) + 0.0722 * channel(colour[2] ?? 0);

      const ground = read(glass);
      const dim: string[] = [];
      for (const selector of targets) {
        const element = document.querySelector(selector);
        if (!element) continue;
        const style = getComputedStyle(element);
        const [r = 0, g = 0, b = 0, alpha = 1] = read(element instanceof SVGElement ? style.fill : style.color);
        const ink = [r, g, b].map((value, index) => value * alpha + (ground[index] ?? 0) * (1 - alpha));
        const lights = [luminance(ink), luminance(ground)].sort((first, second) => second - first);
        const ratio = ((lights[0] ?? 0) + 0.05) / ((lights[1] ?? 0) + 0.05);
        const size = parseFloat(style.fontSize);
        const needs = size >= 24 || (size >= 18.66 && Number(style.fontWeight) >= 700) ? 3 : 4.5;
        if (ratio < needs) {
          dim.push(`${selector}: ${ratio.toFixed(2)}:1, needs ${needs}:1 ("${(element.textContent ?? "").trim().slice(0, 40)}")`);
        }
      }
      return dim;
    },
    { selectors, glass: FLAT_GLASS },
  );
}

/**
 * Passes when axe finds no WCAG 2.2 AA or best-practice problem in the page as it is now, and
 * every piece of text is readable on the lightest the glass gets. The contrast audit leaves a
 * stylesheet behind, so a page is audited once: load it again for the next look.
 */
export async function expectAccessible(page: Page, what: string): Promise<void> {
  await settle(page);
  const { violations } = await new AxeBuilder({ page }).withTags(AXE_TAGS).analyze();
  expect(violations.map(summarise), `accessibility problems: ${what}`).toEqual([]);

  // A constructed stylesheet, because the page's own policy forbids a <style> element.
  await page.evaluate((css) => {
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(css);
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
  }, FLATTEN);
  // Options first: withRules() sets the run options and options() replaces them.
  const result = await new AxeBuilder({ page }).options(MEASURE_EVERYTHING).withRules(["color-contrast"]).analyze();
  const dim = result.violations.flatMap((rule) => rule.nodes).map(dimness);
  const unmeasured = result.incomplete
    .flatMap((rule) => rule.nodes)
    .flatMap((node) => (typeof node.target[0] === "string" ? [node.target[0]] : []));
  dim.push(...(await dimOnGlass(page, unmeasured)));
  expect(dim, `text that is hard to read: ${what}`).toEqual([]);
}
