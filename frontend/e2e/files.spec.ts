import type { Locator, Page, Response as NetworkResponse } from "@playwright/test";

import type {
  ActivityItem,
  ActivityList,
  FileList as StoredFiles,
  PublicShareInfo,
  StoredFileDetail,
} from "../src/types/files";
import {
  blobNames,
  bytesOf,
  expectAccessible,
  expectPublicTraffic,
  expectTokenAbsent,
  expireShare,
  fetchActivity,
  fetchFile,
  fetchFiles,
  flipOneByte,
  istText,
  makeShare,
  newBlob,
  openVisitor,
  removeFile,
  revokeViaApi,
  savedBytes,
  sha256,
  statusOf,
  storeFile,
  storedFile,
  uniqueTag,
  unknownToken,
} from "./files-api";
import { expect, test as base } from "./fixtures";
import { attack, expectInert, watchDialogs } from "./hostile";
import { expectFits, expectOnScreen, expectTextInPlace } from "./layout";
import { exactly, must } from "./text";

/**
 * Encrypted file sharing, in a real browser against the real API: the console at /files and the
 * page a stranger gets from a link. The API is used to set a test up, to clear it away and as an
 * oracle for what the pages should say; everything the pages are for is done in the pages.
 */

interface Vault {
  /** Letters and digits found nowhere else, put into the name of every file the test makes. */
  readonly tag: string;
  /** Marks a file the test made, so that it is deleted when the test ends. */
  keep(id: string): void;
}

/** A test that leaves the database and the folder of encrypted blobs as it found them. */
const test = base.extend<{ vault: Vault }>({
  vault: async ({ request }, use) => {
    const tag = uniqueTag();
    const kept = new Set<string>();
    const blobsBefore = await blobNames();
    await use({
      tag,
      keep: (id) => {
        kept.add(id);
      },
    });

    for (const file of await fetchFiles(request)) {
      if (file.name.includes(tag)) kept.add(file.id);
    }
    for (const id of kept) await removeFile(request, id);
    const left = (await fetchFiles(request)).filter((file) => file.name.includes(tag));
    expect(
      left.map((file) => file.id),
      "files the test left behind",
    ).toEqual([]);
    expect(await blobNames(), "encrypted blobs the test left on disk").toEqual(blobsBefore);
  },
});

test.use({ reducedMotion: "reduce" });

// ---- What the pages call things ----------------------------------------------------------------

const ACTIONS: Readonly<Record<string, string>> = {
  FILE_CREATE: "File uploaded",
  SHARE_CREATE: "Link created",
  SHARE_DOWNLOAD: "File downloaded",
  SHARE_DOWNLOAD_REJECTED: "Download refused",
  SHARE_PASSWORD_FAILED: "Wrong password",
  SHARE_EXPIRED: "Expired link opened",
  SHARE_REVOKE: "Link revoked",
  SHARE_LIMIT_REACHED: "Download limit reached",
  FILE_INTEGRITY_FAILED: "Integrity check failed",
  FILE_DELETE: "File deleted",
};

const RESULTS: Readonly<Record<string, string>> = {
  success: "Success",
  rejected: "Rejected",
  partial: "Partial",
  failed: "Failed",
};

const REASONS: Readonly<Record<string, string>> = {
  revoked: "The link had been revoked",
  expired: "The link had expired",
  limit_reached: "The download limit was used up",
  file_unavailable: "The file could not be read or verified",
  password_required: "A password was needed and none was given",
  invalid_password: "The password was wrong",
  authentication_failed: "The encrypted data failed its authenticity check",
};

/** What a stranger is told about a link that cannot be used. */
const MESSAGES = {
  unknown: "This link does not work",
  expired: "This link has expired",
  revoked: "This link has been revoked",
  limit: "This link has reached its download limit",
  integrity: "This file could not be verified and was not released",
} as const;

const SCREENS = [
  { width: 320, height: 640 },
  { width: 390, height: 844 },
  { width: 768, height: 1024 },
  { width: 1440, height: 900 },
] as const;

// ---- Finding things on the pages -------------------------------------------------------------

/** Eight characters of an id, which is all the console shows of one. */
function short(id: string): string {
  return id.slice(0, 8);
}

function originOf(baseURL: string | undefined): string {
  return new URL(must(baseURL, "a base URL")).origin;
}

function panel(page: Page, title: string): Locator {
  return page.locator("section").filter({ has: page.getByRole("heading", { level: 2, name: title, exact: true }) });
}

/** The value beside a term of a definition list, such as the "Size" of a file. */
function fact(scope: Locator, term: string): Locator {
  return scope.locator("dt", { hasText: exactly(term) }).locator("xpath=following-sibling::dd[1]");
}

function fileRow(page: Page, name: string): Locator {
  return page.getByRole("row").filter({ has: page.getByRole("link", { name, exact: true }) });
}

function shareRow(page: Page, shareId: string): Locator {
  return panel(page, "Share links").getByRole("row").filter({ hasText: short(shareId) });
}

function uploadButton(page: Page): Locator {
  return page.getByRole("button", { name: "Encrypt and upload" });
}

function uploaded(page: Page): Locator {
  return page.getByRole("status").filter({ hasText: "is encrypted and stored" });
}

function newLinkPanel(page: Page): Locator {
  return page.getByRole("region", { name: "Your new share link" });
}

function downloadButton(page: Page): Locator {
  return page.getByRole("button", { name: "Download", exact: true });
}

/** Picks a file the way a person does: through the "choose a file" link and the browser's own chooser. */
async function choose(page: Page, name: string, data: Buffer): Promise<void> {
  const chooser = page.waitForEvent("filechooser");
  await page.getByText("choose a file", { exact: true }).click();
  await (await chooser).setFiles({ name, mimeType: "application/octet-stream", buffer: data });
}

async function chooseAndUpload(page: Page, name: string, data: Buffer): Promise<Locator> {
  await choose(page, name, data);
  await uploadButton(page).click();
  await expect(uploaded(page)).toBeVisible();
  return uploaded(page);
}

function tokenOf(link: string, origin: string): string {
  const prefix = `${origin}/share/`;
  expect(link.startsWith(prefix), "the link starts with this site's address and /share/").toBe(true);
  const token = link.slice(prefix.length);
  expect(/^[A-Za-z0-9_-]{43}$/.test(token), "the link ends with a token of 43 URL-safe characters").toBe(true);
  return token;
}

interface LinkOptions {
  hours?: string;
  downloads?: string;
  password?: string;
}

interface MadeLink {
  link: string;
  token: string;
  region: Locator;
}

/** Fills in the form for a new link, submits it, and reads the link from the panel that shows it once. */
async function createLink(page: Page, origin: string, options: LinkOptions = {}): Promise<MadeLink> {
  const form = page.getByRole("form", { name: "Create a share link" });
  if (options.hours !== undefined) await form.getByLabel("Expires after (hours)").fill(options.hours);
  if (options.downloads !== undefined) await form.getByLabel("Maximum downloads").fill(options.downloads);
  if (options.password !== undefined) await form.getByLabel("Password (optional)").fill(options.password);
  await form.getByRole("button", { name: "Create link" }).click();
  const region = newLinkPanel(page);
  await expect(region).toBeVisible();
  const link = await region.getByRole("textbox", { name: "Share link", exact: true }).inputValue();
  return { link, token: tokenOf(link, origin), region };
}

/** Passes when the activity list shows exactly these events, newest first, in India Standard Time. */
async function expectActivity(page: Page, events: readonly ActivityItem[]): Promise<void> {
  const rows = panel(page, "Activity").locator("tbody tr");
  await expect(rows).toHaveCount(events.length);
  for (const [index, event] of events.entries()) {
    const row = rows.nth(index);
    const cells = row.getByRole("cell");
    await expect(row.getByRole("rowheader"), `event ${index + 1}`).toHaveText(
      must(ACTIONS[event.action], `a label for ${event.action}`),
    );
    await expect(cells.nth(0), `time of event ${index + 1}`).toContainText(istText(event.timestamp));
    await expect(cells.nth(1), `result of event ${index + 1}`).toContainText(
      must(RESULTS[event.result], `a label for the result ${event.result}`),
    );
    await expect(cells.nth(2), `link of event ${index + 1}`).toContainText(
      event.share_id === null ? "No link" : short(event.share_id),
    );
    await expect(cells.nth(3), `reason of event ${index + 1}`).toContainText(
      event.reason === null ? "None" : must(REASONS[event.reason], `a label for the reason ${event.reason}`),
    );
  }
}

// ---- Finding things on the public page ---------------------------------------------------------

const DOWNLOAD_PATH = /^\/api\/v1\/shares\/[^/]+\/download$/;

/** Presses Download and returns what the API answered. */
async function pressDownload(page: Page): Promise<NetworkResponse> {
  const [answer] = await Promise.all([
    page.waitForResponse(
      (response) => response.request().method() === "POST" && DOWNLOAD_PATH.test(new URL(response.url()).pathname),
    ),
    downloadButton(page).click(),
  ]);
  return answer;
}

/** A link that cannot be used says so in an alert with one heading, and offers nothing to download. */
async function expectLinkMessage(page: Page, title: string): Promise<void> {
  const alert = page.getByRole("alert");
  await expect(alert.getByRole("heading", { level: 1, name: title, exact: true })).toBeVisible();
  await expect(downloadButton(page)).toHaveCount(0);
  await expect(page.getByLabel("Password", { exact: true })).toHaveCount(0);
}

// ---- Time ------------------------------------------------------------------------------------------

test("the hand-written India Standard Time oracle carries across the clock and the calendar", () => {
  const cases: ReadonlyArray<readonly [string, string]> = [
    ["2026-05-14T12:00:00Z", "14-05-2026 05:30:00 PM IST"],
    ["2026-05-14T06:30:00Z", "14-05-2026 12:00:00 PM IST"],
    ["2026-05-14T18:29:59Z", "14-05-2026 11:59:59 PM IST"],
    ["2026-05-14T18:30:00Z", "15-05-2026 12:00:00 AM IST"],
    ["2026-05-14T00:00:00.123456Z", "14-05-2026 05:30:00 AM IST"],
    ["2026-12-31T20:00:00+00:00", "01-01-2027 01:30:00 AM IST"],
    ["2027-02-28T23:00:00Z", "01-03-2027 04:30:00 AM IST"],
    ["2028-02-28T23:00:00Z", "29-02-2028 04:30:00 AM IST"],
    ["2100-02-28T23:00:00Z", "01-03-2100 04:30:00 AM IST"],
    ["2000-01-02T00:00:00Z", "02-01-2000 05:30:00 AM IST"],
  ];
  for (const [utc, ist] of cases) expect(istText(utc), utc).toBe(ist);
});

// ---- Journey D --------------------------------------------------------------------------------------

test("Journey D: upload, share with a password, download anonymously, revoke and delete", async ({
  page,
  request,
  browser,
  baseURL,
  vault,
}) => {
  test.setTimeout(150_000);
  const origin = originOf(baseURL);
  const blobsBefore = await blobNames();
  const chosenName = `Relev\u00e9 \u00e9t\u00e9: 2026-${vault.tag}.txt`;
  // The server keeps the last part of a path and replaces characters that Windows forbids.
  const storedName = `Relev\u00e9 \u00e9t\u00e9_ 2026-${vault.tag}.txt`;
  const original = bytesOf(`journey-d-${vault.tag}`, 3072);
  const goodPassword = `Pw-${vault.tag}-ok`;
  const wrongPassword = `Pw-${vault.tag}-no`;

  // Everything the console sends, to show that the link goes nowhere once it has been made.
  const sent: string[] = [];
  page.on("request", (made) => {
    sent.push(`${made.url()} ${made.postData() ?? ""}`);
  });
  const visitor = await openVisitor(browser, origin);
  visitor.expectStatus(403, 404, 410);

  try {
    const stored = await test.step("choose a file and encrypt it", async () => {
      await page.goto("/files");
      await expect(page).toHaveTitle("Files \u00b7 CipherForge");
      await expect(page.getByText("No file chosen.")).toBeVisible();

      await choose(page, chosenName, original);
      await expect(page.getByText(/^Chosen: /)).toHaveText(`Chosen: ${chosenName} (3.00 KB)`);
      await uploadButton(page).click();
      await expect(uploaded(page)).toContainText(`${storedName} is encrypted and stored (3.00 KB).`);

      const file = await storedFile(request, storedName);
      vault.keep(file.id);
      expect(file).toMatchObject({
        size_bytes: 3072,
        status: "active",
        algorithm: "AES-256-GCM",
        share_count: 0,
        active_share_count: 0,
      });
      await expect(uploaded(page).getByRole("link", { name: "Share this file" })).toHaveAttribute(
        "href",
        `/files?file=${file.id}`,
      );

      await expect(
        panel(page, "Your files").locator("tbody tr").first().getByRole("link", { name: storedName, exact: true }),
      ).toBeVisible();
      const cells = fileRow(page, storedName).getByRole("cell");
      await expect(cells.nth(0)).toHaveText("3.00 KB");
      await expect(cells.nth(1)).toContainText(istText(file.created_at));
      await expect(cells.nth(2)).toContainText("Ready");
      await expect(cells.nth(3)).toHaveText("No links");
      return file;
    });

    await test.step("open the file", async () => {
      await fileRow(page, storedName).getByRole("link", { name: storedName, exact: true }).click();
      await expect(page).toHaveURL(`${origin}/files?file=${stored.id}`);
      await expect(page.getByRole("link", { name: storedName, exact: true })).toHaveAttribute("aria-current", "true");

      const details = panel(page, "File details");
      await expect(details.getByRole("heading", { level: 3, name: storedName, exact: true })).toBeFocused();
      await expect(fact(details, "Size")).toHaveText("3.00 KB");
      await expect(fact(details, "Uploaded")).toContainText(istText(stored.created_at));
      await expect(fact(details, "State")).toContainText("Ready");
      await expect(fact(details, "Encryption")).toHaveText("AES-256-GCM");
      await expect(fact(details, "Links")).toHaveText("No links");
      await expect(panel(page, "Share links")).toContainText("No links have been made for this file yet.");
    });

    const made = await test.step("make a link that needs a password and allows two downloads", async () => {
      const form = page.getByRole("form", { name: "Create a share link" });
      await expect(form.getByLabel("Expires after (hours)")).toHaveValue("24");
      await expect(form.getByLabel("Maximum downloads")).toHaveValue("1");
      const password = form.getByLabel("Password (optional)");
      await expect(password).toHaveValue("");
      await expect(password).toHaveAttribute("type", "password");
      await expect(password).toHaveAttribute("autocomplete", "new-password");

      await password.fill(goodPassword);
      await form.getByRole("button", { name: "Show password" }).click();
      await expect(password).toHaveAttribute("type", "text");
      await form.getByRole("button", { name: "Hide password" }).click();
      await expect(password).toHaveAttribute("type", "password");

      const { link, token, region } = await createLink(page, origin, { hours: "2", downloads: "2" });
      await expect(region.getByRole("heading", { level: 3, name: "Your new share link" })).toBeFocused();
      await expect(password, "the password is cleared once the link is made").toHaveValue("");

      const detail = await fetchFile(request, stored.id);
      expect(detail.shares).toHaveLength(1);
      const share = must(detail.shares[0]);
      expect(share).toMatchObject({
        max_downloads: 2,
        download_count: 0,
        downloads_remaining: 2,
        password_protected: true,
        status: "active",
        last_downloaded_at: null,
        revoked_at: null,
      });
      const lifetime = Date.parse(share.expires_at) - Date.parse(share.created_at);
      expect(Math.abs(lifetime - 2 * 3_600_000), "the link lasts two hours").toBeLessThan(5_000);

      await expect(region).toContainText("this link is shown only once");
      await expect(region).toContainText("as long as they also know the password you set");
      await expect(fact(region, "Expires")).toContainText(istText(share.expires_at));
      await expect(fact(region, "Downloads allowed")).toHaveText("2 downloads");
      await expect(fact(region, "Password")).toHaveText("Needed to download");

      await page.context().grantPermissions(["clipboard-read", "clipboard-write"], { origin });
      await region.getByRole("button", { name: "Copy link" }).click();
      await expect(region.getByRole("status")).toHaveText("The link is on your clipboard.");
      await expect(region.getByRole("button", { name: "Copied" })).toBeVisible();
      const onClipboard = await page.evaluate(() => navigator.clipboard.readText());
      expect(onClipboard === link, "the clipboard holds the link").toBe(true);

      await expect(page).toHaveTitle("Files \u00b7 CipherForge");
      await expectTokenAbsent(page, token, "the console showing the link", ["the page markup", "a field's value"]);
      return { link, token, share };
    });

    await test.step("a stranger opens the link and is offered a file whose name is hidden", async () => {
      const stranger = visitor.page;
      await stranger.goto(made.link);
      await expect(stranger.getByRole("heading", { level: 1 })).toHaveText("A password-protected file");
      await expect(stranger).toHaveTitle("Shared file \u00b7 CipherForge");
      await expect(stranger.getByRole("navigation")).toHaveCount(0);
      await expect(stranger.getByRole("banner")).toHaveCount(0);

      const main = stranger.getByRole("main");
      await expect(main).toContainText("CIPHERFORGE");
      await expect(main).not.toContainText(storedName);
      await expect(fact(main, "Size")).toHaveText("3.00 KB");
      await expect(fact(main, "Link expires")).toContainText(istText(made.share.expires_at));
      await expect(fact(main, "Downloads left")).toHaveText("2");
      const password = stranger.getByLabel("Password", { exact: true });
      await expect(password).toHaveAttribute("type", "password");
      await expect(password).toHaveAttribute("autocomplete", "current-password");

      await expectTokenAbsent(stranger, made.token, "the public page");
      expect(await stranger.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
    });

    await test.step("a wrong password is refused and costs nothing", async () => {
      const stranger = visitor.page;
      const password = stranger.getByLabel("Password", { exact: true });
      await password.fill(wrongPassword);
      const answer = await pressDownload(stranger);
      expect(answer.status()).toBe(403);

      const alert = stranger.getByRole("alert");
      await expect(alert).toContainText("That password is not correct");
      await expect(alert).toContainText("Check the password you were given and try again.");
      await expect(password).toHaveValue(wrongPassword);
      await expect(password).toBeFocused();
      await expect(password).toHaveAttribute("aria-invalid", "true");
      expect(visitor.downloads).toHaveLength(0);

      const detail = await fetchFile(request, stored.id);
      expect(must(detail.shares[0]).download_count, "downloads used by a wrong password").toBe(0);
    });

    await test.step("the right password releases the file, byte for byte", async () => {
      const stranger = visitor.page;
      await stranger.getByLabel("Password", { exact: true }).fill(goodPassword);
      const [download] = await Promise.all([stranger.waitForEvent("download"), downloadButton(stranger).click()]);

      expect(download.suggestedFilename()).toBe(storedName);
      expect(download.url().startsWith("blob:"), "the file is saved from the browser's own memory").toBe(true);
      expect(sha256(await savedBytes(download))).toBe(sha256(original));

      await expect(stranger.getByRole("heading", { level: 1, name: "Your download has started" })).toBeFocused();
      const main = stranger.getByRole("main");
      await expect(main).toContainText(storedName);
      await expect(main).toContainText("This link can be used 1 more time.");
      await expectTokenAbsent(stranger, made.token, "the page after the download");
      await expectTokenAbsent(stranger, goodPassword, "the page after the download");
      expect(stranger.url().includes(goodPassword), "the address bar").toBe(false);
    });

    const used = await test.step("the owner sees one download and the whole story in India Standard Time", async () => {
      await page.reload();
      await expect(newLinkPanel(page), "the link is shown only once").toHaveCount(0);
      await expectTokenAbsent(page, made.token, "the console after a reload");

      const detail = await fetchFile(request, stored.id);
      const share = must(detail.shares[0]);
      expect(share).toMatchObject({
        download_count: 1,
        downloads_remaining: 1,
        status: "active",
        password_protected: true,
      });
      const row = shareRow(page, share.id);
      await expect(row).toContainText("Active");
      await expect(row).toContainText("Password");
      await expect(row).toContainText(/1 \/ 2\s*used/);
      await expect(row).toContainText("1 download left");
      await expect(row).toContainText(istText(share.created_at));
      await expect(row).toContainText(istText(share.expires_at));
      await expect(row).toContainText(istText(must(share.last_downloaded_at)));
      await expect(row).toContainText("Not revoked");
      await expect(fact(panel(page, "File details"), "Links")).toHaveText("1 active of 1 link");

      const events = await fetchActivity(request, stored.id);
      expect(events.map((event) => event.action)).toEqual([
        "SHARE_DOWNLOAD",
        "SHARE_PASSWORD_FAILED",
        "SHARE_CREATE",
        "FILE_CREATE",
      ]);
      expect(events[1]).toMatchObject({ result: "rejected", reason: "invalid_password", share_id: share.id });
      await expectActivity(page, events);
      return share;
    });

    await test.step("the owner revokes the link while a stranger holds it open", async () => {
      const waiting = await visitor.newPage();
      await waiting.goto(made.link);
      await expect(waiting.getByLabel("Password", { exact: true })).toBeVisible();

      const revoke = shareRow(page, used.id).getByRole("button", { name: `Revoke link ${short(used.id)}` });
      await revoke.click();
      const dialog = page.getByRole("dialog", { name: "Revoke this link?", exact: true });
      await expect(dialog).toContainText(`Link ${short(used.id)}, protected by a password`);
      await expect(dialog).toContainText("1 of 2 downloads used");
      await dialog.getByRole("button", { name: "Cancel" }).click();
      await expect(dialog).toBeHidden();
      expect(must((await fetchFile(request, stored.id)).shares[0]).status, "after cancelling").toBe("active");

      await revoke.click();
      await dialog.getByRole("button", { name: "Revoke link", exact: true }).click();
      await expect(page.getByRole("status").filter({ hasText: "was revoked" })).toContainText(
        `Link ${short(used.id)} was revoked. It no longer works.`,
      );

      const revoked = must((await fetchFile(request, stored.id)).shares[0]);
      expect(revoked.status).toBe("revoked");
      const row = shareRow(page, used.id);
      await expect(row).toContainText("Revoked");
      await expect(row).toContainText(istText(must(revoked.revoked_at)));
      await expect(revoke, "a revoked link cannot be revoked again").toBeDisabled();
      await expect(fact(panel(page, "File details"), "Links")).toHaveText("0 active of 1 link");

      // The stranger who was already looking at the password box is told, and gets nothing.
      await waiting.getByLabel("Password", { exact: true }).fill(goodPassword);
      await downloadButton(waiting).click();
      await expectLinkMessage(waiting, MESSAGES.revoked);
      expect(visitor.downloads, "downloads after the link was revoked").toHaveLength(1);

      await visitor.page.goto(made.link);
      await expectLinkMessage(visitor.page, MESSAGES.revoked);

      await page.getByRole("button", { name: "Refresh activity" }).click();
      const events = await fetchActivity(request, stored.id);
      expect(events.slice(0, 3).map((event) => event.action)).toEqual([
        "SHARE_DOWNLOAD_REJECTED",
        "SHARE_DOWNLOAD_REJECTED",
        "SHARE_REVOKE",
      ]);
      expect(events[0]).toMatchObject({ result: "rejected", reason: "revoked" });
      await expectActivity(page, events);
    });

    await test.step("the owner deletes the file", async () => {
      await page.getByRole("button", { name: "Delete file", exact: true }).click();
      const dialog = page.getByRole("dialog", { name: "Delete this file?", exact: true });
      await expect(dialog).toContainText(storedName);
      await expect(dialog).toContainText("Every share link made for it stops working immediately");
      await dialog.getByRole("button", { name: "Delete file", exact: true }).click();

      await expect(page.getByRole("status").filter({ hasText: "was deleted" })).toContainText(
        `${storedName} was deleted. Every link made for it stopped working.`,
      );
      await expect(fileRow(page, storedName)).toHaveCount(0);
      await expect(page).toHaveURL(`${origin}/files`);
      expect(await statusOf(request, `/api/v1/files/${stored.id}`)).toBe(404);
      expect(await blobNames(), "the encrypted blob is removed with the file").toEqual(blobsBefore);

      await visitor.page.goto(made.link);
      await expectLinkMessage(visitor.page, MESSAGES.unknown);
    });

    await expectPublicTraffic(visitor, origin);
    expect(visitor.problems, "what the stranger's browser reported").toEqual([]);
    expect(
      sent.some((entry) => entry.includes(made.token)),
      "the console sent the share token somewhere",
    ).toBe(false);
  } finally {
    await visitor.close();
  }
});

// ---- Tampering ------------------------------------------------------------------------------------

test("a file that was tampered with is never released", async ({ page, request, browser, baseURL, vault }) => {
  test.setTimeout(90_000);
  const origin = originOf(baseURL);
  const name = `tamper-${vault.tag}.txt`;
  const marker = `PLAINTEXT-MARKER-${vault.tag}`;
  const plaintext = Buffer.from(marker.repeat(Math.ceil(2048 / marker.length))).subarray(0, 2048);
  const blobsBefore = await blobNames();
  const visitor = await openVisitor(browser, origin);
  visitor.expectStatus(409);

  try {
    await page.goto("/files");
    const done = await chooseAndUpload(page, name, plaintext);
    const stored = await storedFile(request, name);
    vault.keep(stored.id);

    // Flipping one byte inside the ciphertext keeps the size, so only the authentication tag can notice.
    const size = await flipOneByte(await newBlob(blobsBefore));
    expect(size, "the encrypted blob is the file plus a 16-byte tag").toBe(plaintext.length + 16);

    await done.getByRole("link", { name: "Share this file" }).click();
    await expect(page).toHaveURL(`${origin}/files?file=${stored.id}`);
    const { link, token } = await createLink(page, origin);

    const stranger = visitor.page;
    await stranger.goto(link);
    await expect(stranger.getByRole("heading", { level: 1 })).toHaveText(name);
    await expect(fact(stranger.getByRole("main"), "Size")).toHaveText("2.00 KB");

    const answer = await pressDownload(stranger);
    expect(answer.status()).toBe(409);
    expect(answer.headers()["content-type"]).toContain("json");
    expect(answer.headers()["content-disposition"], "a file name for a file that was not released").toBeUndefined();
    expect(await answer.text(), "the body of the refusal").not.toContain(marker);
    await expectLinkMessage(stranger, MESSAGES.integrity);
    expect(visitor.downloads).toHaveLength(0);

    await stranger.reload();
    await expectLinkMessage(stranger, MESSAGES.integrity);
    expect(visitor.downloads).toHaveLength(0);
    await expectAccessible(stranger, "the message for a file that failed its check");
    expect(await stranger.getByRole("main").innerText()).not.toContain(marker);
    await expectTokenAbsent(stranger, token, "the public page after a refusal");

    await page.reload();
    const cells = fileRow(page, name).getByRole("cell");
    await expect(cells.nth(2)).toContainText("Integrity problem");
    await expect(cells.nth(3)).toHaveText("Cannot be shared");
    const details = panel(page, "File details");
    await expect(details.getByRole("note")).toContainText("Integrity problem");
    await expect(fact(details, "State")).toContainText("Integrity problem");
    const form = page.getByRole("form", { name: "Create a share link" });
    await expect(form).toContainText("This file failed its integrity check, so it cannot be shared.");
    await expect(form.getByRole("button", { name: "Create link" })).toBeDisabled();
    expect((await fetchFile(request, stored.id)).status).toBe("corrupt");

    const events = await fetchActivity(request, stored.id);
    const failure = must(events.find((event) => event.action === "FILE_INTEGRITY_FAILED"));
    expect(failure).toMatchObject({ result: "failed", reason: "authentication_failed" });
    await expectActivity(page, events);
    const failedRow = panel(page, "Activity")
      .locator("tbody tr")
      .filter({ has: page.getByRole("rowheader", { name: "Integrity check failed", exact: true }) });
    await expect(failedRow).toContainText(istText(failure.timestamp));
    await expect(failedRow).toContainText("Failed");
    await expect(failedRow).toContainText("The encrypted data failed its authenticity check");

    await page.getByRole("button", { name: "Delete file", exact: true }).click();
    await page
      .getByRole("dialog", { name: "Delete this file?", exact: true })
      .getByRole("button", { name: "Delete file", exact: true })
      .click();
    await expect(page.getByRole("status").filter({ hasText: "was deleted" })).toBeVisible();
    expect(await statusOf(request, `/api/v1/files/${stored.id}`)).toBe(404);
    expect(await blobNames(), "the tampered blob is removed with the file").toEqual(blobsBefore);

    await expectPublicTraffic(visitor, origin);
    expect(visitor.problems, "what the stranger's browser reported").toEqual([]);
  } finally {
    await visitor.close();
  }
});

// ---- Links that cannot be used ------------------------------------------------------------------

test("public link failure states are readable and release nothing", async ({ page, request, vault, guard }) => {
  guard.expectStatus(404, 410);
  const saved: string[] = [];
  page.on("download", (download) => {
    saved.push(download.suggestedFilename());
  });

  const file = await storeFile(request, `states-${vault.tag}.txt`, bytesOf(vault.tag, 600));
  vault.keep(file.id);
  const limited = await makeShare(request, file.id, { max_downloads: 1 });
  const revoked = await makeShare(request, file.id);
  const expired = await makeShare(request, file.id);
  await revokeViaApi(request, file.id, revoked.share.id);
  await expireShare(expired.share.id);

  await test.step("a link with one download works exactly once", async () => {
    await page.goto(limited.path);
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(file.name);
    const download = page.waitForEvent("download");
    await downloadButton(page).click();
    expect((await download).suggestedFilename()).toBe(file.name);
    await expect(page.getByText("This link has no downloads left.")).toBeVisible();

    await page.goto(limited.path);
    await expectLinkMessage(page, MESSAGES.limit);
    await expect(page.getByRole("alert")).toContainText("they have all been used");
  });

  await test.step("a revoked link, an expired link and links that never existed", async () => {
    await page.goto(revoked.path);
    await expectLinkMessage(page, MESSAGES.revoked);
    await expect(page.getByRole("alert")).toContainText("The sender turned this link off");

    await page.goto(expired.path);
    await expectLinkMessage(page, MESSAGES.expired);
    await expect(page.getByRole("alert")).toContainText("stops working at the time its sender chose");

    await page.goto(`/share/${unknownToken()}`);
    await expectLinkMessage(page, MESSAGES.unknown);
    await page.goto("/share/short");
    await expectLinkMessage(page, MESSAGES.unknown);
    expect(saved, "everything the browser saved").toEqual([file.name]);
  });

  await test.step("the owner sees why each link stopped, in India Standard Time", async () => {
    await page.goto(`/files?file=${file.id}`);
    const detail = await fetchFile(request, file.id);
    const expiredShare = must(detail.shares.find((share) => share.id === expired.share.id));
    expect(istText(expiredShare.expires_at)).toBe("02-01-2000 05:30:00 AM IST");

    const spent = shareRow(page, limited.share.id);
    await expect(spent).toContainText("Limit reached");
    await expect(spent).toContainText(/1 \/ 1\s*used/);
    await expect(spent).toContainText("0 downloads left");
    await expect(shareRow(page, revoked.share.id)).toContainText("Revoked");
    await expect(shareRow(page, expired.share.id)).toContainText("Expired");
    await expect(shareRow(page, expired.share.id)).toContainText("02-01-2000 05:30:00 AM IST");

    const revokeButtons = panel(page, "Share links").getByRole("button", { name: /^Revoke link / });
    await expect(revokeButtons).toHaveCount(3);
    for (const button of await revokeButtons.all()) await expect(button).toBeDisabled();
    await expect(fact(panel(page, "File details"), "Links")).toHaveText("0 active of 3 links");

    const events = await fetchActivity(request, file.id);
    const seen = events.map((event) => `${event.action}:${event.reason ?? ""}`);
    expect(seen).toEqual(
      expect.arrayContaining([
        "SHARE_DOWNLOAD:",
        "SHARE_LIMIT_REACHED:limit_reached",
        "SHARE_DOWNLOAD_REJECTED:revoked",
        "SHARE_EXPIRED:expired",
      ]),
    );
    await expectActivity(page, events);
    const lines = panel(page, "Activity");
    await expect(lines).toContainText("Expired link opened");
    await expect(lines).toContainText("The link had expired");
    await expect(lines).toContainText("Download limit reached");
  });
});

// ---- Hostile names ------------------------------------------------------------------------------------

test("hostile file names stay plain text and fit every screen", async ({ page, request, vault }) => {
  test.setTimeout(240_000);
  watchDialogs(page);
  const markupName = "<img src=x onerror=alert(1)>.txt";
  const bidiName = "report-\u202Egnp.exe";
  const longName = `${"W".repeat(296)}.txt`;
  const hostileEvent: ActivityItem = {
    timestamp: "2026-05-14T12:00:00Z",
    action: attack("markup", "action"),
    result: attack("handler", "result"),
    share_id: null,
    reason: attack("frame", "reason"),
  };
  // The server never stores a name like these, so the API's answers are rewritten on the way in.
  const markup = await storeFile(request, `hostile-a-${vault.tag}.txt`, bytesOf("a", 300));
  const bidi = await storeFile(request, `hostile-b-${vault.tag}.txt`, bytesOf("b", 300));
  const long = await storeFile(request, `hostile-c-${vault.tag}.txt`, bytesOf("c", 300));
  for (const file of [markup, bidi, long]) vault.keep(file.id);
  const names = new Map([
    [markup.id, markupName],
    [bidi.id, bidiName],
    [long.id, longName],
  ]);
  const rename = <T extends { id: string; name: string }>(file: T): T => ({
    ...file,
    name: names.get(file.id) ?? file.name,
  });

  await page.route(
    (url) => url.pathname.startsWith("/api/v1/files") && !url.pathname.includes("/shares"),
    async (route) => {
      if (route.request().method() !== "GET") return route.fallback();
      const response = await route.fetch();
      if (!response.ok()) return route.fulfill({ response });
      const { pathname } = new URL(route.request().url());
      const body: unknown = await response.json();
      let rewritten: unknown = body;
      if (pathname === "/api/v1/files") {
        const list = body as StoredFiles;
        rewritten = { ...list, items: list.items.map(rename) };
      } else if (pathname.endsWith("/activity")) {
        const activity = body as ActivityList;
        rewritten = { ...activity, items: [hostileEvent, ...activity.items] };
      } else if (pathname !== "/api/v1/files/status") {
        rewritten = rename(body as StoredFileDetail);
      }
      return route.fulfill({ status: response.status(), json: rewritten });
    },
  );

  await test.step("names that are markup, that reverse text or that never end are shown as text", async () => {
    await page.goto("/files");
    for (const name of [markupName, bidiName, longName]) {
      await expect(fileRow(page, name).getByRole("link", { name, exact: true })).toHaveText(name);
    }
    await expectInert(page, "the list of files");

    await fileRow(page, markupName).getByRole("link", { name: markupName, exact: true }).click();
    const details = panel(page, "File details");
    await expect(details.getByRole("heading", { level: 3 })).toHaveText(markupName);
    const activity = panel(page, "Activity");
    await expect(activity).toContainText(hostileEvent.action);
    await expect(activity).toContainText(hostileEvent.result);
    await expect(activity).toContainText(hostileEvent.reason ?? "");
    await expect(activity).toContainText("14-05-2026 05:30:00 PM IST");
    await expectInert(page, "a file named like markup, with hostile activity");

    await page.getByRole("button", { name: "Delete file", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Delete this file?", exact: true });
    await expect(dialog).toContainText(markupName);
    await expectInert(page, "the confirmation to delete it");
    await dialog.getByRole("button", { name: "Cancel" }).click();
    await expect(dialog).toBeHidden();

    await fileRow(page, bidiName).getByRole("link", { name: bidiName, exact: true }).click();
    await expect(details.getByRole("heading", { level: 3 })).toHaveText(bidiName);
    await expectInert(page, "a file whose name reverses text");
  });

  await test.step("a name typed with markup is stored as plain text", async () => {
    await page.goto("/files");
    const rawName = `<img src=x onerror=alert(1)>-${vault.tag}.txt`;
    const cleanName = rawName.replace(/[<>]/g, "_");
    await choose(page, rawName, bytesOf("raw", 2048));
    await expect(page.getByText(/^Chosen: /)).toHaveText(`Chosen: ${rawName} (2.00 KB)`);
    await expectInert(page, "the chosen file");
    await uploadButton(page).click();
    await expect(uploaded(page)).toContainText(`${cleanName} is encrypted and stored`);
    const stored = await storedFile(request, cleanName);
    vault.keep(stored.id);
    await expect(fileRow(page, cleanName).getByRole("link", { name: cleanName, exact: true })).toBeVisible();
    await expectInert(page, "the file after it was stored");
  });

  const shared = await makeShare(request, long.id, { max_downloads: 50 });
  // A name that would leave the folder it is saved in, and one that is far too long.
  const evilDisposition =
    "attachment; filename=\"evil.bin\"; filename*=UTF-8''..%2F..%5Cwin%2Fsystem32%2Fevil%E2%80%AEgpj.exe";
  let disposition = evilDisposition;
  await page.route(
    (url) => url.pathname.startsWith("/api/v1/shares/"),
    async (route) => {
      const response = await route.fetch();
      const method = route.request().method();
      if (method === "GET" && response.ok()) {
        const info = (await response.json()) as PublicShareInfo;
        return route.fulfill({ status: response.status(), json: { ...info, file_name: longName } });
      }
      if (method === "POST" && response.ok()) {
        return route.fulfill({
          response,
          headers: { ...response.headers(), "content-disposition": disposition },
        });
      }
      return route.fulfill({ response });
    },
  );

  await test.step("the longest name fits on every screen, in the console and on the public page", async () => {
    for (const screen of SCREENS) {
      const where = `at ${screen.width}px`;
      await page.setViewportSize(screen);

      await page.goto(`/files?file=${long.id}`);
      const details = panel(page, "File details");
      await expect(details.getByRole("heading", { level: 3 })).toHaveText(longName);
      await expect(panel(page, "Activity")).toContainText(hostileEvent.action);
      await expectFits(page, `the console with a file named with 300 characters ${where}`);
      await expectTextInPlace(page, `the console with a file named with 300 characters ${where}`);
      await expectInert(page, `the console ${where}`);

      await page.getByRole("button", { name: "Delete file", exact: true }).click();
      const dialog = page.getByRole("dialog", { name: "Delete this file?", exact: true });
      await expect(dialog).toContainText(longName);
      await expectOnScreen(dialog, screen);
      await expectTextInPlace(page, `the confirmation to delete it ${where}`);
      await dialog.getByRole("button", { name: "Cancel" }).click();
      await expect(dialog).toBeHidden();

      disposition = screen.width === 1440 ? evilDisposition : `attachment; filename*=UTF-8''${longName}`;
      await page.goto(shared.path);
      await expect(page.getByRole("heading", { level: 1 })).toHaveText(longName);
      await expectFits(page, `the public page for a file named with 300 characters ${where}`);
      await expectTextInPlace(page, `the public page ${where}`);
      const [download] = await Promise.all([page.waitForEvent("download"), downloadButton(page).click()]);
      const saved = download.suggestedFilename();
      if (screen.width === 1440) expect(saved, "a name that tried to leave the folder").toBe("evilgpj.exe");
      else expect(saved.length, "the saved name is kept within 255 characters").toBeLessThanOrEqual(255);
      await expect(page.getByRole("heading", { level: 1, name: "Your download has started" })).toBeVisible();
      await expectFits(page, `the page after the download ${where}`);
      await expectInert(page, `the public page ${where}`);
    }
  });
});

// ---- Accessibility ---------------------------------------------------------------------------------------

test("the file screens pass the accessibility audit", async ({ page, request, baseURL, vault }) => {
  test.setTimeout(240_000);
  const origin = originOf(baseURL);
  const file = await storeFile(request, `access-${vault.tag}.txt`, bytesOf(vault.tag, 1500));
  vault.keep(file.id);
  const protectedShare = await makeShare(request, file.id, { password: `Pw-${vault.tag}-ok`, max_downloads: 3 });
  const closed = await makeShare(request, file.id);
  await revokeViaApi(request, file.id, closed.share.id);
  // Opening a revoked link leaves a refusal in the activity, so every kind of result is on screen.
  expect((await request.get(closed.path.replace("/share/", "/api/v1/shares/"))).status()).toBe(410);

  const open = async (): Promise<void> => {
    await page.goto(`/files?file=${file.id}`);
    await expect(shareRow(page, protectedShare.share.id)).toBeVisible();
    await expect(panel(page, "Activity").locator("tbody tr")).not.toHaveCount(0);
  };

  await test.step("the list of files", async () => {
    await page.goto("/files");
    await expect(fileRow(page, file.name)).toBeVisible();
    await expectAccessible(page, "the list of files");
  });

  await test.step("a file with its links and activity", async () => {
    await open();
    await expectAccessible(page, "a file open with its links and activity");
  });

  await test.step("the form for a link, with a problem in every field", async () => {
    await open();
    const form = page.getByRole("form", { name: "Create a share link" });
    const hours = form.getByLabel("Expires after (hours)");
    const downloads = form.getByLabel("Maximum downloads");
    const password = form.getByLabel("Password (optional)");
    await hours.fill("0");
    await downloads.fill("1000");
    await password.fill("short");
    await form.getByRole("button", { name: "Show password" }).click();
    await form.getByRole("button", { name: "Create link" }).click();

    for (const field of [hours, downloads, password]) await expect(field).toHaveAttribute("aria-invalid", "true");
    await expect(hours).toHaveAccessibleDescription(/Enter a whole number of hours from 1 to \d+\./);
    await expect(downloads).toHaveAccessibleDescription(/Enter a whole number of downloads from 1 to \d+\./);
    await expect(password).toHaveAccessibleDescription(/Use at least \d+ characters/);
    await expect(hours, "the first field with a problem takes focus").toBeFocused();
    expect((await fetchFile(request, file.id)).shares, "nothing was made").toHaveLength(2);
    await expectAccessible(page, "the form with a problem in every field");
  });

  await test.step("the link that is shown once", async () => {
    await open();
    const { token } = await createLink(page, origin, { hours: "3", downloads: "5" });
    await expectTokenAbsent(page, token, "the console showing the link", ["the page markup", "a field's value"]);
    await expectAccessible(page, "the one-time link");
  });

  await test.step("the confirmation to revoke a link", async () => {
    await open();
    await shareRow(page, protectedShare.share.id)
      .getByRole("button", { name: `Revoke link ${short(protectedShare.share.id)}` })
      .click();
    await expect(page.getByRole("dialog", { name: "Revoke this link?", exact: true })).toBeVisible();
    await expectAccessible(page, "the confirmation to revoke a link");
  });

  await test.step("the confirmation to delete a file", async () => {
    await open();
    await page.getByRole("button", { name: "Delete file", exact: true }).click();
    await expect(page.getByRole("dialog", { name: "Delete this file?", exact: true })).toBeVisible();
    await expectAccessible(page, "the confirmation to delete a file");
  });

  await test.step("a phone", async () => {
    await page.setViewportSize({ width: 390, height: 844 });
    await open();
    await expectFits(page, "a file on a phone");
    await expectAccessible(page, "a file on a phone");
  });
});

test("the public share page passes the accessibility audit", async ({ page, request, vault, guard }) => {
  test.setTimeout(150_000);
  guard.expectStatus(403, 404, 410);
  const file = await storeFile(request, `public-${vault.tag}.txt`, bytesOf(vault.tag, 1200));
  vault.keep(file.id);
  const protectedLink = await makeShare(request, file.id, { password: `Pw-${vault.tag}-ok`, max_downloads: 3 });
  const open = await makeShare(request, file.id, { max_downloads: 3 });
  const finished = await makeShare(request, file.id, { max_downloads: 3 });
  const closed = await makeShare(request, file.id);
  await revokeViaApi(request, file.id, closed.share.id);

  await test.step("the offer of a file that needs a password", async () => {
    await page.goto(protectedLink.path);
    await expect(page.getByLabel("Password", { exact: true })).toBeVisible();
    await expectAccessible(page, "the password prompt");
  });

  await test.step("a password that was not right", async () => {
    await page.goto(protectedLink.path);
    await page.getByLabel("Password", { exact: true }).fill(`Pw-${vault.tag}-no`);
    await downloadButton(page).click();
    await expect(page.getByRole("alert")).toContainText("That password is not correct");
    await expectAccessible(page, "the message about a wrong password");
  });

  await test.step("the offer of a file that needs nothing", async () => {
    await page.goto(open.path);
    await expect(page.getByRole("heading", { level: 1 })).toHaveText(file.name);
    await expectAccessible(page, "the offer of a file");
  });

  await test.step("the answer after a download", async () => {
    await page.goto(finished.path);
    await downloadButton(page).click();
    await expect(page.getByRole("heading", { level: 1, name: "Your download has started" })).toBeFocused();
    await expectAccessible(page, "the answer after a download");
  });

  await test.step("a link that was revoked and one that never existed", async () => {
    await page.goto(closed.path);
    await expectLinkMessage(page, MESSAGES.revoked);
    await expectAccessible(page, "a revoked link");

    await page.goto(`/share/${unknownToken()}`);
    await expectLinkMessage(page, MESSAGES.unknown);
    await expectAccessible(page, "a link that does not work");
  });

  await test.step("a phone", async () => {
    await page.setViewportSize({ width: 390, height: 844 });
    await page.goto(protectedLink.path);
    await expect(page.getByLabel("Password", { exact: true })).toBeVisible();
    await expectFits(page, "the public page on a phone");
    await expectAccessible(page, "the public page on a phone");
  });
});

// ---- What the public page may do ------------------------------------------------------------------------

test("the public page keeps to the share API and the one-time link is shown once", async ({
  page,
  request,
  browser,
  baseURL,
  vault,
}) => {
  test.setTimeout(90_000);
  const origin = originOf(baseURL);
  const file = await storeFile(request, `once-${vault.tag}.txt`, bytesOf(vault.tag, 900));
  vault.keep(file.id);
  const visitor = await openVisitor(browser, origin);

  try {
    await page.goto(`/files?file=${file.id}`);
    await expect(page.locator('meta[name="robots"]')).toHaveCount(0);
    const { link, token, region } = await createLink(page, origin);

    await region.getByRole("button", { name: "Hide link" }).click();
    await expect(region).toHaveCount(0);
    await expectTokenAbsent(page, token, "the console after the link was hidden");
    await page.reload();
    await expect(newLinkPanel(page), "the link comes back after a reload").toHaveCount(0);
    await expectTokenAbsent(page, token, "the console after a reload");
    expect(
      JSON.stringify(await fetchFile(request, file.id)).includes(token),
      "the owner's own view of the file holds the token",
    ).toBe(false);

    const stranger = visitor.page;
    const [info, document] = await Promise.all([
      stranger.waitForResponse((response) => /^\/api\/v1\/shares\/[^/]+$/.test(new URL(response.url()).pathname)),
      stranger.goto(link),
    ]);
    expect(info.status()).toBe(200);
    expect(info.headers()["cache-control"], "how the share API's answer may be cached").toContain("no-store");
    expect(must(document).headers()["referrer-policy"], "what the public page tells browsers about referrers").toBe(
      "no-referrer",
    );
    await expect(stranger.getByRole("heading", { level: 1 })).toHaveText(file.name);
    await expect(fact(stranger.getByRole("main"), "Downloads left")).toHaveText("1");
    await expect(stranger.locator('meta[name="robots"]')).toHaveAttribute("content", "noindex,nofollow");
    expect(stranger.url() === link, "the address bar holds the link").toBe(true);

    const [download] = await Promise.all([stranger.waitForEvent("download"), downloadButton(stranger).click()]);
    expect(download.suggestedFilename()).toBe(file.name);
    await expect(stranger.getByText("This link has no downloads left.")).toBeVisible();

    await expectTokenAbsent(stranger, token, "the public page after the download");
    expect(await stranger.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
    await expectPublicTraffic(visitor, origin);
    expect(visitor.problems, "what the stranger's browser reported").toEqual([]);
  } finally {
    await visitor.close();
  }
});
