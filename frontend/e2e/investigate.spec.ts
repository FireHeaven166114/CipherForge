import type { APIRequestContext, Locator, Page, Request } from "@playwright/test";

import type { Investigation } from "../src/types/intel";
import {
  CLASSIFICATION_LABELS,
  countRequests,
  fetchIndicator,
  fetchIndicators,
  fresh,
  investigateViaApi,
  storedIndicator,
  uniqueSuffix,
} from "./api";
import { expect, test } from "./fixtures";
import { expectDossier, palette, panel, pause, providerCard } from "./pages";
import { must } from "./text";

const INVESTIGATE = /\/api\/v1\/intel\/investigate$/;
const OPEN_QUOTE = "\u201c";
const CLOSE_QUOTE = "\u201d";
const SAVED = "This result is saved. You can return to it from the Indicators page.";
const EMPTY_FILE_MD5 = "d41d8cd98f00b204e9800998ecf8427e";
const EMPTY_FILE_SHA1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709";
const EMPTY_FILE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

// Numbers appear at once instead of counting up, so the page can be compared with the API.
test.use({ reducedMotion: "reduce" });

interface Scanner {
  field: Locator;
  send: Locator;
  working: Locator;
  again: Locator;
  alert: Locator;
  saved: Locator;
  examples: Locator;
}

function scanner(page: Page): Scanner {
  return {
    field: page.getByLabel("Indicator", { exact: true }),
    send: page.getByRole("button", { name: "Investigate", exact: true }),
    working: page.getByRole("button", { name: "Investigating…", exact: true }),
    again: page.getByRole("checkbox", { name: /^Ask the providers again, even if a stored answer is recent/ }),
    alert: page.getByRole("alert"),
    saved: page.getByText(SAVED),
    examples: page.getByRole("group", { name: "Fill with an example" }),
  };
}

async function openScanner(page: Page): Promise<Scanner> {
  await page.goto("/investigate");
  await expect(page.getByRole("heading", { level: 1, name: "Investigate an indicator", exact: true })).toBeVisible();
  return scanner(page);
}

function isLookup(request: Request): boolean {
  return request.method() === "POST" && INVESTIGATE.test(request.url());
}

/** Resolves with the next lookup the page sends. */
function lookupRequest(page: Page): Promise<Request> {
  return page.waitForRequest(isLookup);
}

/** Types the value, sends it and resolves with what was sent and what the API answered. */
async function lookup(page: Page, value: string): Promise<{ body: unknown; answer: Investigation }> {
  const { field, send } = scanner(page);
  await field.fill(value);
  const answered = page.waitForResponse((response) => isLookup(response.request()));
  await send.click();
  const response = await answered;
  return { body: response.request().postDataJSON(), answer: (await response.json()) as Investigation };
}

/** What the page says aloud when a lookup ends, for people who cannot see it change. */
function announcement(dossier: Investigation): string {
  const { indicator, score } = dossier;
  if (score.answered_sources === 0) return `${indicator.indicator_value} was not assessed because no provider answered.`;
  const label = CLASSIFICATION_LABELS[score.classification];
  return `${indicator.indicator_value} is classified ${label}, with score ${score.score} and confidence ${score.confidence}.`;
}

/** The stored dossier of a value, read straight from the API. */
async function storedDossier(request: APIRequestContext, value: string): Promise<Investigation> {
  return fetchIndicator(request, (await storedIndicator(request, value)).indicator_id);
}

function envelope(status: number): { error: { code: string; message: string; correlation_id: string } } {
  return { error: { code: "e2e_failure", message: `Message for ${status}.`, correlation_id: `e2e-ref-${status}` } };
}

test.describe("the form", () => {
  test("opens empty, says where the indicator goes, and asks nothing yet", async ({ page }) => {
    const lookups = countRequests(page, INVESTIGATE);
    const { field, send, again, alert } = await openScanner(page);

    await expect(page).toHaveTitle("Investigate \u00b7 CipherForge");
    await expect(field).toHaveValue("");
    await expect(field).toHaveAttribute("placeholder", "8.8.8.8, example.com, https://example.com/path or a file hash");
    await expect(field).toHaveAccessibleDescription(
      /IPv4, IPv6, domain, URL, or an MD5, SHA-1 or SHA-256 file hash\. Surrounding spaces are ignored\./,
    );
    await expect(again).not.toBeChecked();
    await expect(send).toBeEnabled();
    await expect(page.getByText(/^Before you send:/)).toBeVisible();
    await expect(page.getByText(/is outside your organisation/)).toBeVisible();
    await expect(alert).toHaveCount(0);
    await expect(page.getByText("Looks like")).toHaveCount(0);
    expect(lookups.count).toBe(0);
  });

  test("a blank submit asks for an indicator and sends nothing", async ({ page }) => {
    const lookups = countRequests(page, INVESTIGATE);
    const { field, send, alert } = await openScanner(page);

    for (const blank of ["", "   "]) {
      await field.fill(blank);
      await send.click();
      await expect(alert).toContainText("Enter an indicator to investigate.");
      await expect(field).toHaveAttribute("aria-invalid", "true");
      await expect(field).toHaveAccessibleDescription(/Enter an indicator to investigate\./);
    }
    await field.fill("");
    await field.press("Enter");
    await expect(alert).toContainText("Enter an indicator to investigate.");
    expect(lookups.count).toBe(0);
  });

  test("shows what the text looks like while it is typed", async ({ page }) => {
    const { field } = await openScanner(page);
    const cases: ReadonlyArray<readonly [string, string | null]> = [
      ["8.8.8.8", "IPv4"],
      ["  1.1.1.1  ", "IPv4"],
      ["2001:4860:4860::8888", "IPv6"],
      ["example.com", "Domain"],
      ["EXAMPLE.COM", "Domain"],
      ["https://example.com/path", "URL"],
      [EMPTY_FILE_MD5, "MD5"],
      [EMPTY_FILE_MD5.toUpperCase(), "MD5"],
      [EMPTY_FILE_SHA1, "SHA-1"],
      [EMPTY_FILE_SHA256, "SHA-256"],
      [EMPTY_FILE_SHA256.toUpperCase(), "SHA-256"],
      ["999.1.1.1", null],
      ["not an indicator", null],
      ["ftp://example.com", null],
      ["", null],
    ];

    for (const [typed, hint] of cases) {
      await field.fill(typed);
      const badge = page.getByText("Looks like");
      if (hint === null) await expect(badge, JSON.stringify(typed)).toHaveCount(0);
      else await expect(page.getByText(`Looks like ${hint}`, { exact: true }), JSON.stringify(typed)).toBeVisible();
    }
  });

  test("the example chips fill the field and focus it without sending anything", async ({ page }) => {
    const lookups = countRequests(page, INVESTIGATE);
    const { field, send, alert, examples } = await openScanner(page);
    const chips = [
      { name: "IPv4 8.8.8.8", value: "8.8.8.8", hint: "IPv4" },
      { name: "Domain example.com", value: "example.com", hint: "Domain" },
      { name: "URL https://example.com/path", value: "https://example.com/path", hint: "URL" },
      { name: "MD5 d41d8cd9\u2026", value: EMPTY_FILE_MD5, hint: "MD5" },
      { name: "SHA-1 da39a3ee\u2026", value: EMPTY_FILE_SHA1, hint: "SHA-1" },
      { name: "SHA-256 e3b0c442\u2026", value: EMPTY_FILE_SHA256, hint: "SHA-256" },
    ];
    await expect(examples.getByRole("button")).toHaveCount(chips.length);

    await send.click();
    await expect(alert).toBeVisible();
    for (const chip of chips) {
      await examples.getByRole("button", { name: chip.name }).click();
      await expect(field).toHaveValue(chip.value);
      await expect(field).toBeFocused();
      await expect(page.getByText(`Looks like ${chip.hint}`, { exact: true })).toBeVisible();
      await expect(alert, "choosing an example clears the earlier message").toHaveCount(0);
    }
    expect(lookups.count).toBe(0);
  });

  test("a value over 2048 characters is refused before it is sent, and 2048 is not too long", async ({ page, guard }) => {
    guard.expectStatus(422);
    await page.route(INVESTIGATE, (route) => route.fulfill({ status: 422, json: envelope(422) }));
    const lookups = countRequests(page, INVESTIGATE);
    const { field, send, alert } = await openScanner(page);

    await field.fill("a".repeat(2049));
    await send.click();
    await expect(alert).toContainText("An indicator can be at most 2048 characters. This one has 2049.");
    await field.fill(`  ${"a".repeat(2049)}  `);
    await send.click();
    await expect(alert).toContainText("This one has 2049.");
    expect(lookups.count, "nothing is sent for a value that is too long").toBe(0);

    const sent = lookupRequest(page);
    await field.fill(`  ${"a".repeat(2048)}  `);
    await send.click();
    const body = (await sent).postDataJSON() as { indicator: string };
    expect(body.indicator).toBe("a".repeat(2048));
    await expect(alert).toContainText("Message for 422.");
  });

  test("works from the keyboard alone", async ({ page }) => {
    const value = fresh.domain();
    const { field, send, again, saved, examples } = await openScanner(page);

    await field.focus();
    await page.keyboard.type(value);
    for (const chip of ["IPv4", "Domain", "URL", "MD5", "SHA-1", "SHA-256"]) {
      await page.keyboard.press("Tab");
      await expect(examples.getByRole("button", { name: new RegExp(`^${chip} `) })).toBeFocused();
    }
    await page.keyboard.press("Tab");
    await expect(again).toBeFocused();
    await page.keyboard.press("Space");
    await expect(again).toBeChecked();
    await page.keyboard.press("Tab");
    await expect(send).toBeFocused();

    const sent = lookupRequest(page);
    await page.keyboard.press("Enter");
    expect((await sent).postDataJSON()).toEqual({ indicator: value, refresh: true });
    await expect(saved).toBeVisible();
    await expect(send, "the keyboard is still on the button that was pressed").toBeFocused();
  });
});

test.describe("a lookup", () => {
  const KINDS = [
    { name: "an IPv6 address", make: fresh.ipv6, hint: "IPv6", queriedByAbuseIpdb: true },
    { name: "a domain", make: fresh.domain, hint: "Domain", queriedByAbuseIpdb: false },
    { name: "a URL", make: fresh.url, hint: "URL", queriedByAbuseIpdb: false },
    { name: "an MD5 hash", make: fresh.md5, hint: "MD5", queriedByAbuseIpdb: false },
    { name: "a SHA-1 hash", make: fresh.sha1, hint: "SHA-1", queriedByAbuseIpdb: false },
    { name: "a SHA-256 hash", make: fresh.sha256, hint: "SHA-256", queriedByAbuseIpdb: false },
  ] as const;

  for (const kind of KINDS) {
    test(`${kind.name}: shows that it is working, then the saved assessment`, async ({ page, request }) => {
      const value = kind.make();
      await page.route(INVESTIGATE, async (route) => {
        await pause(1_000);
        await route.continue().catch(() => undefined);
      });
      const { field, send, working, saved } = await openScanner(page);
      await field.fill(value);
      await expect(page.getByText(`Looks like ${kind.hint}`, { exact: true })).toBeVisible();

      const sent = lookupRequest(page);
      await send.click();
      expect((await sent).postDataJSON()).toEqual({ indicator: value, refresh: false });

      await expect(working).toBeDisabled();
      await expect(page.getByText(`Asking the providers about ${value}. This can take up to 30 seconds.`)).toBeVisible();
      await expect(page.getByRole("status").filter({ hasText: `Investigating ${value}.` })).toBeAttached();
      await expect(saved).toBeVisible();

      const stored = await storedIndicator(request, value);
      const dossier = await fetchIndicator(request, stored.indicator_id);
      await expectDossier(page, dossier);
      await expect(page.getByRole("status").filter({ hasText: announcement(dossier) })).toBeAttached();
      await expect(page.getByRole("link", { name: "Open the saved record" })).toHaveAttribute(
        "href",
        `/indicators/${stored.indicator_id}`,
      );
      await expect(send).toBeEnabled();
      await expect(field).toHaveValue(value);

      const abuseIpdb = must(dossier.providers.find((p) => p.provider === "abuseipdb"), "the AbuseIPDB answer");
      if (kind.queriedByAbuseIpdb) expect(abuseIpdb.status).not.toBe("unsupported");
      else {
        expect(abuseIpdb.status).toBe("unsupported");
        await expect(providerCard(page, "AbuseIPDB")).toContainText(must(abuseIpdb.message));
      }
    });
  }

  test("another spelling of a known indicator is the same record, not a new one", async ({ page, request }) => {
    const value = fresh.domain();
    const typed = `${value.toUpperCase()}.`;
    const total = async () => (await fetchIndicators(request, { limit: 1 })).total;
    const before = await total();
    const { saved } = await openScanner(page);

    const first = await lookup(page, `  ${typed}  `);
    expect(first.body, "what was typed is sent as it is, without the surrounding spaces").toEqual({
      indicator: typed,
      refresh: false,
    });
    await expect(saved).toBeVisible();
    await expect(panel(page, "CipherForge assessment")).toContainText(value);
    expect(first.answer.indicator.indicator_value).toBe(value);
    expect(await total()).toBe(before + 1);

    const second = await lookup(page, value);
    expect(second.answer.indicator.indicator_id).toBe(first.answer.indicator.indicator_id);
    expect(await total(), "a second lookup of the same indicator adds no record").toBe(before + 1);
    await expect(page.getByRole("link", { name: "Open the saved record" })).toHaveAttribute(
      "href",
      `/indicators/${first.answer.indicator.indicator_id}`,
    );
  });

  test("a new lookup replaces the result of the one before it", async ({ page }) => {
    const [first, second] = [fresh.domain(), fresh.domain()];
    const { saved } = await openScanner(page);
    const done = await lookup(page, first);
    await expect(saved).toBeVisible();
    await expectDossier(page, done.answer);

    await page.route(INVESTIGATE, async (route) => {
      await pause(800);
      await route.continue().catch(() => undefined);
    });
    const next = lookup(page, second);
    await expect(page.getByText(`Asking the providers about ${second}.`)).toBeVisible();
    await expect(panel(page, "CipherForge assessment"), "the old result goes while the new one is awaited").toHaveCount(0);
    await expect(saved).toHaveCount(0);

    await expectDossier(page, (await next).answer);
    await expect(panel(page, "CipherForge assessment")).not.toContainText(first);
  });

  test("asking the providers again sends the request to refresh, and the record is checked again", async ({ page, request }) => {
    const created = await investigateViaApi(request, fresh.domain());
    const value = created.indicator.indicator_value;
    const { again, saved } = await openScanner(page);

    await again.check();
    const refreshed = await lookup(page, value);
    expect(refreshed.body).toEqual({ indicator: value, refresh: true });
    await expect(saved).toBeVisible();
    await expect(again, "the choice stays for the next lookup").toBeChecked();
    expect(refreshed.answer.indicator.indicator_id).toBe(created.indicator.indicator_id);
    const after = await storedIndicator(request, value);
    expect(Date.parse(must(after.last_checked_at))).toBeGreaterThan(Date.parse(must(created.indicator.last_checked_at)));

    await again.uncheck();
    expect((await lookup(page, value)).body).toEqual({ indicator: value, refresh: false });
  });

  test("opens the saved record, which shows what the lookup showed", async ({ page, request }) => {
    const value = fresh.ipv6();
    const { saved } = await openScanner(page);
    const { answer } = await lookup(page, value);
    await expect(saved).toBeVisible();

    await page.getByRole("link", { name: "Open the saved record" }).click();
    await expect(page).toHaveURL(new RegExp(`/indicators/${answer.indicator.indicator_id}$`));
    await expect(page.getByRole("heading", { level: 1, name: "Indicator details" })).toBeVisible();
    await expectDossier(page, await fetchIndicator(request, answer.indicator.indicator_id));
  });

  test("pressing Investigate again while a lookup runs does not send a second one", async ({ page }) => {
    await page.route(INVESTIGATE, async (route) => {
      await pause(1_000);
      await route.continue().catch(() => undefined);
    });
    const lookups = countRequests(page, INVESTIGATE);
    const { field, send, working, saved } = await openScanner(page);
    await field.fill(fresh.domain());
    await send.click();
    await expect(working).toBeDisabled();
    await expect(working, "the button keeps the focus while it works").toBeFocused();
    await field.press("Enter");
    await working.click({ force: true });

    await expect(saved).toBeVisible();
    expect(lookups.count).toBe(1);
    await expect(send).toBeFocused();
  });
});

test.describe("what the providers can say", () => {
  // Domains are not AbuseIPDB's to answer, so the three providers that take them all fail alike.
  const FAILING = [
    { marker: "rate-limit", status: "rate_limited", label: "Rate limited", reason: "rate_limited" },
    { marker: "provider-error", status: "error", label: "Error", reason: "unavailable" },
  ] as const;
  const REASON_TEXT = { rate_limited: "Rate limited", unavailable: "Provider unavailable" } as const;
  const ASKED = [
    ["otx", "AlienVault OTX"],
    ["virustotal", "VirusTotal"],
    ["threatfox", "ThreatFox"],
  ] as const;

  for (const failing of FAILING) {
    test(`a provider that reports "${failing.label}" is shown as such, and nothing is scored`, async ({ page, request }) => {
      const value = `${failing.marker}-${uniqueSuffix()}.example.net`;
      const { saved } = await openScanner(page);
      const { answer } = await lookup(page, value);
      await expect(saved).toBeVisible();

      // The lookup reports the failure itself; only answers are stored, so the saved record differs.
      expect(answer.score.answered_sources, "no provider answered").toBe(0);
      await expectDossier(page, answer);
      for (const [name, displayName] of ASKED) {
        const provider = must(answer.providers.find((p) => p.provider === name), `the ${displayName} answer`);
        expect(provider.status).toBe(failing.status);
        expect(provider.reason).toBe(failing.reason);
        const card = providerCard(page, displayName);
        await expect(card).toContainText(failing.label);
        await expect(card).toContainText(REASON_TEXT[failing.reason]);
        await expect(card).toContainText(must(provider.message));
        await expect(card).toContainText("Lookup attempted");
        await expect(card.getByRole("button", { name: `Retry ${displayName}` })).toBeVisible();
      }
      await expect(page.getByRole("status").filter({ hasText: announcement(answer) })).toBeAttached();
      await expect(panel(page, "CipherForge assessment")).toContainText("This is not a clean result");

      await page.getByRole("link", { name: "Open the saved record" }).click();
      await expect(page.getByRole("heading", { level: 1, name: "Indicator details" })).toBeVisible();
      const stored = await fetchIndicator(request, answer.indicator.indicator_id);
      expect(stored.score.answered_sources).toBe(0);
      await expectDossier(page, stored);
    });
  }

  test("Retry asks the providers again without forcing a refresh, and replaces the result", async ({ page }) => {
    const value = `rate-limit-${uniqueSuffix()}.example.net`;
    const { saved } = await openScanner(page);
    const first = await lookup(page, value);
    await expect(saved).toBeVisible();
    expect(first.answer.score.answered_sources).toBe(0);

    const again = page.waitForResponse((response) => isLookup(response.request()));
    await providerCard(page, "VirusTotal").getByRole("button", { name: "Retry VirusTotal" }).click();
    const retried = await again;
    expect(retried.request().postDataJSON()).toEqual({ indicator: value, refresh: false });
    const answer = (await retried.json()) as Investigation;
    expect(answer.indicator.indicator_id).toBe(first.answer.indicator.indicator_id);
    await expectDossier(page, answer);
    await expect(providerCard(page, "VirusTotal").getByRole("button", { name: "Retry VirusTotal" })).toBeVisible();
  });

  test("an answer from VirusTotal and ThreatFox is shown with the provider's own verdict and no Retry", async ({
    page,
  }) => {
    const { saved } = await openScanner(page);
    const { answer } = await lookup(page, fresh.ipv6());
    await expect(saved).toBeVisible();
    // expectDossier checks each card's status, verdict and failure reason against the API.
    await expectDossier(page, answer);

    for (const name of ["virustotal", "threatfox"]) {
      const provider = must(answer.providers.find((p) => p.provider === name), name);
      const card = providerCard(page, provider.display_name);
      await expect(card).toBeVisible();
      if (provider.status === "ok") {
        await expect(card.getByRole("button", { name: /^Retry / })).toHaveCount(0);
      }
    }
  });
});

test.describe("when the lookup is refused or fails", () => {
  for (const value of ["192.168.1.10", "localhost", "router.local"]) {
    test(`${value} is refused in the API's own words`, async ({ page, request, guard }) => {
      guard.expectStatus(422);
      const refusal = await request.post("/api/v1/intel/investigate", { data: { indicator: value, refresh: false } });
      expect(refusal.status()).toBe(422);
      const { error } = (await refusal.json()) as { error: { message: string } };

      const { field, send, alert, saved } = await openScanner(page);
      await field.fill(value);
      await send.click();

      await expect(alert).toContainText("That request was not accepted");
      await expect(alert).toContainText(error.message);
      await expect(alert).toContainText("Reference: ");
      await expect(alert.getByRole("button", { name: "Try again" }), "the form itself is how to try again").toHaveCount(0);
      await expect(saved).toHaveCount(0);
      await expect(send).toBeEnabled();
      await expect(field).toHaveValue(value);
      await expect(page.getByRole("status")).toHaveText("");
      expect((await fetchIndicators(request, { q: value })).items.map((i) => i.indicator_value)).not.toContain(value);
    });
  }

  const FAILURES = [
    { status: 401, title: "Not signed in", hint: /development authentication mode/ },
    { status: 403, title: "Access denied", hint: /SecurityAnalyst or Admin role/ },
    { status: 404, title: "Not found", hint: null },
    { status: 422, title: "That request was not accepted", hint: null },
    { status: 500, title: "The API reported an error", hint: /give the reference below to an administrator/ },
    { status: 503, title: "The API reported an error", hint: /give the reference below to an administrator/ },
  ] as const;

  for (const failure of FAILURES) {
    test(`HTTP ${failure.status} is explained, with the server's message and its reference`, async ({ page, guard }) => {
      guard.expectStatus(failure.status);
      await page.route(INVESTIGATE, (route) => route.fulfill({ status: failure.status, json: envelope(failure.status) }));
      const { field, send, alert } = await openScanner(page);
      await field.fill(fresh.domain());
      await send.click();

      await expect(alert).toContainText(failure.title);
      await expect(alert).toContainText(`Message for ${failure.status}.`);
      await expect(alert).toContainText(`Reference: e2e-ref-${failure.status}`);
      if (failure.hint !== null) await expect(alert).toContainText(failure.hint);
    });
  }

  test("a rate limit says how long to wait, when the API says so", async ({ page, guard }) => {
    guard.expectStatus(429);
    let retryAfter: string | undefined;
    await page.route(INVESTIGATE, (route) =>
      route.fulfill({
        status: 429,
        headers: retryAfter === undefined ? {} : { "Retry-After": retryAfter },
        json: envelope(429),
      }),
    );
    const { field, send, alert } = await openScanner(page);
    await field.fill(fresh.domain());

    const waits = [
      { header: "30", hint: "Try again in 30 seconds." },
      { header: "1", hint: "Try again in 1 second." },
      { header: "90", hint: "Try again in 2 minutes." },
      { header: "0", hint: "Try again in a moment." },
      { header: undefined, hint: "Try again shortly." },
      { header: "soon", hint: "Try again shortly." },
    ];
    for (const wait of waits) {
      retryAfter = wait.header;
      await send.click();
      await expect(alert, `Retry-After ${wait.header}`).toContainText(wait.hint);
      await expect(alert).toContainText("Rate limit reached");
      await expect(alert).toContainText("Message for 429.");
    }
  });

  test("an error that is not the API's own is reported without showing what it said", async ({ page, guard }) => {
    guard.expectStatus(502);
    await page.route(INVESTIGATE, (route) =>
      route.fulfill({
        status: 502,
        headers: { "Content-Type": "text/html", "X-Correlation-ID": "e2e-ref-502" },
        body: "<html><body>Bad gateway from a proxy</body></html>",
      }),
    );
    const { field, send, alert } = await openScanner(page);
    await field.fill(fresh.domain());
    await send.click();

    await expect(alert).toContainText("The API reported an error");
    await expect(alert).toContainText("The API responded with HTTP 502.");
    await expect(alert).toContainText("Reference: e2e-ref-502");
    await expect(page.getByText("Bad gateway from a proxy")).toHaveCount(0);
  });

  test("an API that cannot be reached is reported as such", async ({ page, guard }) => {
    guard.expectRequestFailure(INVESTIGATE);
    await page.route(INVESTIGATE, (route) => route.abort("connectionrefused"));
    const { field, send, alert } = await openScanner(page);
    await field.fill(fresh.domain());
    await send.click();

    await expect(alert).toContainText("Could not reach the API");
    await expect(alert).toContainText("Could not reach the CipherForge API.");
    await expect(alert).toContainText("Check that the API is running and that your network connection works.");
    await expect(send).toBeEnabled();
  });

  test("an answer the console cannot read is reported, not shown", async ({ page }) => {
    await page.route(INVESTIGATE, (route) => route.fulfill({ status: 200, json: { unexpected: true } }));
    const { field, send, alert, saved } = await openScanner(page);
    await field.fill(fresh.domain());
    await send.click();

    await expect(alert).toContainText("Unexpected response from the API");
    await expect(alert).toContainText("The API returned a response this app cannot read.");
    await expect(saved).toHaveCount(0);
  });

  test("a lookup that takes longer than 30 seconds times out", async ({ page }) => {
    test.setTimeout(90_000);
    // Never answered: the request stays open until the console gives up on it.
    await page.route(INVESTIGATE, () => new Promise<void>(() => undefined));
    const { field, send, working, alert } = await openScanner(page);
    await field.fill(fresh.domain());
    await send.click();
    await expect(working).toBeDisabled();

    await expect(alert).toContainText("The request timed out", { timeout: 40_000 });
    await expect(alert).toContainText("The API or a provider is slow to answer. Try again in a moment.");
    await expect(send).toBeEnabled();
  });

  test("after a failure the same form works again, and the notice goes", async ({ page, guard }) => {
    guard.expectStatus(503);
    let calls = 0;
    await page.route(INVESTIGATE, (route) => {
      calls += 1;
      return calls === 1 ? route.fulfill({ status: 503, json: envelope(503) }) : route.continue();
    });
    const { field, send, alert, saved } = await openScanner(page);
    const value = fresh.domain();
    await field.fill(value);
    await send.click();
    await expect(alert).toContainText("Message for 503.");

    const answered = page.waitForResponse((response) => isLookup(response.request()) && response.ok());
    await field.press("Enter");
    const dossier = (await (await answered).json()) as Investigation;
    await expect(saved).toBeVisible();
    await expect(alert).toHaveCount(0);
    await expectDossier(page, dossier);
  });
});

test.describe("from the command palette", () => {
  test("Investigate starts one lookup, and reloading or going back does not repeat it", async ({ page, request }) => {
    const value = fresh.domain();
    await page.goto("/indicators");
    const lookups = countRequests(page, INVESTIGATE);
    const { box, options } = palette(page);
    await page.keyboard.press("Control+k");
    await box.fill(value);
    await options.filter({ hasText: `Investigate ${OPEN_QUOTE}${value}${CLOSE_QUOTE}` }).click();

    const { field, saved } = scanner(page);
    await expect(page).toHaveURL(/\/investigate$/);
    await expect(field).toHaveValue(value);
    await expect(saved).toBeVisible();
    await expectDossier(page, await storedDossier(request, value));
    expect(lookups.count).toBe(1);

    await page.reload();
    await expect(field, "the field is filled again from the history entry").toHaveValue(value);
    await expect(page.getByRole("link", { name: "API ONLINE" })).toBeVisible();
    await expect(saved).toHaveCount(0);
    expect(lookups.count, "reloading must not ask the providers again").toBe(1);

    await page.getByRole("navigation", { name: "Primary" }).getByRole("link", { name: "Indicators", exact: true }).click();
    await expect(page.getByRole("heading", { level: 1, name: "Indicators", exact: true })).toBeVisible();
    await page.goBack();
    await expect(field).toHaveValue(value);
    await expect(page.getByRole("link", { name: "API ONLINE" })).toBeVisible();
    expect(lookups.count, "going back must not ask the providers again").toBe(1);
  });

  test("asking about the same value again looks it up again", async ({ page }) => {
    const value = fresh.domain();
    const { saved } = await openScanner(page);
    await lookup(page, value);
    await expect(saved).toBeVisible();

    const lookups = countRequests(page, INVESTIGATE);
    const { box, options } = palette(page);
    await page.keyboard.press("Control+k");
    await box.fill(value);
    const sent = lookupRequest(page);
    await options.filter({ hasText: "Investigate" }).first().click();
    expect((await sent).postDataJSON()).toEqual({ indicator: value, refresh: false });
    await expect(saved).toBeVisible();
    expect(lookups.count).toBe(1);
  });

  test("a lookup started while another is still running replaces it", async ({ page, request }) => {
    const [first, second] = [fresh.domain(), fresh.domain()];
    let calls = 0;
    await page.route(INVESTIGATE, async (route) => {
      calls += 1;
      // The second lookup is held as well, so the page is still waiting when the test looks for the
      // "Asking the providers" text; it is held for less time than the first, which comes back late.
      await pause(calls === 1 ? 2_000 : 800);
      await route.continue().catch(() => undefined);
    });
    const { field, send, working, saved } = await openScanner(page);
    await field.fill(first);
    await send.click();
    await expect(working).toBeDisabled();

    const { box, options } = palette(page);
    await page.keyboard.press("Control+k");
    await box.fill(second);
    await options.filter({ hasText: `Investigate ${OPEN_QUOTE}${second}${CLOSE_QUOTE}` }).click();
    await expect(page.getByText(`Asking the providers about ${second}.`)).toBeVisible();
    await expect(saved).toBeVisible();
    await expectDossier(page, await storedDossier(request, second));

    await pause(2_500);
    await expect(panel(page, "CipherForge assessment"), "the slower, earlier lookup must not come back").not.toContainText(first);
    await expect(panel(page, "CipherForge assessment")).toContainText(second);
  });

  test("a value the API refuses shows the refusal on the page", async ({ page, guard }) => {
    guard.expectStatus(422);
    await page.goto("/");
    const { box, options } = palette(page);
    await page.keyboard.press("Control+k");
    await box.fill("localhost");
    await options.filter({ hasText: "Investigate" }).first().click();

    const { field, alert, saved } = scanner(page);
    await expect(page).toHaveURL(/\/investigate$/);
    await expect(field).toHaveValue("localhost");
    await expect(alert).toContainText("That request was not accepted");
    await expect(alert).toContainText("Reference: ");
    await expect(saved).toHaveCount(0);
  });
});
