import type { Locator, Page } from "@playwright/test";

import type { Investigation, ProviderView } from "../src/types/intel";
import { CLASSIFICATION_LABELS, fetchIndicator, purgeIndicators, uniqueSuffix } from "./api";
import { istText } from "./files-api";
import { expect, test } from "./fixtures";
import { expectDossier, panel, providerCard } from "./pages";
import { exactly, must } from "./text";

/*
 * Journey A with one provider failing. The demo server's simulated providers (never the real
 * ones, so no quota is spent) answer HTTP 500 from only the provider that a value names
 * (`otx-down`, `virustotal-down` or `threatfox-down`) and describe the value as heavily reported
 * to the others. The page has to show the failure and still show what the other two sent,
 * attributed to the right provider and with every time in India Standard Time.
 */

const INVESTIGATE = /\/api\/v1\/intel\/investigate$/;
const SAVED = "This result is saved. You can return to it from the Indicators page.";
// "20-11-2026 04:34:45 PM IST (3 minutes ago)": the exact IST time, then how long ago that was.
const IST_AND_AGE = /^\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2} (AM|PM) IST \(.+\)$/;

const DISPLAY = { otx: "AlienVault OTX", virustotal: "VirusTotal", threatfox: "ThreatFox" } as const;
type Name = keyof typeof DISPLAY;

/** What each provider's card calls the latest and the first sign of activity. */
const ACTIVITY = {
  otx: { latest: "Latest activity", first: "First activity" },
  virustotal: { latest: "Last analysed", first: "First submitted" },
  threatfox: { latest: "Last seen", first: "First seen" },
} as const;

const CASES: ReadonlyArray<{ down: Name; answering: readonly [Name, Name] }> = [
  { down: "otx", answering: ["virustotal", "threatfox"] },
  { down: "virustotal", answering: ["otx", "threatfox"] },
  { down: "threatfox", answering: ["otx", "virustotal"] },
];

// Numbers appear at once instead of counting up, so the page can be compared with the API.
test.use({ reducedMotion: "reduce" });

const suffixes: string[] = [];

test.afterEach(async ({ request }) => {
  for (const suffix of suffixes.splice(0)) await purgeIndicators(request, suffix);
});

/** A domain that makes only this provider fail, and that no earlier run can have used. */
function valueFor(down: Name): string {
  const suffix = uniqueSuffix();
  suffixes.push(suffix);
  return `${down}-down-${suffix}.example.net`;
}

/** Resolves with what the page sent for its next lookup and what the API answered. */
async function nextLookup(
  page: Page,
  send: () => Promise<void>,
): Promise<{ body: unknown; answer: Investigation }> {
  const answered = page.waitForResponse(
    (response) => response.request().method() === "POST" && INVESTIGATE.test(response.url()),
  );
  await send();
  const response = await answered;
  return { body: response.request().postDataJSON(), answer: (await response.json()) as Investigation };
}

/** Looks the value up on the Investigate page and resolves with the API's answer. */
async function lookup(page: Page, value: string): Promise<Investigation> {
  await page.goto("/investigate");
  await expect(page.getByRole("heading", { level: 1, name: "Investigate an indicator", exact: true })).toBeVisible();
  await page.getByLabel("Indicator", { exact: true }).fill(value);
  const { answer } = await nextLookup(page, () =>
    page.getByRole("button", { name: "Investigate", exact: true }).click(),
  );
  await expect(page.getByText(SAVED)).toBeVisible();
  return answer;
}

/** What the page says aloud when a lookup ends, for people who cannot see it change. */
function announcement(dossier: Investigation): string {
  const { indicator, score } = dossier;
  const label = CLASSIFICATION_LABELS[score.classification];
  return `${indicator.indicator_value} is classified ${label}, with score ${score.score} and confidence ${score.confidence}.`;
}

function provider(dossier: Investigation, name: Name): ProviderView {
  return must(dossier.providers.find((item) => item.provider === name), `the ${name} answer`);
}

/** The label of a fact in a card's fact list. */
function term(card: Locator, label: string): Locator {
  return card.locator("dt").filter({ hasText: exactly(label) });
}

/** The value beside that label. */
function fact(card: Locator, label: string): Locator {
  return term(card, label).locator("xpath=following-sibling::dd[1]");
}

function num(summary: ProviderView["summary"], key: string): number {
  const value = summary[key];
  if (typeof value !== "number") throw new Error(`Expected the summary to hold a number for ${key}`);
  return value;
}

function words(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? "" : "s"}`;
}

/** The times an answer carries: when it was asked, when the activity happened and when it lapses. */
async function expectTimes(card: Locator, item: ProviderView, name: Name): Promise<void> {
  const { latest, first } = ACTIVITY[name];
  await expect(fact(card, "Checked")).toContainText(istText(must(item.fetched_at, "when it was fetched")));
  await expect(fact(card, "Answer valid until")).toContainText(
    istText(must(item.cache_expires_at, "when the answer lapses")),
  );
  if (item.evidence_at === null) await expect(fact(card, latest)).toHaveText("Not reported");
  else await expect(fact(card, latest)).toContainText(istText(item.evidence_at));
  if (item.first_evidence_at === null) await expect(term(card, first)).toHaveCount(0);
  else await expect(fact(card, first)).toContainText(istText(item.first_evidence_at));
  await expectOnlyIst(card);
}

/** Every time in the card is an exact IST time and an age, and none is written in another zone. */
async function expectOnlyIst(card: Locator): Promise<void> {
  const times = await card.locator("time").allTextContents();
  expect(times.length, "the card dates what it shows").toBeGreaterThan(0);
  for (const text of times) expect(text.trim()).toMatch(IST_AND_AGE);
  await expect(card).not.toContainText(/\bUTC\b/);
}

async function expectVirusTotal(card: Locator, item: ProviderView): Promise<void> {
  const { summary } = item;
  expect(item.verdict).toBe("malicious");
  const engines = `${num(summary, "malicious")} malicious, ${num(summary, "suspicious")} suspicious, `
    + `${num(summary, "harmless")} harmless, ${num(summary, "undetected")} undetected`;
  await expect(fact(card, "Engine results")).toContainText(engines);
  await expect(fact(card, "Engine results")).toContainText(`(${words(num(summary, "engines_total"), "engine")})`);
  expect(summary.analysis_status).toBe("completed");
  await expect(fact(card, "Analysis")).toHaveText("Completed: antivirus and security engines have examined it");
  if (typeof summary.reputation === "number") {
    await expect(fact(card, "Reputation")).toContainText(
      `${summary.reputation} (VirusTotal community score; below zero is worse)`,
    );
  }
  const categories = summary.categories;
  if (Array.isArray(categories) && categories.length > 0) {
    await expect(card.getByRole("list", { name: "Categories assigned by VirusTotal engines" })).toContainText(
      String(categories[0]),
    );
  }
  // Another provider's facts do not appear on this card.
  for (const foreign of ["Records", "Reporter confidence", "Matches"]) {
    await expect(term(card, foreign), `${foreign} belongs to ThreatFox`).toHaveCount(0);
  }
}

interface FoxMatch {
  ioc: string;
  confidence_level: number;
  first_seen: string | null;
  last_seen: string | null;
  reporter: string | null;
}

async function expectThreatFox(card: Locator, item: ProviderView): Promise<void> {
  const { summary } = item;
  expect(item.verdict).toBe("malicious");
  expect(summary.association).toBe("indicator");
  await expect(fact(card, "Records")).toHaveText(`${words(num(summary, "match_count"), "record")} matching this indicator`);
  await expect(fact(card, "Reporter confidence")).toContainText(
    `${num(summary, "highest_confidence")} / 100 (the highest across the records)`,
  );

  const matches = summary.matches as FoxMatch[];
  expect(matches.length, "ThreatFox sent at least one record").toBeGreaterThan(0);
  const listed = fact(card, "Matches").locator(":scope > ul > li");
  await expect(listed).toHaveCount(matches.length);
  for (const [index, match] of matches.entries()) {
    const entry = listed.nth(index);
    await expect(entry).toContainText(match.ioc);
    await expect(entry).toContainText(`Confidence ${match.confidence_level} / 100`);
    if (match.reporter !== null) await expect(entry).toContainText(`Reported by ${match.reporter}`);
    if (match.first_seen !== null) await expect(entry).toContainText(`First seen ${istText(match.first_seen)}`);
    if (match.last_seen === null) await expect(entry).not.toContainText("Last seen");
    else await expect(entry).toContainText(`Last seen ${istText(match.last_seen)}`);
  }
  // Another provider's facts do not appear on this card.
  for (const foreign of ["Engine results", "Analysis", "Reputation"]) {
    await expect(term(card, foreign), `${foreign} belongs to VirusTotal`).toHaveCount(0);
  }
}

test.describe("one provider is down while the others answer", () => {
  for (const { down, answering } of CASES) {
    test(`${DISPLAY[down]} fails: its card says so, the other two keep their answers`, async ({ page, request }) => {
      const answer = await lookup(page, valueFor(down));

      // Two providers answered. AbuseIPDB takes no domains, so it was never going to.
      expect(answer.score.answered_sources).toBe(2);
      await expectDossier(page, answer);
      const verdict = panel(page, "CipherForge assessment");
      await expect(verdict).not.toContainText("Not assessed");
      await expect(page.getByRole("status").filter({ hasText: announcement(answer) })).toBeAttached();

      // The provider that failed: an error with a reason, when it was tried, a way to try again, no data.
      const failed = provider(answer, down);
      expect(failed.status).toBe("error");
      expect(failed.reason).toBe("unavailable");
      const failedCard = providerCard(page, DISPLAY[down]);
      await expect(failedCard).toContainText("Error");
      await expect(failedCard).toContainText("Provider unavailable");
      await expect(failedCard).toContainText(must(failed.message, "the failure message"));
      await expect(failedCard).toContainText(
        `Lookup attempted ${istText(must(answer.indicator.last_checked_at, "when the lookup ran"))}`,
      );
      await expect(failedCard.getByRole("button", { name: `Retry ${DISPLAY[down]}` })).toBeVisible();
      await expect(failedCard.locator("dt"), "a failed lookup shows no evidence").toHaveCount(0);
      await expectOnlyIst(failedCard);

      // The two that answered: live, attributed to the right provider, dated in IST, nothing to retry.
      for (const name of answering) {
        const item = provider(answer, name);
        expect(item.status).toBe("ok");
        expect(item.from_cache).toBe(false);
        const card = providerCard(page, DISPLAY[name]);
        await expect(card.getByRole("button", { name: /^Retry / })).toHaveCount(0);
        await expect(fact(card, "Source")).toHaveText("Queried live for this lookup");
        await expectTimes(card, item, name);
        if (name === "virustotal") await expectVirusTotal(card, item);
        if (name === "threatfox") await expectThreatFox(card, item);
      }

      // The score is built from the two answers only, and says what is missing.
      const built = panel(page, "How the score was built");
      const rows = built.getByRole("table", { name: "Points that make up the score" }).locator("tbody tr");
      for (const name of answering) {
        await expect(rows.filter({ hasText: `${DISPLAY[name]} evidence` })).toHaveCount(1);
      }
      await expect(rows.filter({ hasText: `${DISPLAY[down]} evidence` })).toHaveCount(0);
      const missing = `${DISPLAY[down]} could not be queried, so it contributed no evidence.`;
      expect(answer.score.uncertainty).toContain(missing);
      await expect(built.getByRole("listitem").filter({ hasText: exactly(missing) })).toHaveCount(1);

      // The saved record holds the answers; a failure is not stored.
      await page.getByRole("link", { name: "Open the saved record" }).click();
      await expect(page.getByRole("heading", { level: 1, name: "Indicator details" })).toBeVisible();
      const stored = await fetchIndicator(request, answer.indicator.indicator_id);
      expect(stored.score.answered_sources).toBe(2);
      expect(provider(stored, down).status).toBe("not_queried");
      for (const name of answering) expect(provider(stored, name).status).toBe("ok");
      await expectDossier(page, stored);
    });
  }

  test("Retry asks only for what failed, and the answers already stored are shown again, not fetched again", async ({
    page,
  }) => {
    const first = await lookup(page, valueFor("virustotal"));
    expect(provider(first, "virustotal").status).toBe("error");

    const retry = providerCard(page, "VirusTotal").getByRole("button", { name: "Retry VirusTotal" });
    await expect(page.getByText("Providers that already have a fresh answer are not asked again.")).toBeVisible();
    const { body, answer } = await nextLookup(page, () => retry.click());

    expect(body).toEqual({ indicator: first.indicator.indicator_value, refresh: false });
    expect(answer.indicator.indicator_id).toBe(first.indicator.indicator_id);
    expect(provider(answer, "virustotal").status).toBe("error");
    for (const name of ["otx", "threatfox"] as const) {
      const before = provider(first, name);
      const after = provider(answer, name);
      expect(before.from_cache).toBe(false);
      expect(after.from_cache).toBe(true);
      expect(Date.parse(must(after.fetched_at))).toBe(Date.parse(must(before.fetched_at)));
      expect(after.summary).toEqual(before.summary);
      await expect(fact(providerCard(page, DISPLAY[name]), "Source")).toHaveText(
        "Stored answer from an earlier lookup",
      );
    }
    await expectDossier(page, answer);
    await expect(retry).toBeVisible();
  });
});

test.describe("in a browser set to another time zone", () => {
  test.use({ timezoneId: "America/Los_Angeles" });

  test("the provider cards still show India Standard Time", async ({ page }) => {
    const answer = await lookup(page, valueFor("otx"));
    expect(await page.evaluate(() => Intl.DateTimeFormat().resolvedOptions().timeZone)).toBe("America/Los_Angeles");

    await expect(providerCard(page, "AlienVault OTX")).toContainText(
      `Lookup attempted ${istText(must(answer.indicator.last_checked_at, "when the lookup ran"))}`,
    );
    for (const name of ["virustotal", "threatfox"] as const) {
      const card = providerCard(page, DISPLAY[name]);
      await expect(fact(card, "Checked")).toContainText(istText(must(provider(answer, name).fetched_at)));
      await expectOnlyIst(card);
    }
  });
});
