import type { APIRequestContext, Locator, Page } from "@playwright/test";

import type { FacetEntry, Indicator } from "../src/types/intel";
import {
  CLASSIFICATION_LABELS,
  TYPE_LABELS,
  countOf,
  countRequests,
  fetchIndicators,
  firstIndicator,
  storedIndicator,
  uniqueSuffix,
} from "./api";
import { expect, test } from "./fixtures";
import {
  ATTACKS,
  DOSSIER_ID,
  KINDS,
  TRAVERSAL_ID,
  activeContent,
  attack,
  expectInert,
  hostileFacets,
  hostileIndicators,
  hostileOverview,
  hostileProviders,
  overviewWithExtraCounts,
  serveHostileDossier,
  serveOverview,
  watchDialogs,
  type HostileFacets,
} from "./hostile";
import { investigate, openInvestigate, openList, openOverview, openRecord, openStatus } from "./open";
import { expectDossier, expectFound, listFilters, palette, panel } from "./pages";
import { bandOf, escapeRegExp, exactly, must } from "./text";

/**
 * Everything a provider sends, and everything a visitor types or links to, is written by someone
 * else. These tests give the app text built to become markup, a script, a link or a broken layout,
 * and check that it stays text: nothing is created in the page, nothing runs, nothing is followed.
 */
test.use({ reducedMotion: "reduce" });

test.beforeEach(({ page }) => {
  watchDialogs(page);
});

const OPEN_QUOTE = "\u201c";
const CLOSE_QUOTE = "\u201d";
const NOT_FOUND = { level: 1, name: "Indicator not found" } as const;

const flat = (text: string | null): string => (text ?? "").replace(/\s+/g, " ").trim();

/** What the browser prints for a country code, e.g. "Netherlands (NL)"; anything else is its own name. */
async function countryText(page: Page, code: string): Promise<string> {
  if (!/^[A-Z]{2}$/.test(code)) return code;
  const name = await page.evaluate(
    (region) => new Intl.DisplayNames(["en"], { type: "region" }).of(region),
    code,
  );
  return name === undefined || name === code ? code : `${name} (${code})`;
}

/** A row of a ranked list reads "<name>: <count>, highest risk <band>". */
function rowName(label: string, entry: FacetEntry): RegExp {
  const band = CLASSIFICATION_LABELS[bandOf(entry.max_risk)];
  return new RegExp(`^${escapeRegExp(label)}\\s?: ${escapeRegExp(countOf(entry.count))}, highest risk ${band}$`);
}

function figure(drawer: Locator, term: string): Locator {
  return drawer.locator("dt", { hasText: exactly(term) }).locator("xpath=following-sibling::dd[1]");
}

interface Facet {
  name: string;
  list: string;
  kind: string;
  entries: (facets: HostileFacets) => FacetEntry[];
  labelOf: (page: Page, key: string) => Promise<string>;
}

const asKey = (_page: Page, key: string): Promise<string> => Promise.resolve(key);

const FACETS: readonly Facet[] = [
  {
    name: "provider-reported country",
    list: "Top provider-reported countries",
    kind: "Provider-reported country",
    entries: (facets) => facets.countries,
    labelOf: countryText,
  },
  { name: "malware family", list: "Malware families", kind: "Malware family", entries: (f) => f.malware, labelOf: asKey },
  { name: "ATT&CK technique", list: "ATT&CK techniques", kind: "ATT&CK technique", entries: (f) => f.techniques, labelOf: asKey },
  { name: "provider tag", list: "Provider tags", kind: "Provider tag", entries: (f) => f.tags, labelOf: asKey },
];

test.describe("the scanner for active content", () => {
  const HAZARDS: readonly { name: string; html: string; finding: RegExp; blockedByPolicy?: true }[] = [
    {
      name: "an inline event handler",
      html: '<div onclick="void 0">x</div>',
      finding: /event handler \(onclick\)/,
      blockedByPolicy: true,
    },
    { name: "a javascript: link", html: '<a href="javascript:void(0)">x</a>', finding: /unsafe URL in href/ },
    { name: "a javascript: link in capitals", html: '<a href="JaVaScRiPt:void(0)">x</a>', finding: /unsafe URL in href/ },
    { name: "a javascript: link written with an entity", html: '<a href="&#106;avascript:void(0)">x</a>', finding: /unsafe URL in href/ },
    { name: "a link to another site", html: '<a href="https://evil.example/">x</a>', finding: /unsafe URL in href/ },
    { name: "a protocol-relative link", html: '<a href="//evil.example/">x</a>', finding: /unsafe URL in href/ },
    { name: "a link that a browser reads as protocol-relative", html: '<a href="/\\evil.example/">x</a>', finding: /unsafe URL in href/ },
    { name: "a link split by a tab", html: '<a href="/&#9;/evil.example/">x</a>', finding: /unsafe URL in href/ },
    {
      name: "a link that only starts like the pulse site",
      html: '<a href="https://otx.alienvault.com.evil.example/pulse/5c0ffee0aaaaaaaaaaaaaaaa">x</a>',
      finding: /unsafe URL in href/,
    },
    { name: "a pulse link whose ID is not a pulse ID", html: '<a href="https://otx.alienvault.com/pulse/x">x</a>', finding: /unsafe URL in href/ },
    { name: "a data: source", html: '<input src="data:text/html,x">', finding: /unsafe URL in src/ },
    { name: "a new-tab link with no rel", html: '<a href="/indicators" target="_blank">x</a>', finding: /new tab without noopener and noreferrer/ },
    {
      name: "a new-tab link with only noopener",
      html: '<a href="/indicators" target="_blank" rel="noopener">x</a>',
      finding: /new tab without noopener and noreferrer/,
    },
    { name: "a form with an action", html: '<form action="/x"></form>', finding: /the action attribute/ },
    { name: "a button with a formaction", html: '<button formaction="/x">x</button>', finding: /the formaction attribute/ },
    { name: "a srcdoc", html: '<div srcdoc="x"></div>', finding: /the srcdoc attribute/ },
    { name: "an image", html: '<img alt="">', finding: /<img> element/ },
    { name: "a frame", html: "<iframe></iframe>", finding: /<iframe> element/ },
    { name: "an object", html: "<object></object>", finding: /<object> element/ },
    { name: "an embed", html: "<embed>", finding: /<embed> element/ },
    { name: "a script", html: "<script>void 0</script>", finding: /a script that is not the app's bundle/ },
    { name: "a base element", html: '<base target="_self">', finding: /<base> element/ },
    { name: "a meta http-equiv", html: '<meta http-equiv="x-test" content="1">', finding: /a meta http-equiv/ },
    { name: "an SVG animation", html: '<svg><animate attributeName="x"></animate></svg>', finding: /<animate> element/ },
    { name: "an SVG foreignObject", html: "<svg><foreignObject></foreignObject></svg>", finding: /<foreignobject> element/ },
  ];

  for (const hazard of HAZARDS) {
    test(`reports ${hazard.name}`, async ({ page, guard }) => {
      if (hazard.blockedByPolicy) {
        // The browser refuses the handler the moment it is parsed, and says so; the scanner
        // must still see it, because the page's own policy is a second line of defence.
        guard.expectCspViolations();
        guard.expectConsole(/Executing inline event handler violates the following Content Security Policy/);
      }
      await page.goto("/no-such-page");
      await expect(page.getByRole("heading", { level: 1, name: "Page not found" })).toBeVisible();
      expect(await activeContent(page), "the page before anything is added").toEqual([]);

      await page.evaluate((html) => {
        const probe = document.createElement("div");
        probe.id = "scan-probe";
        // The point of the test is to put real markup in the page, which React never does.
        // eslint-disable-next-line no-restricted-syntax
        probe.innerHTML = html;
        document.body.append(probe);
      }, hazard.html);
      const found = await activeContent(page);
      expect(
        found.some((finding) => hazard.finding.test(finding)),
        `no finding matched ${String(hazard.finding)}; the scanner reported: ${JSON.stringify(found)}`,
      ).toBe(true);

      await page.locator("#scan-probe").evaluate((probe) => {
        probe.remove();
      });
      expect(await activeContent(page), "after the probe is removed").toEqual([]);
    });
  }

  const SCENES: readonly { name: string; open: (page: Page, request: APIRequestContext) => Promise<void> }[] = [
    { name: "the overview", open: (page) => openOverview(page) },
    {
      name: "a details drawer",
      open: async (page) => {
        await openOverview(page);
        await page.getByRole("list", { name: "Malware families" }).getByRole("button").first().click();
        await expect(page.getByRole("dialog")).toBeVisible();
      },
    },
    {
      name: "the command palette",
      open: async (page) => {
        await openOverview(page);
        await page.keyboard.press("Control+k");
        await expect(palette(page).dialog).toBeVisible();
      },
    },
    { name: "Investigate", open: (page) => openInvestigate(page) },
    { name: "the indicators list", open: (page) => openList(page) },
    {
      name: "a stored record",
      open: async (page, request) => openRecord(page, (await firstIndicator(request, { sort: "risk" })).indicator_id),
    },
    { name: "System status", open: (page) => openStatus(page) },
    {
      name: "the not-found page",
      open: async (page) => {
        await page.goto("/no-such-page");
        await expect(page.getByRole("heading", { level: 1, name: "Page not found" })).toBeVisible();
      },
    },
  ];

  for (const scene of SCENES) {
    test(`finds nothing in ${scene.name}, as the app ships`, async ({ page, request }) => {
      await scene.open(page, request);
      await expectInert(page, scene.name);
    });
  }
});

test.describe("an overview full of hostile names, values and links", () => {
  const facets = hostileFacets(ATTACKS);

  test.beforeEach(async ({ page }) => {
    await serveOverview(page, (overview) => hostileOverview(overview, ATTACKS));
    await openOverview(page);
  });

  for (const facet of FACETS) {
    test(`${facet.name}: every row reads as text, with its count and risk`, async ({ page }) => {
      const entries = facet.entries(facets);
      const rows = page.getByRole("list", { name: facet.list }).getByRole("button");
      await expect(rows).toHaveCount(entries.length);
      for (const [index, entry] of entries.entries()) {
        const label = await facet.labelOf(page, entry.key);
        await expect(rows.nth(index)).toHaveAccessibleName(rowName(label, entry));
        await expect(rows.nth(index).locator("[title]")).toHaveAttribute("title", label);
      }
      await expectInert(page, facet.name);
    });

    test(`${facet.name}: every details drawer shows the name and its sample indicator as text`, async ({ page }) => {
      const entries = facet.entries(facets);
      const rows = page.getByRole("list", { name: facet.list }).getByRole("button");
      for (const [index, entry] of entries.entries()) {
        await test.step(entry.key, async () => {
          const title = await facet.labelOf(page, entry.key);
          await rows.nth(index).click();
          const drawer = page.getByRole("dialog", { name: `${facet.kind}: ${title}`, exact: true });
          await expect(drawer).toBeVisible();
          await expect(drawer.getByRole("heading", { level: 2 })).toHaveText(title);
          await expect(figure(drawer, "Indicators")).toHaveText(String(entry.count));

          const sample = must(entry.samples[0]);
          const link = drawer.getByRole("listitem").getByRole("link");
          await expect(link).toHaveCount(1);
          await expect(link).toHaveText(sample.indicator_value);
          await expect(link).toHaveAttribute("href", `/indicators/${sample.indicator_id}`);
          await expect(drawer).toContainText(`${TYPE_LABELS[sample.indicator_type]} · score ${sample.risk_score}`);

          // Only a well-formed ATT&CK technique ID is ever turned into a link.
          const external = drawer.locator('a[target="_blank"]');
          if (facet.kind === "ATT&CK technique" && /^T\d{4}(\.\d{3})?$/.test(entry.key)) {
            await expect(external).toHaveCount(1);
            await expect(external).toHaveAttribute(
              "href",
              `https://attack.mitre.org/techniques/${entry.key.replace(".", "/")}/`,
            );
          } else {
            await expect(external).toHaveCount(0);
          }
          await expectInert(page, `the drawer for ${entry.key}`);
          await page.keyboard.press("Escape");
          await expect(drawer).toBeHidden();
        });
      }
    });
  }

  for (const list of [
    { name: "Highest-risk indicators", kind: "top" },
    { name: "Latest investigations", kind: "recent" },
  ] as const) {
    test(`${list.name}: values, links and times are plain text`, async ({ page }) => {
      const indicators = hostileIndicators(ATTACKS, list.kind);
      const rows = page.getByRole("list", { name: list.name }).getByRole("link");
      await expect(rows).toHaveCount(indicators.length);
      for (const [index, indicator] of indicators.entries()) {
        const row = rows.nth(index);
        await expect(row).toHaveAttribute("href", `/indicators/${encodeURIComponent(indicator.indicator_id)}`);
        await expect(row.locator("[title]").first()).toHaveAttribute("title", indicator.indicator_value);
        await expect(row).toContainText(indicator.indicator_value);
        await expect(row).toContainText(`${TYPE_LABELS[indicator.indicator_type]} · `);
        await expect(row).toContainText(`Score ${indicator.risk_score}`);
        // A time the page cannot read is "Never checked", not "Invalid Date".
        if (Number.isNaN(Date.parse(indicator.last_checked_at ?? ""))) {
          await expect(row).toContainText("Never checked");
          await expect(row.locator("time")).toHaveCount(0);
        } else {
          await expect(row.locator("time")).toHaveText(/ago$|^just now$/);
        }
      }
      await expectInert(page, list.name);
    });
  }

  test("the providers panel shows hostile names as text", async ({ page }) => {
    const rows = panel(page, "Intelligence providers").getByRole("listitem");
    for (const provider of hostileProviders(ATTACKS)) {
      const row = rows.filter({ hasText: flat(provider.display_name) });
      await expect(row).toHaveCount(1);
      await expect(row).toContainText(`Handles ${provider.supported_types.map((type) => TYPE_LABELS[type]).join(", ")}`);
      // The badge starts with a decorative symbol, so match the end of the row.
      await expect(row).toHaveText(provider.configured ? /\WConfigured$/ : /Not configured$/);
    }
    await expectInert(page, "the providers panel");
  });

  test("countries with names an object already has are listed, never placed on the map, and open", async ({ page }) => {
    const countries = facets.countries;
    const markers = page.getByRole("group", { name: "Provider-reported countries" }).getByRole("button");
    await expect(markers).toHaveCount(1);
    await expect(markers).toHaveAccessibleName(rowName(await countryText(page, "NL"), must(countries[0])));
    await expect(
      page.getByText(/^7 countries have no position on this map\. They are still counted in the list\./),
    ).toBeVisible();

    const list = page.getByRole("list", { name: "Top provider-reported countries" });
    for (const name of ["constructor", "__proto__", "toString", "hasOwnProperty", "valueOf"]) {
      await test.step(name, async () => {
        await list.getByRole("button", { name: new RegExp(`^${escapeRegExp(name)}\\s?:`) }).click();
        const drawer = page.getByRole("dialog", { name: `Provider-reported country: ${name}`, exact: true });
        await expect(drawer.getByRole("heading", { level: 2 })).toHaveText(name);
        await page.keyboard.press("Escape");
        await expect(drawer).toBeHidden();
      });
    }
    await expectInert(page, "the country list");
  });

  test("an ID that climbs out of the path is refused before any request is made", async ({ page }) => {
    const reads = countRequests(page, /\/api\/v1\/intel\/indicators\/[^?]/);
    const link = page.getByRole("list", { name: "Highest-risk indicators" }).getByRole("link").first();
    await expect(link).toHaveAttribute("href", "/indicators/..%2F..%2Fevil%3Fx%3D1%23frag");

    await link.click();
    await expect(page).toHaveURL(/\/indicators\/\.\.%2F\.\.%2Fevil%3Fx%3D1%23frag$/);
    await expect(page.getByRole("heading", NOT_FOUND)).toBeVisible();
    await expect(page.getByText("That is not a valid indicator ID. Open an indicator from the list instead.")).toBeVisible();
    await expect(page.getByRole("main")).not.toContainText("evil");
    expect(reads.count).toBe(0);
    expect(TRAVERSAL_ID).toContain("..");
    await expectInert(page, "the refused ID");
  });
});

test.describe("an overview with extra, unknown keys", () => {
  /** What the four panels that count by risk band and by type draw, down to the markup. */
  async function drawn(page: Page): Promise<string[]> {
    const parts = [
      page.getByRole("region", { name: "Key figures" }),
      panel(page, "Risk posture"),
      panel(page, "Indicator types by risk"),
      panel(page, "Indicator mix"),
    ];
    return Promise.all(parts.map(async (part) => part.evaluate((element) => element.innerHTML)));
  }

  test("are ignored: the counts by band and by type draw exactly what they drew before", async ({ page }) => {
    await openOverview(page);
    const before = await drawn(page);

    await serveOverview(page, (overview) => overviewWithExtraCounts(overview, ATTACKS));
    await page.reload();
    await expect(page.getByRole("region", { name: "Key figures" })).toBeVisible();

    expect(await drawn(page)).toEqual(before);
    await expectInert(page, "the counts");
  });
});

test.describe("the identity chip", () => {
  test("shows roles as text, and never the name or subject it was sent", async ({ page }) => {
    const role = attack("markup", "me-role");
    await page.route("**/api/v1/me", (route) =>
      route.fulfill({
        status: 200,
        json: {
          subject: attack("scheme", "me-subject"),
          name: attack("handler", "me-name"),
          roles: [role, "Analyst"],
          auth_mode: "entra",
        },
      }),
    );
    await openOverview(page);

    await expect(page.getByRole("banner")).toContainText(`${flat(role)} · Analyst`);
    const markup = await page.evaluate(() => document.documentElement.outerHTML);
    expect(markup).not.toContain("me-subject");
    expect(markup).not.toContain("me-name");
    await expectInert(page, "the identity chip");
  });
});

test.describe("a stored record whose every provider field is hostile", () => {
  test("shows each field as plain text, exactly as written, and nothing else", async ({ page }) => {
    const { dossier, shown, unread } = await serveHostileDossier(page, ATTACKS);
    await openRecord(page, DOSSIER_ID);
    await expectDossier(page, dossier);

    const text = flat(await page.locator("main").textContent());
    expect(
      shown.filter((item) => !text.includes(flat(item))),
      "strings the page should show but does not",
    ).toEqual([]);

    // Dates the page cannot read are replaced by words, never printed or put in an attribute.
    const markup = await page.evaluate(() => document.documentElement.outerHTML);
    expect(
      unread.filter((token) => markup.includes(token)),
      "values the page cannot read but still printed",
    ).toEqual([]);

    expect(flat(await page.title())).toBe(
      flat(`Indicator ${dossier.indicator.indicator_value.slice(0, 60)} \u00b7 CipherForge`),
    );
    await expectInert(page, "the dossier");
  });

  test("links out only to the two sites it builds links to itself, and only from valid IDs", async ({ page }) => {
    await serveHostileDossier(page, ATTACKS);
    await openRecord(page, DOSSIER_ID);

    const links = page.locator('a[target="_blank"]');
    await expect(links).toHaveCount(2);
    const found = await links.evaluateAll((anchors) =>
      anchors.map((anchor) => ({ href: anchor.getAttribute("href"), rel: anchor.getAttribute("rel") })),
    );
    expect(found.map((link) => link.href).sort()).toEqual([
      "https://attack.mitre.org/techniques/T1059/001/",
      "https://otx.alienvault.com/pulse/5c0ffee0aaaaaaaaaaaaaaaa",
    ]);
    for (const link of found) {
      expect(link.rel?.split(/\s+/)).toEqual(expect.arrayContaining(["noopener", "noreferrer"]));
    }
  });

  test("a link that opens a new tab cannot reach back to the page, or tell the other site where it came from", async ({
    page,
    context,
  }) => {
    const requested: string[] = [];
    await context.route("https://otx.alienvault.com/**", async (route) => {
      requested.push(route.request().url());
      await route.fulfill({ status: 200, contentType: "text/html", body: "<title>stub</title>" });
    });
    await serveHostileDossier(page, ATTACKS);
    await openRecord(page, DOSSIER_ID);

    const [popup] = await Promise.all([
      context.waitForEvent("page"),
      page.locator('a[href^="https://otx.alienvault.com/pulse/"]').click(),
    ]);
    await popup.waitForLoadState();
    expect(await popup.evaluate(() => window.opener as unknown), "the new tab holds no reference to the page").toBeNull();
    expect(
      await popup.evaluate(() => document.referrer),
      "what the other site is told about the page the visitor came from",
    ).toBe("");
    expect(requested).toEqual(["https://otx.alienvault.com/pulse/5c0ffee0aaaaaaaaaaaaaaaa"]);
    await popup.close();
  });

  test("the Referer check can tell: a link without noreferrer does leak under a permissive policy, the real one does not", async ({
    page,
    context,
  }) => {
    await context.route("https://otx.alienvault.com/**", (route) =>
      route.fulfill({ status: 200, contentType: "text/html", body: "<title>stub</title>" }),
    );
    await serveHostileDossier(page, ATTACKS);
    // The page's own policy would hide the Referer by itself, so take that cover away: no
    // <meta name="referrer"> and a header that sends the whole address.
    await page.route(
      (url) => url.pathname === `/indicators/${DOSSIER_ID}`,
      async (route) => {
        const response = await route.fetch();
        const body = (await response.text()).replace(/<meta name="referrer"[^>]*>/, "");
        const headers: Record<string, string> = { ...response.headers(), "referrer-policy": "unsafe-url" };
        delete headers["content-length"];
        await route.fulfill({ response, body, headers });
      },
    );
    await openRecord(page, DOSSIER_ID);
    await expect(page.locator('meta[name="referrer"]')).toHaveCount(0);

    await page.evaluate(() => {
      const control = document.createElement("a");
      control.id = "control";
      control.href = "https://otx.alienvault.com/control";
      control.target = "_blank";
      control.textContent = "control";
      document.body.append(control);
    });
    const referrerIn = async (tab: Page): Promise<string> => {
      await tab.waitForLoadState();
      const referrer = await tab.evaluate(() => document.referrer);
      await tab.close();
      return referrer;
    };
    const [controlTab] = await Promise.all([context.waitForEvent("page"), page.locator("#control").click()]);
    const [realTab] = await Promise.all([
      context.waitForEvent("page"),
      page.locator('a[href^="https://otx.alienvault.com/pulse/"]').click(),
    ]);

    expect(await referrerIn(controlTab), "the control link should tell the other site the page address").toBe(page.url());
    expect(await referrerIn(realTab), "the real link told the other site the page address").toBe("");
  });
});

test.describe("the real pipeline, from the browser to the database and back", () => {
  async function everyIndicator(request: APIRequestContext): Promise<Indicator[]> {
    const all: Indicator[] = [];
    for (let offset = 0; ; offset += 100) {
      const batch = await fetchIndicators(request, { limit: 100, offset });
      all.push(...batch.items);
      if (batch.items.length === 0 || all.length >= batch.total) return all;
    }
  }

  test("an indicator written as an attack is stored as written and shown as text everywhere", async ({
    page,
    request,
  }) => {
    const value = `https://e2e-${uniqueSuffix()}.example.net/p?q=');alert(document.cookie);//&r=javascript:alert(1)`;
    await investigate(page, value);
    await expect(panel(page, "CipherForge assessment")).toContainText(value);
    await expectInert(page, "the result");

    const stored = await storedIndicator(request, value);
    expect(stored.indicator_value).toBe(value);

    await openList(page, `?q=${encodeURIComponent(value)}`);
    await expectFound(page, 1);
    await expect(listFilters(page).search).toHaveValue(value);
    await expect(page.getByRole("table")).toContainText(value);
    await expectInert(page, "the list");

    await openRecord(page, stored.indicator_id);
    await expect(panel(page, "CipherForge assessment")).toContainText(value);
    await expectInert(page, "the stored record");

    await openOverview(page);
    await expect(page.getByRole("list", { name: "Latest investigations" })).toContainText(value);
    await expectInert(page, "the overview");
  });

  test("search text is matched as written and is never part of the query", async ({ page, request }) => {
    const everything = await everyIndicator(request);
    const queries = ["' OR '1'='1", "'; DROP TABLE threat_indicators; --", '" OR ""="', "%", "_", "%_%", "/", "\\"];
    for (const q of queries) {
      const expected = everything
        .filter((item) => item.indicator_value.toLowerCase().includes(q.toLowerCase()))
        .map((item) => item.indicator_id)
        .sort();
      const answer = await fetchIndicators(request, { q, limit: 100 });
      expect(answer.total, `matches for ${q}`).toBe(expected.length);
      expect(answer.items.map((item) => item.indicator_id).sort(), `matches for ${q}`).toEqual(expected);
    }
    expect((await fetchIndicators(request)).total, "the stored indicators").toBe(everything.length);

    await page.goto(`/indicators?q=${encodeURIComponent("' OR '1'='1")}`);
    await expectFound(page, 0);
    await expect(page.getByText("No indicators match these filters.")).toBeVisible();
    await expectInert(page, "the empty list");
  });
});

test.describe("text from the address bar, the search box and the palette", () => {
  for (const kind of KINDS) {
    const payload = attack(kind, "reflected");

    test(`${kind}: filters in the address are only ever shown in the search box`, async ({ page }) => {
      const query = new URLSearchParams({ q: payload, type: payload, classification: payload, sort: payload, page: payload });
      // An empty answer shows no table, so wait for the count instead of for the table.
      await page.goto(`/indicators?${query.toString()}`);
      await expectFound(page, 0);
      await expect(listFilters(page).search).toHaveValue(payload.trim());
      await expect(listFilters(page).type).toHaveValue("");
      await expect(listFilters(page).classification).toHaveValue("");
      await expect(listFilters(page).sort).toHaveValue("recent");
      await expectInert(page, "the list");
    });

    test(`${kind}: a lookup is never started by the address`, async ({ page }) => {
      const lookups = countRequests(page, /\/api\/v1\/intel\/investigate$/);
      await page.goto(`/investigate?${new URLSearchParams({ indicator: payload, autorun: "true" }).toString()}`);
      await expect(page.getByRole("heading", { level: 1, name: "Investigate an indicator" })).toBeVisible();
      await expect(page.getByRole("textbox", { name: /^Indicator/ })).toHaveValue("");
      await expect(page.getByRole("alert")).toHaveCount(0);
      expect(lookups.count).toBe(0);
      await expectInert(page, "Investigate");
    });

    test(`${kind}: an unknown record ID or page is never echoed`, async ({ page }) => {
      const reads = countRequests(page, /\/api\/v1\/intel\/indicators\/[^?]/);
      await page.goto(`/indicators/${encodeURIComponent(payload)}`);
      await expect(page.getByRole("heading", NOT_FOUND)).toBeVisible();
      await expect(page.getByRole("main")).not.toContainText("reflected");
      await expectInert(page, "the refused ID");

      await page.goto(`/${encodeURIComponent(payload)}`);
      await expect(page.getByRole("heading", { level: 1, name: "Page not found" })).toBeVisible();
      await expect(page.getByRole("main")).not.toContainText("reflected");
      await expectInert(page, "the unknown page");
      expect(reads.count).toBe(0);
    });

    test(`${kind}: typed into the palette it is offered as text and searches for it as text`, async ({ page }) => {
      await openStatus(page);
      await page.keyboard.press("Control+k");
      const { box, options } = palette(page);
      await box.fill(payload);
      await expect(options.nth(0)).toHaveText(`Investigate ${OPEN_QUOTE}${flat(payload)}${CLOSE_QUOTE}Ask the providers`);
      await expect(options.nth(1)).toHaveText(
        `Search indicators for ${OPEN_QUOTE}${flat(payload)}${CLOSE_QUOTE}Stored indicators`,
      );
      await expectInert(page, "the palette");

      await page.keyboard.press("ArrowDown");
      await page.keyboard.press("Enter");
      await expect(page).toHaveURL(new RegExp(`/indicators\\?q=`));
      await expect(listFilters(page).search).toHaveValue(payload.trim());
      await expectFound(page, 0);
      await expectInert(page, "the list");
    });
  }

  test("an indicator written as markup is refused by the API, and the page shows its own words", async ({
    page,
    guard,
  }) => {
    guard.expectStatus(422);
    const value = '"><svg/onload=window.__pwned=1>';
    await investigate(page, value);
    const notice = page.getByRole("alert");
    await expect(notice).toContainText("That request was not accepted");
    await expect(notice).toContainText("Reference: ");
    await expect(notice).not.toContainText("onload");
    await expect(page.getByRole("textbox", { name: /^Indicator/ })).toHaveValue(value);
    await expectInert(page, "the refusal");
  });
});
