import type { Page } from "@playwright/test";

import { fetchIndicators } from "./api";
import { expect, test } from "./fixtures";
import { palette } from "./pages";

const DOT = "\u00b7";
const OPEN_QUOTE = "\u201c";
const CLOSE_QUOTE = "\u201d";

const PAGES = [
  { path: "/", link: "Overview", heading: "Overview", title: "Overview" },
  { path: "/investigate", link: "Investigate", heading: "Investigate an indicator", title: "Investigate" },
  { path: "/indicators", link: "Indicators", heading: "Indicators", title: "Indicators" },
  { path: "/network", link: "Network", heading: "Network", title: "Network" },
  { path: "/files", link: "Files", heading: "Files", title: "Files" },
  { path: "/status", link: "System status", heading: "System status", title: "System status" },
] as const;

async function runningAnimations(page: Page): Promise<number> {
  return page.evaluate(() => document.getAnimations().filter((a) => a.playState === "running").length);
}

test.describe("pages and navigation", () => {
  for (const entry of PAGES) {
    test(`${entry.link}: heading, tab title and current-page marker`, async ({ page }) => {
      await page.goto(entry.path);
      await expect(
        page.getByRole("heading", { level: 1, name: entry.heading, exact: true }),
      ).toBeVisible();
      await expect(page).toHaveTitle(`${entry.title} ${DOT} CipherForge`);

      const nav = page.getByRole("navigation", { name: "Primary" });
      for (const other of PAGES) {
        const link = nav.getByRole("link", { name: other.link, exact: true });
        if (other.path === entry.path) await expect(link).toHaveAttribute("aria-current", "page");
        else await expect(link).not.toHaveAttribute("aria-current", "page");
      }
    });
  }

  test("the rail moves between pages, moves focus to the content and keeps history", async ({ page }) => {
    await page.goto("/");
    const nav = page.getByRole("navigation", { name: "Primary" });

    await nav.getByRole("link", { name: "Investigate", exact: true }).click();
    await expect(page).toHaveURL(/\/investigate$/);
    await expect(page.locator("#main-content")).toBeFocused();

    await nav.getByRole("link", { name: "System status", exact: true }).click();
    await expect(page).toHaveURL(/\/status$/);

    await page.goBack();
    await expect(page.getByRole("heading", { level: 1, name: "Investigate an indicator" })).toBeVisible();
    await page.goForward();
    await expect(page.getByRole("heading", { level: 1, name: "System status" })).toBeVisible();
  });

  test("the logo leads home, and its name is the words it shows", async ({ page }) => {
    await page.goto("/status");
    const logo = page.getByRole("banner").getByRole("link", { name: /^CIPHERFORGE/ });
    await expect(logo).toHaveAccessibleName("CIPHERFORGE Security operations console");
    await logo.click();
    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
  });

  test("the skip link is the first tab stop and jumps to the content without touching the address", async ({
    page,
  }) => {
    await page.goto("/indicators");
    await expect(page.getByRole("heading", { level: 1, name: "Indicators" })).toBeVisible();

    await page.keyboard.press("Tab");
    const skip = page.getByRole("link", { name: "Skip to main content" });
    await expect(skip).toBeFocused();
    const box = await skip.boundingBox();
    expect(box, "the focused skip link is on screen").not.toBeNull();
    expect(box?.x).toBeGreaterThanOrEqual(0);
    expect(box?.y).toBeGreaterThanOrEqual(0);

    await page.keyboard.press("Enter");
    await expect(page.locator("#main-content")).toBeFocused();
    expect(new URL(page.url()).hash).toBe("");
  });

  for (const path of ["/no-such-page", "/investigate/extra", "/indicators/a/b"]) {
    test(`an unknown address (${path}) shows the not-found page and a way home`, async ({ page }) => {
      await page.goto(path);
      await expect(page.getByRole("heading", { level: 1, name: "Page not found" })).toBeVisible();
      await expect(page).toHaveTitle(`Page not found ${DOT} CipherForge`);
      await page.getByRole("link", { name: "Go to the overview" }).click();
      await expect(page).toHaveURL(/\/$/);
      await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
    });
  }

  test("a trailing slash still reaches the page", async ({ page }) => {
    await page.goto("/status/");
    await expect(page.getByRole("heading", { level: 1, name: "System status" })).toBeVisible();
  });
});

test.describe("top bar", () => {
  test("shows a ticking IST clock, the caller's role and the API state", async ({ page, request }) => {
    await page.goto("/");
    const bar = page.getByRole("banner");
    const clock = bar.locator("time");

    await expect(clock).toHaveText(/^\d{2}:\d{2}:\d{2} (AM|PM) IST$/);
    const first = await clock.textContent();
    await expect.poll(() => clock.textContent(), { timeout: 5_000 }).not.toBe(first);

    const stamp = await clock.getAttribute("datetime");
    expect(Math.abs(Date.now() - Date.parse(stamp ?? ""))).toBeLessThan(10_000);

    const me = (await (await request.get("/api/v1/me")).json()) as {
      subject: string;
      name: string | null;
      roles: string[];
      auth_mode: string;
    };
    await expect(bar).toContainText(me.roles.join(` ${DOT} `));
    await expect(bar).toContainText("Dev auth");
    // The chip says which role the caller holds, never who they are.
    await expect(bar).not.toContainText(me.subject);
    if (me.name) await expect(bar).not.toContainText(me.name);

    const beacon = bar.getByRole("link", { name: "API ONLINE" });
    await expect(beacon).toHaveAttribute("href", "/status");
    await beacon.click();
    await expect(page.getByRole("heading", { level: 1, name: "System status" })).toBeVisible();
  });

  test("warns on every page that the providers are simulated", async ({ page, request }) => {
    const stats = (await (await request.get("/api/v1/intel/stats")).json()) as {
      providers: { simulated: boolean }[];
    };
    expect(stats.providers.some((provider) => provider.simulated)).toBe(true);

    const warning = page.getByText("Simulated providers: this is demo data, not real threat intelligence");
    for (const entry of PAGES) {
      await page.goto(entry.path);
      await expect(warning).toHaveCount(1);
      await expect(warning).toBeVisible();
    }
  });

  test("shows no simulation warning when the providers are real", async ({ page }) => {
    await page.route("**/api/v1/intel/stats", async (route) => {
      const response = await route.fetch();
      const stats = (await response.json()) as { providers: { simulated: boolean }[] };
      await route.fulfill({
        status: response.status(),
        json: { ...stats, providers: stats.providers.map((p) => ({ ...p, simulated: false })) },
      });
    });
    await page.goto("/");
    await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
    await expect(page.getByText(/Simulated providers: this is demo data/)).toHaveCount(0);
  });
});

test.describe("keyboard shortcuts", () => {
  test("Ctrl+K opens the command palette and a second press closes it", async ({ page }) => {
    await page.goto("/");
    const { dialog, box } = palette(page);

    await page.keyboard.press("Control+k");
    await expect(dialog).toBeVisible();
    await expect(box).toBeFocused();

    await page.keyboard.press("Control+k");
    await expect(dialog).toBeHidden();
  });

  test("the slash key opens the palette from anywhere that is not a text field", async ({ page }) => {
    await page.goto("/status");
    await expect(page.getByRole("heading", { level: 1, name: "System status" })).toBeVisible();
    await page.keyboard.press("/");
    await expect(palette(page).dialog).toBeVisible();
  });

  for (const [letter, path, heading] of [
    ["i", "/investigate", "Investigate an indicator"],
    ["l", "/indicators", "Indicators"],
    ["n", "/network", "Network"],
    ["f", "/files", "Files"],
    ["s", "/status", "System status"],
    ["o", "/", "Overview"],
  ] as const) {
    test(`G then ${letter.toUpperCase()} goes to ${path}`, async ({ page }) => {
      // Start somewhere else so the move is visible.
      await page.goto(path === "/status" ? "/indicators" : "/status");
      await page.keyboard.press("g");
      await page.keyboard.press(letter);
      await expect(page).toHaveURL(new RegExp(`${path === "/" ? "/" : path}$`));
      await expect(page.getByRole("heading", { level: 1, name: heading, exact: true })).toBeVisible();
    });
  }

  test("G followed by a pause does nothing", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
    await page.keyboard.press("g");
    await page.waitForTimeout(1_300);
    await page.keyboard.press("i");
    await expect(page).toHaveURL(/\/$/);
    await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
  });

  test("plain keys are ordinary text inside a field", async ({ page }) => {
    await page.goto("/investigate");
    const field = page.getByRole("textbox", { name: "Indicator" });
    await field.click();
    await page.keyboard.type("gs/o");
    await expect(field).toHaveValue("gs/o");
    await expect(page).toHaveURL(/\/investigate$/);
    await expect(palette(page).dialog).toBeHidden();
  });

  test("shortcuts stand down while the palette is open", async ({ page }) => {
    await page.goto("/");
    const { box } = palette(page);
    await page.keyboard.press("Control+k");
    await page.keyboard.type("go/i");
    await expect(box).toHaveValue("go/i");
    await expect(page).toHaveURL(/\/$/);
  });
});

test.describe("command palette", () => {
  test("offers the pages and the effects switch, with the first option highlighted", async ({ page }) => {
    await page.goto("/");
    const { box, options } = palette(page);
    await page.keyboard.press("Control+k");

    await expect(options).toHaveText([
      /^Go to Overview/,
      /^Go to Investigate/,
      /^Go to Indicators/,
      /^Go to Network/,
      /^Go to Files/,
      /^Go to System status/,
      /^Turn visual effects off/,
    ]);
    await expect(options.nth(0)).toHaveAttribute("aria-selected", "true");
    const firstId = await options.nth(0).getAttribute("id");
    await expect(box).toHaveAttribute("aria-activedescendant", firstId ?? "");
  });

  test("arrow keys move through the options, wrap around, and Enter runs the highlighted one", async ({
    page,
  }) => {
    await page.goto("/");
    const { dialog, options } = palette(page);
    await page.keyboard.press("Control+k");

    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowDown");
    await expect(options.nth(2)).toHaveAttribute("aria-selected", "true");
    await expect(options.nth(0)).toHaveAttribute("aria-selected", "false");

    // From the first option, up wraps to the last.
    await page.keyboard.press("ArrowUp");
    await page.keyboard.press("ArrowUp");
    await page.keyboard.press("ArrowUp");
    await expect(options.nth(6)).toHaveAttribute("aria-selected", "true");

    // Four steps up from the last option: effects switch -> System status -> Files -> Network ->
    // Indicators.
    for (let press = 0; press < 4; press += 1) await page.keyboard.press("ArrowUp");
    await expect(options.nth(2)).toHaveAttribute("aria-selected", "true");
    await page.keyboard.press("Enter");

    await expect(dialog).toBeHidden();
    await expect(page).toHaveURL(/\/indicators$/);
    await expect(page.getByRole("heading", { level: 1, name: "Indicators" })).toBeVisible();
  });

  test("typing offers to investigate or search for the text and filters the pages", async ({ page }) => {
    await page.goto("/");
    const { box, options } = palette(page);
    await page.keyboard.press("Control+k");

    await box.fill("stat");
    await expect(options).toHaveText([
      new RegExp(`^Investigate ${OPEN_QUOTE}stat${CLOSE_QUOTE}`),
      new RegExp(`^Search indicators for ${OPEN_QUOTE}stat${CLOSE_QUOTE}`),
      /^Go to System status/,
    ]);

    await box.fill("zq9x");
    await expect(options).toHaveCount(2);

    await box.fill("motion");
    await expect(options).toHaveText([/^Investigate/, /^Search indicators for/, /^Turn visual effects off/]);

    await box.fill("");
    await expect(options).toHaveCount(7);
  });

  test("clicking an option runs it", async ({ page }) => {
    await page.goto("/");
    const { dialog, options } = palette(page);
    await page.keyboard.press("Control+k");
    await options.filter({ hasText: "Go to System status" }).click();
    await expect(dialog).toBeHidden();
    await expect(page.getByRole("heading", { level: 1, name: "System status" })).toBeVisible();
  });

  test("searching from the palette opens the indicators list filtered by the text", async ({
    page,
    request,
  }) => {
    await page.goto("/");
    const { box, options } = palette(page);
    await page.keyboard.press("Control+k");
    await box.fill("2100:");
    await options.filter({ hasText: "Search indicators for" }).click();

    await expect(page).toHaveURL(/\/indicators\?q=2100%3A$/);
    await expect(page.getByRole("searchbox", { name: "Search" })).toHaveValue("2100:");
    const expected = await fetchIndicators(request, { q: "2100:" });
    await expect(page.getByRole("status").filter({ hasText: "found." })).toHaveText(
      `${expected.total} ${expected.total === 1 ? "indicator" : "indicators"} found.`,
    );
  });

  test("Escape closes it and focus returns to the button that opened it", async ({ page }) => {
    await page.goto("/");
    const { dialog } = palette(page);
    const opener = page.getByRole("button", { name: "Command palette" });

    await opener.click();
    await expect(dialog).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
    await expect(opener).toBeFocused();
  });

  test("a click on the backdrop closes it", async ({ page }) => {
    await page.goto("/");
    const { dialog } = palette(page);
    await page.keyboard.press("Control+k");
    await expect(dialog).toBeVisible();
    await page.mouse.click(5, 5);
    await expect(dialog).toBeHidden();
  });

  test("keeps keyboard focus inside while open and makes the page behind inert", async ({ page }) => {
    await page.goto("/");
    const { dialog, box } = palette(page);
    await page.keyboard.press("Control+k");
    await expect(page.locator("#root")).toHaveAttribute("inert", "");

    for (let press = 0; press < 3; press += 1) {
      await page.keyboard.press("Tab");
      await expect(box).toBeFocused();
    }
    await page.keyboard.press("Shift+Tab");
    await expect(dialog.locator(":focus")).toHaveCount(1);

    await page.keyboard.press("Escape");
    await expect(page.locator("#root")).not.toHaveAttribute("inert", "");
  });

  test("limits what can be typed", async ({ page }) => {
    await page.goto("/");
    const { box } = palette(page);
    await page.keyboard.press("Control+k");
    await box.fill("x".repeat(3_000));
    await expect(box).toHaveValue("x".repeat(2_048));
  });
});

test.describe("visual effects switch", () => {
  test("starts on, can be turned off and on, and is remembered across reloads", async ({ page }) => {
    await page.goto("/");
    const html = page.locator("html");
    const toggle = page.getByRole("button", { name: "Effects" });

    await expect(toggle).toHaveAttribute("aria-pressed", "true");
    await expect(html).toHaveAttribute("data-effects", "on");
    await expect.poll(() => runningAnimations(page), { message: "effects on animate" }).toBeGreaterThan(0);

    await toggle.click();
    await expect(toggle).toHaveAttribute("aria-pressed", "false");
    await expect(html).toHaveAttribute("data-effects", "off");
    await expect.poll(() => runningAnimations(page), { message: "effects off are still" }).toBe(0);
    expect(await page.evaluate(() => localStorage.getItem("cipherforge.effects"))).toBe("off");

    await page.reload();
    await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
    await expect(page.getByRole("button", { name: "Effects" })).toHaveAttribute("aria-pressed", "false");
    await expect(html).toHaveAttribute("data-effects", "off");

    // Page content is complete without motion: the same figures are there.
    await expect(page.getByRole("region", { name: "Key figures" }).getByRole("link")).toHaveCount(5);

    await page.getByRole("button", { name: "Effects" }).click();
    await expect(html).toHaveAttribute("data-effects", "on");
    expect(await page.evaluate(() => localStorage.getItem("cipherforge.effects"))).toBe("on");
  });

  test("the palette can switch effects too, and says what it will do", async ({ page }) => {
    await page.goto("/");
    const { box, options } = palette(page);

    await page.keyboard.press("Control+k");
    await box.fill("effects");
    await options.filter({ hasText: "Turn visual effects off" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-effects", "off");

    await page.keyboard.press("Control+k");
    await box.fill("effects");
    await expect(options.filter({ hasText: "Turn visual effects on" })).toHaveCount(1);
    await options.filter({ hasText: "Turn visual effects on" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-effects", "on");
  });

  test.describe("when the system asks for reduced motion", () => {
    test.use({ reducedMotion: "reduce" });

    test("effects stay off, the switch is disabled and nothing animates", async ({ page }) => {
      // Even a stored "on" must not win over the system setting.
      await page.addInitScript(() => localStorage.setItem("cipherforge.effects", "on"));
      await page.goto("/");
      await expect(page.getByRole("heading", { level: 1, name: "Overview" })).toBeVisible();

      const toggle = page.getByRole("button", { name: "Effects" });
      await expect(toggle).toBeDisabled();
      await expect(toggle).toHaveAttribute("aria-pressed", "false");
      await expect(toggle).toHaveAttribute("title", /reduced motion/);
      await expect(page.locator("html")).toHaveAttribute("data-effects", "off");
      await expect.poll(() => runningAnimations(page)).toBe(0);

      const { options } = palette(page);
      await page.keyboard.press("Control+k");
      await expect(options.filter({ hasText: "visual effects" })).toHaveCount(0);
    });
  });
});
