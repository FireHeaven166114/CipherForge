import type { Locator, Page } from "@playwright/test";

import { firstIndicator, fresh } from "./api";
import { expect, test } from "./fixtures";
import { sidewaysOverflow } from "./layout";
import { investigate, openList, openOverview, openRecord, openStatus } from "./open";
import { panel } from "./pages";

// These specs are about the moving parts, so motion is on. The rest of the suite mostly runs
// without it, and the rules that keep the console usable hold either way.
test.use({ reducedMotion: "no-preference" });

const DESKTOP = { width: 1440, height: 900 };
const PHONE = { width: 390, height: 844 };

/** One frame of a heading: the text a screen reader reads, and the text on screen. */
interface HeadingSample {
  spoken: string;
  shown: string;
}

function primaryNav(page: Page): Locator {
  return page.getByRole("navigation", { name: "Primary" });
}

/** Animations that are running now (CSS or Web Animations) on elements that match the selector. */
function running(page: Page, selector: string): Promise<number> {
  return page.evaluate(
    (match) =>
      document.getAnimations().filter((animation) => {
        const target = (animation.effect as KeyframeEffect | null)?.target;
        return animation.playState === "running" && target instanceof Element && target.matches(match);
      }).length,
    selector,
  );
}

/** The particle canvas as an image: whether anything is painted on it, and what it looks like. */
function fieldImage(page: Page): Promise<{ painted: boolean; image: string }> {
  return page.evaluate(() => {
    const canvas = document.querySelector<HTMLCanvasElement>("canvas.cf-field");
    if (canvas === null) return { painted: false, image: "" };
    const blank = document.createElement("canvas");
    blank.width = canvas.width;
    blank.height = canvas.height;
    const image = canvas.toDataURL();
    return { painted: image !== blank.toDataURL(), image };
  });
}

/**
 * From the first script of the page on, counts the entrances it starts: every time an element that
 * asks for one (data-reveal) is animated. Call it before the page is opened.
 */
async function countEntrances(page: Page): Promise<() => Promise<number>> {
  await page.addInitScript(() => {
    let started = 0;
    Object.defineProperty(window, "__cfEntrances", { get: () => started });
    const animate = Element.prototype.animate;
    Element.prototype.animate = function (this: Element, keyframes, options) {
      if (this.matches("[data-reveal]")) started += 1;
      return animate.call(this, keyframes, options);
    };
  });
  return () => page.evaluate(() => (window as unknown as { __cfEntrances: number }).__cfEntrances);
}

/** The biggest difference, in pixels, between the lamp and the link it is meant to sit on. */
async function lampOffset(page: Page, link: Locator): Promise<number> {
  const [lamp, target] = await Promise.all([page.locator(".cf-lamp").boundingBox(), link.boundingBox()]);
  if (lamp === null || target === null) return Number.POSITIVE_INFINITY;
  return Math.max(
    Math.abs(lamp.x - target.x),
    Math.abs(lamp.y - target.y),
    Math.abs(lamp.width - target.width),
    Math.abs(lamp.height - target.height),
  );
}

async function expectLampOn(page: Page, link: Locator): Promise<void> {
  // Half a pixel is what rounding to whole pixels costs on a phone, where four tabs share 390px.
  await expect
    .poll(() => lampOffset(page, link), { message: "the lamp sits on the link of the open page", timeout: 5_000 })
    .toBeLessThan(0.5);
}

test.describe("the background", () => {
  test("is a living layer that never gets in the way", async ({ page }) => {
    await openOverview(page);
    const atmosphere = page.locator(".cf-atmosphere");
    await expect(atmosphere).toHaveAttribute("aria-hidden", "true");
    expect(await atmosphere.evaluate((element) => getComputedStyle(element).pointerEvents)).toBe("none");

    // The three orbs drift, and the dots are drawn and keep moving.
    await expect.poll(() => running(page, ".cf-orb"), { message: "orbs drift" }).toBeGreaterThanOrEqual(3);
    await expect(page.locator("canvas.cf-field")).toHaveCount(1);
    await expect.poll(async () => (await fieldImage(page)).painted, { message: "dots are painted" }).toBe(true);
    const before = (await fieldImage(page)).image;
    await expect
      .poll(async () => (await fieldImage(page)).image !== before, { message: "dots drift" })
      .toBe(true);
  });

  test("goes away completely with the switch, and comes back with it without replaying the page", async ({
    page,
  }) => {
    const entrances = await countEntrances(page);
    await openOverview(page);
    await expect.poll(() => running(page, "[data-reveal]"), { message: "the entrance has ended" }).toBe(0);
    const played = await entrances();
    expect(played, "the panels had their entrance").toBeGreaterThan(0);

    const toggle = page.getByRole("button", { name: "Effects" });
    const layers = page.locator("canvas.cf-field, .cf-cursor, .cf-lamp");
    await expect(layers).toHaveCount(3);

    await toggle.click();
    await expect(layers).toHaveCount(0);

    await toggle.click();
    await expect(layers).toHaveCount(3);
    // Panels that have had their entrance do not have it again.
    expect(await entrances(), "entrances after the switch went off and on").toBe(played);
    await expectLampOn(page, primaryNav(page).getByRole("link", { name: "Overview", exact: true }));
  });

  for (const [name, size] of [
    ["desktop", DESKTOP],
    ["phone", PHONE],
  ] as const) {
    test(`does not make the ${name} page wider than the window`, async ({ page }) => {
      await page.setViewportSize(size);
      await openOverview(page);
      await expect(page.locator("canvas.cf-field")).toHaveCount(1);
      expect(await sidewaysOverflow(page)).toEqual([]);
    });
  }
});

test.describe("the navigation lamp", () => {
  test("sits on the open page, glides to the next one, and goes dark on a page that has no link", async ({
    page,
  }) => {
    await openOverview(page);
    const nav = primaryNav(page);
    await expect(page.locator(".cf-lamp")).toHaveAttribute("aria-hidden", "true");
    await expectLampOn(page, nav.getByRole("link", { name: "Overview", exact: true }));

    await nav.getByRole("link", { name: "Investigate", exact: true }).click();
    await expect(page).toHaveURL(/\/investigate$/);
    await expectLampOn(page, nav.getByRole("link", { name: "Investigate", exact: true }));

    await nav.getByRole("link", { name: "System status", exact: true }).click();
    await expect(page).toHaveURL(/\/status$/);
    await expectLampOn(page, nav.getByRole("link", { name: "System status", exact: true }));

    await page.goto("/no-such-page");
    await expect(page.getByRole("heading", { level: 1, name: "Page not found" })).toBeVisible();
    await expect
      .poll(() => page.locator(".cf-lamp").evaluate((lamp) => getComputedStyle(lamp).opacity), {
        message: "the lamp is out",
      })
      .toBe("0");
  });

  test.describe("on a phone", () => {
    test.use({ viewport: PHONE });

    test("lights the open page's tab in the bar along the bottom", async ({ page }) => {
      await openOverview(page);
      const nav = primaryNav(page);
      await expectLampOn(page, nav.getByRole("link", { name: "Overview", exact: true }));

      await nav.getByRole("link", { name: "Indicators", exact: true }).click();
      await expect(page).toHaveURL(/\/indicators$/);
      await expectLampOn(page, nav.getByRole("link", { name: "Indicators", exact: true }));

      // The last tab ends where the window does. The tab bar has five links and leaves out System status.
      await nav.getByRole("link", { name: "Files", exact: true }).click();
      await expect(page).toHaveURL(/\/files$/);
      await expectLampOn(page, nav.getByRole("link", { name: "Files", exact: true }));
      const lamp = await page.locator(".cf-lamp").boundingBox();
      if (lamp === null) throw new Error("the lamp has a box");
      expect(lamp.x + lamp.width, "the lamp ends inside the window").toBeLessThanOrEqual(PHONE.width + 0.01);
    });
  });
});

test.describe("the glass under the pointer", () => {
  test("lights up near the pointer, follows it, and goes out when the window loses focus", async ({ page }) => {
    await openOverview(page);
    const modules = panel(page, "Platform modules");
    await modules.scrollIntoViewIfNeeded();
    const box = await modules.boundingBox();
    if (box === null) throw new Error("the modules panel has a box");

    await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 4 });
    await expect(modules).toHaveAttribute("data-lit", "");
    await expect
      .poll(() => modules.evaluate((element) => element.style.getPropertyValue("--mx")), { message: "pointer place" })
      .toMatch(/^-?\d+(\.\d)?px$/);

    const lit = await page.locator("[data-lit]").count();
    const panels = await page.locator(".hud-panel").count();
    expect(lit, "some of the glass is lit").toBeGreaterThan(0);
    expect(lit, "but not all of it").toBeLessThan(panels);

    await page.evaluate(() => window.dispatchEvent(new Event("blur")));
    await expect(page.locator("[data-lit]")).toHaveCount(0);
  });

  test.describe("on a touch screen", () => {
    test.use({ hasTouch: true, isMobile: true, viewport: PHONE });

    test("nothing follows a pointer, because a finger has no hover", async ({ page }) => {
      await openOverview(page);
      const modules = panel(page, "Platform modules");
      await modules.scrollIntoViewIfNeeded();
      const box = await modules.boundingBox();
      if (box === null) throw new Error("the modules panel has a box");

      await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 4 });
      await page.waitForTimeout(400);
      await expect(page.locator("[data-lit]")).toHaveCount(0);
      await expect(page.locator(".cf-cursor")).toHaveCount(1);
    });
  });
});

test.describe("entrances and headings", () => {
  test("panels arrive with a staggered entrance that leaves nothing behind", async ({ page }) => {
    const entrances = await countEntrances(page);
    await openOverview(page);

    expect(await entrances(), "elements that were given an entrance").toBeGreaterThanOrEqual(5);

    await expect.poll(() => running(page, "[data-reveal]"), { message: "entrances end" }).toBe(0);
    const leftovers = await page.evaluate(
      () =>
        [...document.querySelectorAll<HTMLElement>("[data-reveal]")].filter(
          (element) => element.style.opacity !== "" || element.style.transform !== "",
        ).length,
    );
    expect(leftovers, "elements that kept an inline opacity or transform").toBe(0);
  });

  test("a heading is spoken as it reads while its letters decode on screen, and ends as plain text", async ({
    page,
  }) => {
    await page.addInitScript(() => {
      const samples: HeadingSample[] = [];
      Object.defineProperty(window, "__cfHeading", { value: samples });
      const textOf = (node: Node, skip: (element: Element) => boolean): string => {
        if (node.nodeType === Node.TEXT_NODE) return node.textContent ?? "";
        if (node instanceof Element && skip(node)) return "";
        return [...node.childNodes].map((child) => textOf(child, skip)).join("");
      };
      // Every frame from the start: what a screen reader would read, and what a person would see.
      const sample = () => {
        const heading = document.querySelector("h1");
        if (heading !== null) {
          samples.push({
            spoken: textOf(heading, (element) => element.getAttribute("aria-hidden") === "true"),
            shown: textOf(heading, (element) => element.classList.contains("sr-only")),
          });
        }
        if (samples.length < 400) requestAnimationFrame(sample);
      };
      requestAnimationFrame(sample);
    });
    await page.goto("/status");

    const heading = page.getByRole("heading", { level: 1 });
    await expect(heading).toHaveText("System status");
    await expect(heading.locator('[aria-hidden="true"]')).toHaveCount(0);
    await expect(heading).toHaveAccessibleName("System status");

    const samples = await page.evaluate(() => (window as unknown as { __cfHeading: HeadingSample[] }).__cfHeading);
    expect(samples.length, "frames in which the heading was there").toBeGreaterThan(0);
    expect([...new Set(samples.map((sample) => sample.spoken.trim()))], "what is read out, on every frame").toEqual([
      "System status",
    ]);
    expect(
      samples.some((sample) => sample.shown.trim() !== "System status"),
      "the letters were still decoding on screen at first",
    ).toBe(true);
  });
});

test.describe("every page with the effects on", () => {
  for (const [name, size] of [
    ["desktop", DESKTOP],
    ["phone", PHONE],
  ] as const) {
    test(`runs on the ${name} without a console message, a policy violation or a sideways scroll`, async ({
      page,
      request,
    }) => {
      await page.setViewportSize(size);
      const record = await firstIndicator(request, { sort: "risk" });
      const visits: ReadonlyArray<readonly [string, () => Promise<void>]> = [
        ["overview", () => openOverview(page)],
        [
          "a lookup and its result",
          async () => {
            await investigate(page, fresh.domain());
            await expect(page.getByRole("link", { name: "Open the saved record" })).toBeVisible({ timeout: 30_000 });
          },
        ],
        ["the indicators list", () => openList(page)],
        ["one record", () => openRecord(page, record.indicator_id)],
        ["system status", () => openStatus(page)],
        [
          "a page that does not exist",
          async () => {
            await page.goto("/no-such-page");
            await expect(page.getByRole("heading", { level: 1, name: "Page not found" })).toBeVisible();
          },
        ],
      ];

      for (const [what, open] of visits) {
        await test.step(what, async () => {
          await open();
          await expect(page.locator("canvas.cf-field")).toHaveCount(1);
          expect(await sidewaysOverflow(page), `sticks out sideways: ${what}`).toEqual([]);
        });
      }
    });
  }
});

test.describe("when the system asks for reduced motion", () => {
  test.use({ reducedMotion: "reduce" });

  test("there is no canvas, lamp or pointer light, and the open page is still marked", async ({ page }) => {
    await openOverview(page);
    await expect(page.locator("canvas.cf-field, .cf-cursor, .cf-lamp")).toHaveCount(0);
    await expect(primaryNav(page).getByRole("link", { name: "Overview", exact: true })).toHaveAttribute(
      "aria-current",
      "page",
    );
    expect(await running(page, "*")).toBe(0);
  });
});
