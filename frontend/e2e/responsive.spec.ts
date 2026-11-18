import type { APIRequestContext, Page } from "@playwright/test";

import { firstIndicator, fresh } from "./api";
import { settle } from "./axe";
import { type Guard, type Seed, expect, test } from "./fixtures";
import { expectFits, expectOnScreen, frames, sidewaysOverflow } from "./layout";
import { investigate, openInvestigate, openList, openOverview, openRecord, openStatus } from "./open";
import { palette } from "./pages";
import { must } from "./text";

interface Screen {
  name: string;
  width: number;
  height: number;
  /** The navigation runs along the bottom edge, as on a phone, instead of down the left edge. */
  tabBar: boolean;
  /** How many key-figure tiles sit side by side. */
  tiles: number;
}

const SCREENS: readonly Screen[] = [
  { name: "desktop", width: 1440, height: 900, tabBar: false, tiles: 5 },
  { name: "common laptop", width: 1366, height: 768, tabBar: false, tiles: 5 },
  { name: "laptop", width: 1024, height: 768, tabBar: false, tiles: 2 },
  { name: "tablet", width: 768, height: 1024, tabBar: false, tiles: 2 },
  { name: "phone on its side", width: 844, height: 390, tabBar: false, tiles: 2 },
  // A 1280 px window at 200% browser zoom is 640 CSS px wide: what WCAG 1.4.4 (resize text) is about.
  { name: "desktop at 200% zoom", width: 640, height: 400, tabBar: true, tiles: 2 },
  { name: "phone", width: 390, height: 844, tabBar: true, tiles: 1 },
  // 320 px is what a 1280 px window shows at 400% zoom, the narrowest width WCAG asks pages to reflow to.
  { name: "small phone", width: 320, height: 568, tabBar: true, tiles: 1 },
];

// One lookup for the whole file: the same value is answered from the stored record after the first time.
const LOOKED_UP = fresh.domain();

interface Tools {
  page: Page;
  request: APIRequestContext;
  seed: Seed;
  guard: Guard;
}

const SELECT_ALL = "Select all indicators on this page";

/** Stores indicators for the scene, shows them in the list and ticks every one of them. */
async function openSeededAndTick(page: Page, seed: Seed, count: number): Promise<void> {
  const { search } = await seed(count);
  await openList(page, `?q=${search}`);
  await page.getByRole("checkbox", { name: SELECT_ALL }).check();
  await expect(page.getByRole("button", { name: `Delete selected (${count})`, exact: true })).toBeVisible();
}

const SCENES: Record<string, (tools: Tools) => Promise<void>> = {
  "the overview": ({ page }) => openOverview(page),
  "the overview with a details drawer": async ({ page }) => {
    await openOverview(page);
    await page.getByRole("list", { name: "Malware families" }).getByRole("button").first().click();
    await expect(page.getByRole("dialog")).toBeVisible();
  },
  "the command palette": async ({ page }) => {
    await openOverview(page);
    await page.keyboard.press("Control+k");
    await expect(palette(page).dialog).toBeVisible();
  },
  "the investigate page": ({ page }) => openInvestigate(page),
  "the investigate page with a result": async ({ page }) => {
    await investigate(page, LOOKED_UP);
    await expect(page.getByRole("link", { name: "Open the saved record" })).toBeVisible();
  },
  "the indicators list": ({ page }) => openList(page),
  "the indicators list with rows ticked": ({ page, seed }) => openSeededAndTick(page, seed, 3),
  "the confirmation to delete several indicators": async ({ page, seed }) => {
    await openSeededAndTick(page, seed, 7);
    await page.getByRole("button", { name: "Delete selected (7)", exact: true }).click();
    await expect(page.getByRole("dialog", { name: "Delete 7 indicators?", exact: true })).toBeVisible();
  },
  // The tallest the dialog gets: the list of values, the explanation and the notice of a failure.
  "the confirmation after a deletion failed": async ({ page, seed, guard }) => {
    guard.expectStatus(500);
    await page.route(/\/api\/v1\/intel\/indicators\/bulk-delete$/, (route) =>
      route.fulfill({
        status: 500,
        json: { error: { code: "internal_error", message: "The service is having a problem.", correlation_id: "resp-ref-500" } },
      }),
    );
    await openSeededAndTick(page, seed, 7);
    await page.getByRole("button", { name: "Delete selected (7)", exact: true }).click();
    const dialog = page.getByRole("dialog", { name: "Delete 7 indicators?", exact: true });
    await dialog.getByRole("button", { name: "Delete 7 indicators", exact: true }).click();
    await expect(dialog.getByRole("alert")).toContainText("Reference: resp-ref-500");
  },
  "a stored record": async ({ page, request }) => {
    await openRecord(page, (await firstIndicator(request, { sort: "risk" })).indicator_id);
  },
  "a stored record after it is deleted": async ({ page, seed }) => {
    const { items } = await seed(1);
    await openRecord(page, must(items[0], "an indicator").indicator_id);
    await page.getByRole("button", { name: "Delete indicator", exact: true }).click();
    await page
      .getByRole("dialog", { name: "Delete this indicator?", exact: true })
      .getByRole("button", { name: "Delete indicator", exact: true })
      .click();
    await expect(page.getByRole("heading", { level: 1, name: "Indicator deleted" })).toBeVisible();
  },
  "the system status": ({ page }) => openStatus(page),
};

interface Box {
  x: number;
  y: number;
  width: number;
  height: number;
}

function overlap(a: Box, b: Box): boolean {
  const tolerance = 0.5;
  return (
    a.x < b.x + b.width - tolerance &&
    b.x < a.x + a.width - tolerance &&
    a.y < b.y + b.height - tolerance &&
    b.y < a.y + a.height - tolerance
  );
}

/**
 * Presses a key over and over and reports the first control that the keyboard focus lands on while
 * something fixed on screen, such as the top bar or the tab bar, covers it (WCAG 2.4.11). Content
 * that merely overlaps a neighbour, like two dots on the map, is not the question here.
 */
async function hiddenWhileTabbing(page: Page, key: "Tab" | "Shift+Tab", presses: number): Promise<string | null> {
  for (let press = 1; press <= presses; press++) {
    await page.keyboard.press(key);
    const problem = await page.evaluate(async () => {
      await new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve())));
      const focused = document.activeElement;
      if (!focused || focused === document.body) return null;
      const describe = (element: Element): string => {
        const words = (element.getAttribute("aria-label") ?? element.textContent ?? "").trim().replace(/\s+/g, " ");
        return `<${element.tagName.toLowerCase()}> ${words.slice(0, 30)}`;
      };
      const stayingPut = (element: Element): Element | null => {
        for (let node: Element | null = element; node; node = node.parentElement) {
          const { position } = getComputedStyle(node);
          if (position === "fixed" || position === "sticky") return node;
        }
        return null;
      };
      const box = focused.getBoundingClientRect();
      const top = Math.max(box.top, 0);
      const bottom = Math.min(box.bottom, window.innerHeight);
      if (bottom <= top) return `${describe(focused)} is not on the screen`;
      const found = document.elementFromPoint(box.left + box.width / 2, (top + bottom) / 2);
      if (!found || focused.contains(found) || found.contains(focused)) return null;
      const cover = stayingPut(found);
      return cover ? `${describe(focused)} is hidden behind ${describe(cover)}` : null;
    });
    if (problem) return `after ${press} press(es) of ${key}: ${problem}`;
  }
  return null;
}

/**
 * How far down the visible content of the page body reaches (measured from the top of the page), the
 * room the layout keeps below it, and how far the window is scrolled right now.
 */
function bodyExtent(page: Page): Promise<{ bottom: number; padding: number; scrolled: number }> {
  return page.evaluate(() => {
    const main = document.querySelector("main");
    if (!main) throw new Error("The page has no main region.");
    let bottom = 0;
    for (const element of main.querySelectorAll("*")) {
      const holder = element.closest(".sr-only");
      if (holder && getComputedStyle(holder).clipPath !== "none") continue;
      const style = getComputedStyle(element);
      if (style.display === "none" || style.visibility === "hidden") continue;
      const box = element.getBoundingClientRect();
      if (box.height > 0) bottom = Math.max(bottom, box.bottom + window.scrollY);
    }
    return { bottom, padding: parseFloat(getComputedStyle(main).paddingBottom), scrolled: window.scrollY };
  });
}

for (const screen of SCREENS) {
  test.describe(`${screen.name}, ${screen.width} by ${screen.height}`, () => {
    test.use({
      viewport: { width: screen.width, height: screen.height },
      reducedMotion: "reduce",
      hasTouch: screen.tabBar,
    });

    for (const [name, open] of Object.entries(SCENES)) {
      test(`${name} fits the screen`, async ({ page, request, seed, guard }) => {
        await open({ page, request, seed, guard });
        const dialog = page.getByRole("dialog");
        if ((await dialog.count()) > 0) await expectOnScreen(dialog, screen);
        await expectFits(page, name);
      });
    }

    test("the navigation sits where this screen expects it", async ({ page }) => {
      await openOverview(page);
      const nav = page.getByRole("navigation", { name: "Primary" });
      const bar = must(await nav.boundingBox(), "the navigation box");
      const viewport = await page.evaluate(() => ({
        width: document.documentElement.clientWidth,
        height: window.innerHeight,
      }));

      expect(bar.x).toBeCloseTo(0, 0);
      if (screen.tabBar) {
        expect(bar.width).toBeCloseTo(viewport.width, 0);
        expect(bar.y + bar.height).toBeCloseTo(viewport.height, 0);
      } else {
        const header = must(await page.getByRole("banner").boundingBox(), "the top bar box");
        const body = must(await page.getByRole("main").boundingBox(), "the page body box");
        expect(bar.y).toBeGreaterThanOrEqual(header.y + header.height - 1);
        // The rail fills the left edge down to the bottom of the window, however short the page is.
        expect(bar.y + bar.height).toBeGreaterThanOrEqual(viewport.height - 0.5);
        expect(body.x).toBeGreaterThanOrEqual(bar.x + bar.width - 1);
      }

      const links = nav.getByRole("link");
      await expect(links).toHaveCount(4);
      for (const link of await links.all()) {
        const box = must(await link.boundingBox(), "a link box");
        const where = await link.innerText();
        expect(box.width, `width of ${where}`).toBeGreaterThanOrEqual(44);
        expect(box.height, `height of ${where}`).toBeGreaterThanOrEqual(44);
        expect(box.x, `left edge of ${where}`).toBeGreaterThanOrEqual(bar.x - 0.5);
        expect(box.x + box.width, `right edge of ${where}`).toBeLessThanOrEqual(bar.x + bar.width + 0.5);
        expect(box.y, `top edge of ${where}`).toBeGreaterThanOrEqual(bar.y - 0.5);
        expect(box.y + box.height, `bottom edge of ${where}`).toBeLessThanOrEqual(bar.y + bar.height + 0.5);
        expect(box.y + box.height, `bottom edge of ${where} against the window`).toBeLessThanOrEqual(
          viewport.height + 0.5,
        );
      }
    });

    test("every navigation label fits on one line inside its link", async ({ page }) => {
      await openOverview(page);
      const labels = await page
        .getByRole("navigation", { name: "Primary" })
        .getByRole("link")
        .evaluateAll((links) =>
          links.map((link) => {
            const box = link.getBoundingClientRect();
            const range = document.createRange();
            const tops = new Set<number>();
            let left = Infinity;
            let right = -Infinity;
            let text = "";
            const walker = document.createTreeWalker(link, NodeFilter.SHOW_TEXT);
            for (let node = walker.nextNode(); node; node = walker.nextNode()) {
              const parent = node.parentElement;
              // Only the words a person sees, not the ones clipped away for screen readers (sr-only).
              const holder = parent?.closest(".sr-only");
              if (!parent || (holder && getComputedStyle(holder).clipPath !== "none") || !parent.checkVisibility()) continue;
              range.selectNodeContents(node);
              for (const rect of range.getClientRects()) {
                tops.add(Math.round(rect.top));
                left = Math.min(left, rect.left);
                right = Math.max(right, rect.right);
              }
              text += node.textContent ?? "";
            }
            return { text: text.trim(), lines: tops.size, spaceLeft: left - box.left, spaceRight: box.right - right };
          }),
        );
      expect(labels).toHaveLength(4);
      for (const label of labels) {
        expect(label.text, "a visible label").not.toBe("");
        expect(label.lines, `lines used by ${label.text}`).toBe(1);
        expect(label.spaceLeft, `space left of ${label.text}`).toBeGreaterThanOrEqual(-0.5);
        expect(label.spaceRight, `space right of ${label.text}`).toBeGreaterThanOrEqual(-0.5);
      }
    });

    test("the top bar holds its controls without overlap", async ({ page }) => {
      await openOverview(page);
      const controls: { name: string; box: Box }[] = [];
      for (const control of await page.getByRole("banner").locator("a, button").all()) {
        if (!(await control.isVisible())) continue;
        const name = await control.evaluate((element) =>
          (element.getAttribute("aria-label") ?? element.textContent ?? "").trim().slice(0, 30),
        );
        controls.push({ name, box: must(await control.boundingBox(), `a box for ${name}`) });
      }
      expect(controls.length, "controls in the top bar").toBeGreaterThanOrEqual(3);
      const clashes = controls.flatMap((first, index) =>
        controls
          .slice(index + 1)
          .filter((second) => overlap(first.box, second.box))
          .map((second) => `${first.name} overlaps ${second.name}`),
      );
      expect(clashes).toEqual([]);
    });

    test(`the key figures flow into ${screen.tiles} ${screen.tiles === 1 ? "column" : "columns"}`, async ({ page }) => {
      await openOverview(page);
      const tiles = page.getByRole("region", { name: "Key figures" }).locator(":scope > ul > li");
      await expect(tiles).toHaveCount(5);
      const boxes = await Promise.all(
        (await tiles.all()).map(async (tile) => must(await tile.boundingBox(), "a tile box")),
      );
      expect(new Set(boxes.map((box) => Math.round(box.x))).size).toBe(screen.tiles);
    });

    test("the end of a long page is not hidden behind the navigation", async ({ page }) => {
      await openList(page);
      await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
      await frames(page);
      const { bottom, scrolled } = await bodyExtent(page);
      const limit = await page.evaluate(() => {
        const nav = document.querySelector("nav[aria-label='Primary']");
        return nav && getComputedStyle(nav).position === "fixed" ? nav.getBoundingClientRect().top : window.innerHeight;
      });
      expect(bottom, "bottom of the page content").toBeGreaterThan(0);
      expect(bottom - scrolled, "bottom of the page content against the top of the navigation").toBeLessThanOrEqual(
        limit + 0.5,
      );
    });

    test("the navigation stays in view while a long page scrolls", async ({ page }) => {
      await openList(page);
      await page.evaluate(() => window.scrollTo(0, document.documentElement.scrollHeight));
      await frames(page);
      const { scrolled, height } = await page.evaluate(() => ({ scrolled: window.scrollY, height: window.innerHeight }));
      expect(scrolled, "how far the list scrolled").toBeGreaterThan(100);

      const header = must(await page.getByRole("banner").boundingBox(), "the top bar box");
      const links = page.getByRole("navigation", { name: "Primary" }).getByRole("link");
      await expect(links).toHaveCount(4);
      for (const link of await links.all()) {
        const box = must(await link.boundingBox(), "a link box");
        const where = await link.innerText();
        expect(box.y, `top edge of ${where} against the top bar`).toBeGreaterThanOrEqual(header.y + header.height - 1);
        expect(box.y + box.height, `bottom edge of ${where} against the window`).toBeLessThanOrEqual(height + 0.5);
      }
    });

    test("a short page does not scroll for nothing", async ({ page }) => {
      await page.goto("/no-such-page");
      await expect(page.getByRole("heading", { level: 1, name: "Page not found" })).toBeVisible();
      await settle(page);
      await frames(page);
      const { bottom, padding } = await bodyExtent(page);
      const { content, height } = await page.evaluate(() => ({
        content: document.documentElement.scrollHeight,
        height: window.innerHeight,
      }));
      // A window only 390 px tall may be shorter than the content itself. Then the page scrolls, but
      // only as far as that content and the room the layout keeps below it.
      expect(content, "height of the page against the window or its own content").toBeLessThanOrEqual(
        Math.max(height, bottom + padding) + 1,
      );
    });

    test("keyboard focus is never hidden behind the top bar or the tab bar", async ({ page }) => {
      for (const open of [() => openList(page), () => openOverview(page)]) {
        await open();
        expect(await hiddenWhileTabbing(page, "Tab", 60), "tabbing forwards").toBeNull();
        await open();
        expect(await hiddenWhileTabbing(page, "Shift+Tab", 60), "tabbing backwards").toBeNull();
      }
    });
  });
}

test.describe("text enlarged to 200%", () => {
  // Like "zoom text only" in a browser: the window stays 1280 px wide while the type doubles in size.
  test.use({ viewport: { width: 1280, height: 800 }, reducedMotion: "reduce" });

  for (const [name, open] of Object.entries(SCENES)) {
    test(`${name} still fits`, async ({ page, request, seed, guard }) => {
      await open({ page, request, seed, guard });
      await page.evaluate(() => {
        const sheet = new CSSStyleSheet();
        sheet.replaceSync("html { font-size: 200% !important; }");
        document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
      });
      await settle(page);
      await frames(page);
      expect(await sidewaysOverflow(page), `sticks out sideways: ${name}`).toEqual([]);
    });
  }
});
