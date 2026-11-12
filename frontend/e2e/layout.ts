import AxeBuilder from "@axe-core/playwright";
import type { Locator, Page } from "@playwright/test";

import { settle, summarise } from "./axe";
import { expect } from "./fixtures";
import { must } from "./text";

/** Lets layout and every chart that measures its box catch up with a change. */
export function frames(page: Page): Promise<void> {
  return page.evaluate(
    () => new Promise<void>((resolve) => requestAnimationFrame(() => requestAnimationFrame(() => resolve()))),
  );
}

/**
 * What sticks out of the window sideways: the page itself, every element that is not inside a box
 * that scrolls or clips (a wide table keeps its own scroll bar, and that is fine), and every run of
 * text that is not. The page is measured first, so a culprit that is hard to see is still named.
 */
export function sidewaysOverflow(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const root = document.documentElement;
    const width = root.clientWidth;
    const found: string[] = [];
    if (root.scrollWidth > width) {
      found.push(`the page scrolls sideways: ${root.scrollWidth}px of content in a ${width}px window`);
    }

    const describe = (element: Element): string => {
      const words = (element.getAttribute("aria-label") ?? element.textContent ?? "").trim().replace(/\s+/g, " ");
      return `<${element.tagName.toLowerCase()} class="${(element.getAttribute("class") ?? "").slice(0, 50)}"> ${words.slice(0, 30)}`;
    };
    // A box that scrolls or clips keeps what is inside it, except for what is positioned absolutely:
    // only its containing block, and the boxes above that, hold it. This is how a hidden description
    // placed after a very long label ends up thousands of pixels to the right of a box that clips.
    const insideClippingBox = (start: Element, startIsBox = false): boolean => {
      let position = startIsBox ? "static" : getComputedStyle(start).position;
      for (let box = startIsBox ? start : start.parentElement; box && box !== document.body; box = box.parentElement) {
        if (position === "fixed") return false;
        const style = getComputedStyle(box);
        const holdsPositioned = style.position !== "static" || style.transform !== "none";
        if (position === "absolute" && !holdsPositioned) continue;
        if (style.overflowX !== "visible") return true;
        position = style.position;
      }
      return false;
    };
    // Text for screen readers is clipped away on purpose (sr-only). Wide screens turn some of it back
    // into visible text (not-sr-only), so the clipping is what gets checked, not the class name.
    const parkedIn = (element: Element): Element | null => {
      const holder = element.closest(".sr-only");
      return holder !== null && getComputedStyle(holder).clipPath !== "none" ? holder : null;
    };
    // A hidden box sits 1px to the left of where it would be (that is how sr-only works), so only the
    // right edge says whether it widens the page.
    const outside = (box: DOMRect, hidden = false): boolean => box.right > width + 0.5 || (!hidden && box.left < -0.5);

    for (const element of document.body.querySelectorAll("*")) {
      // What is inside a hidden box is hidden. The box itself is checked: it is 1px wide, but where it sits can still widen the page.
      const parked = parkedIn(element);
      if (parked !== null && parked !== element) continue;
      const style = getComputedStyle(element);
      if (style.display === "none" || style.visibility === "hidden") continue;
      const box = element.getBoundingClientRect();
      if (box.width === 0 && box.height === 0) continue;
      if (outside(box, parked === element) && !insideClippingBox(element)) {
        found.push(`${describe(element)} spans ${Math.round(box.left)} to ${Math.round(box.right)}px in a ${width}px window`);
      }
    }

    // A line of text can run on past the edge of a box that is itself inside the window.
    const range = document.createRange();
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let node = walker.nextNode(); node !== null; node = walker.nextNode()) {
      const holder = node.parentElement;
      if (holder === null || (node.textContent ?? "").trim() === "" || parkedIn(holder) !== null) continue;
      if (getComputedStyle(holder).visibility === "hidden") continue;
      range.selectNodeContents(node);
      const text = range.getBoundingClientRect();
      if (text.width === 0 && text.height === 0) continue;
      if (outside(text) && !insideClippingBox(holder, true)) {
        found.push(`text in ${describe(holder)} runs from ${Math.round(text.left)} to ${Math.round(text.right)}px in a ${width}px window`);
      }
    }
    return [...new Set(found)].slice(0, 12);
  });
}

/**
 * Boxes that scroll sideways because their content is wider than they are, other than the ones
 * allowed by name. A wide table may do that on a narrow screen; a drawer, a dialog or a panel full
 * of text should wrap instead. A box is named by its aria-label or, for a table, its caption.
 */
export function sidewaysScrollers(page: Page, allowed: readonly string[] = []): Promise<string[]> {
  return page.evaluate((allowedNames) => {
    const found: string[] = [];
    for (const element of document.body.querySelectorAll("*")) {
      const style = getComputedStyle(element);
      if (style.overflowX !== "auto" && style.overflowX !== "scroll") continue;
      if (style.display === "none" || style.visibility === "hidden") continue;
      if (element.scrollWidth <= element.clientWidth + 1) continue;
      const name = (element.getAttribute("aria-label") ?? element.querySelector("caption")?.textContent ?? "").trim();
      if (allowedNames.some((allowedName) => name.startsWith(allowedName))) continue;
      const words = (name || element.textContent || "").trim().replace(/\s+/g, " ");
      found.push(
        `<${element.tagName.toLowerCase()} class="${(element.getAttribute("class") ?? "").slice(0, 50)}"> ${words.slice(0, 30)}` +
          ` holds ${element.scrollWidth}px in ${element.clientWidth}px`,
      );
    }
    return found.slice(0, 12);
  }, allowed);
}

/**
 * Text that does not stay where it belongs. Either a box that clips cuts it off without an ellipsis
 * to say so, or it spills out of the box it is drawn in: a HUD panel, or anything with a border all
 * the way round, such as a chip, a button or a figure in a drawer. A box that scrolls, or ends its
 * text with an ellipsis, is not a problem.
 */
export function textOutOfPlace(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const found: string[] = [];
    const range = document.createRange();
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const TOLERANCE = 1.5;

    const hidden = (start: Element): boolean => {
      for (let box: Element | null = start; box !== null; box = box.parentElement) {
        const style = getComputedStyle(box);
        if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") return true;
        if (box.matches(".sr-only") && style.clipPath !== "none") return true;
      }
      return false;
    };
    const framed = (box: Element, style: CSSStyleDeclaration): boolean =>
      box.classList.contains("hud-panel") ||
      [style.borderTopWidth, style.borderRightWidth, style.borderBottomWidth, style.borderLeftWidth].every(
        (width) => parseFloat(width) > 0,
      );

    for (let node = walker.nextNode(); node !== null; node = walker.nextNode()) {
      const words = (node.textContent ?? "").trim().replace(/\s+/g, " ");
      const holder = node.parentElement;
      if (words === "" || holder === null || hidden(holder)) continue;
      range.selectNodeContents(node);
      const text = range.getBoundingClientRect();
      if (text.width === 0 && text.height === 0) continue;

      for (let box: Element | null = holder; box !== null && box !== document.body; box = box.parentElement) {
        const style = getComputedStyle(box);
        const frame = box.getBoundingClientRect();
        const pokesOut = text.right > frame.right + TOLERANCE || text.left < frame.left - TOLERANCE;
        if (style.overflowX === "auto" || style.overflowX === "scroll") break;
        if (style.overflowX !== "visible") {
          if (pokesOut && style.textOverflow !== "ellipsis") {
            found.push(`cut off by a <${box.tagName.toLowerCase()} class="${(box.getAttribute("class") ?? "").slice(0, 40)}">: ${words.slice(0, 40)}`);
          }
          break;
        }
        if (framed(box, style) && pokesOut) {
          found.push(`spills out of its ${box.classList.contains("hud-panel") ? "panel" : "box"} <${box.tagName.toLowerCase()} class="${(box.getAttribute("class") ?? "").slice(0, 40)}">: ${words.slice(0, 40)}`);
          break;
        }
        if (box.classList.contains("hud-panel")) break;
      }
    }
    return [...new Set(found)].slice(0, 12);
  });
}

/** Passes when no text is cut off without an ellipsis, or spills out of the box it is drawn in. */
export async function expectTextInPlace(page: Page, what: string): Promise<void> {
  await settle(page);
  await frames(page);
  expect(await textOutOfPlace(page), `text that is cut off or spills out of its box: ${what}`).toEqual([]);
}

/**
 * Passes when nothing sticks out of the window sideways and every control is big enough and
 * reachable by keyboard, once every animation has finished.
 */
export async function expectFits(page: Page, what: string): Promise<void> {
  await settle(page);
  await frames(page);
  expect(await sidewaysOverflow(page), `sticks out sideways: ${what}`).toEqual([]);
  // Measured from the top of the page: a control that happens to sit under the sticky top bar at some
  // other scroll position is only covered for the moment, and the size of the control is the question.
  await page.evaluate(() => window.scrollTo(0, 0));
  const { violations } = await new AxeBuilder({ page })
    .withRules(["target-size", "scrollable-region-focusable"])
    .analyze();
  expect(violations.map(summarise), `controls that are too small or cannot be reached: ${what}`).toEqual([]);
}

/** A dialog may scroll inside itself, but it must never run off the screen. */
export async function expectOnScreen(dialog: Locator, screen: { width: number; height: number }): Promise<void> {
  const box = must(await dialog.boundingBox(), "a box for the dialog");
  expect(box.x, "left edge of the dialog").toBeGreaterThanOrEqual(-0.5);
  expect(box.y, "top edge of the dialog").toBeGreaterThanOrEqual(-0.5);
  expect(box.x + box.width, "right edge of the dialog").toBeLessThanOrEqual(screen.width + 0.5);
  expect(box.y + box.height, "bottom edge of the dialog").toBeLessThanOrEqual(screen.height + 0.5);
}
