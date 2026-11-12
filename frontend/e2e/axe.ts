import type AxeBuilder from "@axe-core/playwright";
import type { Page } from "@playwright/test";

export type Violation = Awaited<ReturnType<AxeBuilder["analyze"]>>["violations"][number];

/** One axe finding as text a failing test can print: the rule, then the first few elements. */
export function summarise(violation: Violation): string {
  const where = violation.nodes
    .slice(0, 3)
    .map(
      (node) =>
        `    ${node.target.join(" > ")}\n      ${node.html.slice(0, 200)}\n      ${(node.failureSummary ?? "").replace(/\s+/g, " ")}`,
    )
    .join("\n");
  return `${violation.id} [${violation.impact ?? "?"}] ${violation.help} (${violation.nodes.length} element(s))\n${where}`;
}

/** Waits for every animation that ends, so a half-faded element is not measured. */
export async function settle(page: Page): Promise<void> {
  await page.evaluate(async () => {
    const finite = document
      .getAnimations()
      .filter((animation) => animation.effect?.getComputedTiming().iterations !== Infinity);
    await Promise.allSettled(finite.map((animation) => animation.finished));
  });
}
