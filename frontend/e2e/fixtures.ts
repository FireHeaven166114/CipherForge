import { expect, test as base } from "@playwright/test";

import { type SeededIndicators, purgeIndicators, seedIndicators } from "./api";

/** Stores new indicators for the test; whatever is left of them is deleted when the test ends. */
export type Seed = (count: number) => Promise<SeededIndicators>;

/** What a test says it expects the browser to report, so everything else counts as a failure. */
export interface Guard {
  /** HTTP statuses the test provokes on purpose, such as a 404 for an unknown record. */
  expectStatus(...statuses: number[]): void;
  /** Console messages the test provokes on purpose. */
  expectConsole(pattern: RegExp): void;
  /** Requests the test cuts off on purpose, such as an API that goes away, matched by URL. */
  expectRequestFailure(pattern: RegExp): void;
  /** Content-Security-Policy violations are failures unless the test is about the policy itself. */
  expectCspViolations(): void;
  /** Violations seen so far, as `directive: blocked URL`. */
  readonly cspViolations: readonly string[];
}

interface CspReport {
  __cfReportCsp(detail: string): void;
}

/**
 * Every test runs under a guard: a console error or warning, an uncaught exception, a failed
 * request, an unexpected HTTP error status or a CSP violation fails it, even when the assertions
 * about the page itself pass.
 */
export const test = base.extend<{ guard: Guard; seed: Seed }>({
  seed: async ({ request }, use) => {
    const searches: string[] = [];
    await use(async (count) => {
      const seeded = await seedIndicators(request, count);
      searches.push(seeded.search);
      return seeded;
    });
    for (const search of searches) await purgeIndicators(request, search);
  },
  guard: [
    async ({ page }, use) => {
      const problems: string[] = [];
      const statuses = new Set<number>();
      const consolePatterns: RegExp[] = [];
      const failurePatterns: RegExp[] = [];
      const violations: string[] = [];
      let violationsExpected = false;

      await page.exposeFunction("__cfReportCsp", (detail: string) => {
        violations.push(detail);
      });
      await page.addInitScript(() => {
        document.addEventListener("securitypolicyviolation", (event) => {
          const report = window as unknown as CspReport;
          report.__cfReportCsp(
            `${event.violatedDirective}: ${event.blockedURI || "inline"} (${event.sourceFile}:${event.lineNumber})`,
          );
        });
      });

      page.on("console", (message) => {
        if (message.type() !== "error" && message.type() !== "warning") return;
        const text = message.text();
        // Chromium prints a console error for every non-2xx response; the status is judged below.
        if (text.startsWith("Failed to load resource:")) return;
        if (consolePatterns.some((pattern) => pattern.test(text))) return;
        problems.push(`console ${message.type()}: ${text}`);
      });
      page.on("pageerror", (error) => {
        problems.push(`uncaught error: ${error.message}`);
      });
      page.on("requestfailed", (request) => {
        const reason = request.failure()?.errorText ?? "unknown";
        // The app cancels a request it no longer needs, which the browser reports as aborted.
        if (reason === "net::ERR_ABORTED") return;
        if (failurePatterns.some((pattern) => pattern.test(request.url()))) return;
        problems.push(`request failed: ${request.method()} ${request.url()} (${reason})`);
      });
      page.on("response", (response) => {
        const status = response.status();
        if (status >= 400 && !statuses.has(status)) {
          problems.push(`HTTP ${status}: ${response.request().method()} ${response.url()}`);
        }
      });

      await use({
        expectStatus: (...expected) => {
          for (const status of expected) statuses.add(status);
        },
        expectConsole: (pattern) => {
          consolePatterns.push(pattern);
        },
        expectRequestFailure: (pattern) => {
          failurePatterns.push(pattern);
        },
        expectCspViolations: () => {
          violationsExpected = true;
        },
        cspViolations: violations,
      });

      expect(problems, "browser problems during the test").toEqual([]);
      if (!violationsExpected) expect(violations, "CSP violations during the test").toEqual([]);
    },
    { auto: true },
  ],
});

export { expect };
