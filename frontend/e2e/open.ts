import type { Page } from "@playwright/test";

import { expect } from "./fixtures";
import { panel } from "./pages";

/** Each opens a page and waits until it has drawn what a person would look at first. */

export async function openOverview(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.getByRole("region", { name: "Key figures" })).toBeVisible();
  await expect(page.getByText(/^Live · refreshed/)).toBeVisible();
}

export async function openInvestigate(page: Page): Promise<void> {
  await page.goto("/investigate");
  await expect(page.getByRole("heading", { level: 1, name: "Investigate an indicator" })).toBeVisible();
}

/** Types the value on the Investigate page and sends it. */
export async function investigate(page: Page, value: string): Promise<void> {
  await openInvestigate(page);
  await page.getByRole("textbox", { name: /^Indicator/ }).fill(value);
  await page.getByRole("button", { name: "Investigate", exact: true }).click();
}

export async function openList(page: Page, query = ""): Promise<void> {
  await page.goto(`/indicators${query}`);
  await expect(page.getByRole("table")).toBeVisible();
}

export async function openRecord(page: Page, id: string): Promise<void> {
  await page.goto(`/indicators/${id}`);
  await expect(panel(page, "CipherForge assessment")).toBeVisible();
}

export async function openStatus(page: Page): Promise<void> {
  await page.goto("/status");
  await expect(page.getByText("Operational", { exact: true })).toBeVisible();
}

export async function openNetwork(page: Page, query = ""): Promise<void> {
  await page.goto(`/network${query}`);
  await expect(page.getByRole("heading", { level: 1, name: "Network", exact: true })).toBeVisible();
  await expect(panel(page, "Live capture")).toBeVisible();
  await expect(page.getByText(/^Live · refreshed/)).toBeVisible();
}

export async function openFiles(page: Page): Promise<void> {
  await page.goto("/files");
  await expect(page.getByRole("heading", { level: 1, name: "Files", exact: true })).toBeVisible();
  await expect(panel(page, "Your files")).toBeVisible();
}
