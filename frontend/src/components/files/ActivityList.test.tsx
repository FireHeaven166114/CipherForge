import { render, screen, within } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SHARE_ID, makeActivityItem } from "../../test/filesFixtures";
import type { ActivityItem } from "../../types/files";
import ActivityList from "./ActivityList";

function renderList(items: ActivityItem[]) {
  render(<ActivityList items={items} />);
  return screen.getByRole("table", { name: "Activity for this file, newest first" });
}

/** The rows below the header, in the order they are shown. */
function bodyRows(table: HTMLElement): HTMLElement[] {
  return within(table).getAllByRole("row").slice(1);
}

describe("ActivityList", () => {
  it("lists what happened in the order given, with IST times and a word for each result", () => {
    const table = renderList([
      makeActivityItem({
        timestamp: "2026-05-20T10:00:00Z",
        action: "SHARE_DOWNLOAD_REJECTED",
        result: "rejected",
        share_id: SHARE_ID,
        reason: "expired",
      }),
      makeActivityItem({ timestamp: "2026-05-20T08:30:00Z", action: "FILE_CREATE", result: "success" }),
      makeActivityItem({ action: "FILE_INTEGRITY_FAILED", result: "failed", reason: "authentication_failed" }),
    ]);
    const [refused, uploaded, integrity] = bodyRows(table);
    if (refused === undefined || uploaded === undefined || integrity === undefined) {
      throw new Error("Expected three rows.");
    }

    expect(within(refused).getByText("20-05-2026 03:30:00 PM IST")).toBeInTheDocument();
    expect(within(refused).getByText("Download refused")).toBeInTheDocument();
    expect(within(refused).getByText("Rejected")).toBeInTheDocument();
    expect(within(refused).getByText(SHARE_ID.slice(0, 8))).toBeInTheDocument();
    expect(within(refused).getByText("The link had expired")).toBeInTheDocument();

    expect(within(uploaded).getByText("20-05-2026 02:00:00 PM IST")).toBeInTheDocument();
    expect(within(uploaded).getByText("File uploaded")).toBeInTheDocument();
    expect(within(uploaded).getByText("Success")).toBeInTheDocument();

    expect(within(integrity).getByText("Integrity check failed")).toBeInTheDocument();
    expect(within(integrity).getByText("Failed")).toBeInTheDocument();
    expect(within(integrity).getByText("The encrypted data failed its authenticity check")).toBeInTheDocument();
  });

  it("marks a missing link or reason with a dash that a screen reader reads as words", () => {
    const table = renderList([makeActivityItem()]);
    const [row] = bodyRows(table);
    if (row === undefined) throw new Error("Expected a row.");

    expect(within(row).getByText("No link")).toBeInTheDocument();
    expect(within(row).getByText("None")).toBeInTheDocument();
    expect(within(row).getAllByText("—")).toHaveLength(2);
  });

  it("shows words it does not know as plain text, never as markup", () => {
    const table = renderList([
      makeActivityItem({
        action: "<img src=x onerror=alert(1)>",
        result: "<b>odd</b>",
        reason: "<script>alert(1)</script>",
      }),
    ]);

    expect(within(table).getByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
    expect(within(table).getByText("<b>odd</b>")).toBeInTheDocument();
    expect(within(table).getByText("<script>alert(1)</script>")).toBeInTheDocument();
    expect(table.querySelector("img, b, script")).toBeNull();
  });

  it("says Unknown for a result that is empty", () => {
    const table = renderList([makeActivityItem({ result: "" })]);

    expect(within(table).getByText("Unknown")).toBeInTheDocument();
  });
});
