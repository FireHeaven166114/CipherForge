import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { SHARE_ID, makeShare } from "../../test/filesFixtures";
import type { Share, ShareStatus } from "../../types/files";
import ShareList from "./ShareList";

function renderList(shares: Share[]) {
  const onRevoke = vi.fn<(share: Share) => void>();
  render(<ShareList shares={shares} onRevoke={onRevoke} />);
  return { onRevoke };
}

/** The row of a link, found by the button that revokes it. */
function rowOf(shortId: string): HTMLElement {
  const row = screen.getByRole("button", { name: `Revoke link ${shortId}` }).closest("tr");
  if (row === null) throw new Error(`No table row holds the button for link ${shortId}.`);
  return row;
}

const SHORT = SHARE_ID.slice(0, 8);

describe("ShareList", () => {
  const STATES: { status: ShareStatus; label: string; revocable: boolean }[] = [
    { status: "active", label: "Active", revocable: true },
    { status: "expired", label: "Expired", revocable: false },
    { status: "revoked", label: "Revoked", revocable: false },
    { status: "exhausted", label: "Limit reached", revocable: false },
  ];

  it.each(STATES)(
    "names a $status link in words, and offers to revoke it only if it still works",
    ({ status, label, revocable }) => {
      renderList([makeShare({ status })]);
      const row = rowOf(SHORT);

      expect(within(row).getByText(label)).toBeInTheDocument();
      expect(within(row).getByRole("button").matches(":disabled")).toBe(!revocable);
    },
  );

  it("lays out a link's times in IST, its downloads and its password", () => {
    renderList([
      makeShare({
        download_count: 1,
        max_downloads: 3,
        downloads_remaining: 2,
        last_downloaded_at: "2026-05-20T10:00:00Z",
        revoked_at: "2026-05-20T11:00:00Z",
        status: "revoked",
        password_protected: true,
      }),
    ]);
    const row = rowOf(SHORT);

    expect(within(row).getByText("20-05-2026 02:00:00 PM IST")).toBeInTheDocument();
    expect(within(row).getByText("21-05-2026 02:00:00 PM IST")).toBeInTheDocument();
    expect(within(row).getByText("20-05-2026 03:30:00 PM IST")).toBeInTheDocument();
    expect(within(row).getByText("20-05-2026 04:30:00 PM IST")).toBeInTheDocument();
    expect(within(row).getByText("1 / 3")).toBeInTheDocument();
    expect(within(row).getByText("2 downloads left")).toBeInTheDocument();
    expect(within(row).getByText("Password")).toBeInTheDocument();
  });

  it("says so when a link was never downloaded or revoked, and has no password", () => {
    renderList([makeShare()]);
    const row = rowOf(SHORT);

    expect(within(row).getByText("Never")).toBeInTheDocument();
    expect(within(row).getByText("Not revoked")).toBeInTheDocument();
    expect(within(row).getByText("0 / 3")).toBeInTheDocument();
    expect(within(row).getByText("3 downloads left")).toBeInTheDocument();
    expect(within(row).queryByText("Password")).not.toBeInTheDocument();
  });

  it("hands over the link whose button was pressed, and nothing for one that no longer works", async () => {
    const user = userEvent.setup();
    const working = makeShare({ id: "11111111-aaaa-4bbb-8ccc-000000000001" });
    const expired = makeShare({ id: "22222222-aaaa-4bbb-8ccc-000000000002", status: "expired" });
    const { onRevoke } = renderList([working, expired]);

    await user.click(within(rowOf("22222222")).getByRole("button"));
    expect(onRevoke).not.toHaveBeenCalled();

    await user.click(within(rowOf("11111111")).getByRole("button"));
    expect(onRevoke).toHaveBeenCalledExactlyOnceWith(working);
  });
});
