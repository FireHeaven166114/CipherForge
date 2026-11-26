import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { describe, expect, it, vi } from "vitest";

import { ApiError } from "../../services/apiClient";
import { SHARE_ID } from "../../test/filesFixtures";
import RevokeShareDialog from "./RevokeShareDialog";

const SHARE = { id: SHARE_ID, download_count: 2, max_downloads: 5, password_protected: false };

function renderDialog(props: Partial<ComponentProps<typeof RevokeShareDialog>> = {}) {
  const onConfirm = vi.fn<() => void>();
  const onCancel = vi.fn<() => void>();
  render(<RevokeShareDialog share={SHARE} busy={false} error={null} onConfirm={onConfirm} onCancel={onCancel} {...props} />);
  return { onConfirm, onCancel };
}

const dialog = () => screen.getByRole("dialog", { name: "Revoke this link?" });

describe("RevokeShareDialog", () => {
  it("stays closed while there is no link to revoke", () => {
    renderDialog({ share: null });

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it.each([
    { password_protected: false, expected: "Link c3d4e5f6: 2 of 5 downloads used." },
    { password_protected: true, expected: "Link c3d4e5f6, protected by a password: 2 of 5 downloads used." },
  ])("describes the link, password or none ($password_protected)", ({ password_protected, expected }) => {
    renderDialog({ share: { ...SHARE, password_protected } });

    expect(dialog()).toHaveTextContent(expected);
    expect(dialog()).toHaveTextContent("receives nothing. The file stays stored, and you can make another link.");
  });

  it("starts on Cancel, so a stray Enter does not revoke anything, and answers Cancel, Escape and the button", async () => {
    const user = userEvent.setup();
    const { onConfirm, onCancel } = renderDialog();
    expect(within(dialog()).getByRole("button", { name: "Cancel" })).toHaveFocus();

    await user.keyboard("{Escape}");
    await user.click(within(dialog()).getByRole("button", { name: "Cancel" }));

    expect(onCancel).toHaveBeenCalledTimes(2);
    expect(onConfirm).not.toHaveBeenCalled();

    await user.click(within(dialog()).getByRole("button", { name: "Revoke link" }));

    expect(onConfirm).toHaveBeenCalledOnce();
  });

  it("answers nothing while the revoke is in progress, and says it is working", async () => {
    const user = userEvent.setup();
    const { onConfirm, onCancel } = renderDialog({ busy: true });

    const working = within(dialog()).getByRole("button", { name: "Revoking…" });
    expect(working).toHaveAttribute("aria-disabled", "true");
    expect(within(dialog()).getByRole("button", { name: "Cancel" })).toHaveAttribute("aria-disabled", "true");

    await user.click(working);
    await user.click(within(dialog()).getByRole("button", { name: "Cancel" }));
    await user.keyboard("{Escape}");

    expect(onConfirm).not.toHaveBeenCalled();
    expect(onCancel).not.toHaveBeenCalled();
  });

  it("says why a revoke failed, in words for the code, with the reference", () => {
    const error = new ApiError({
      message: "No such link.",
      status: 404,
      code: "share_not_found",
      correlationId: "req-43",
    });
    renderDialog({ error });

    const alert = within(dialog()).getByRole("alert");
    expect(alert).toHaveTextContent("The link could not be revoked");
    expect(alert).toHaveTextContent("This link no longer exists.");
    expect(alert).toHaveTextContent("Reference: req-43");
    expect(within(dialog()).getByRole("button", { name: "Revoke link" })).not.toHaveAttribute("aria-disabled");
  });
});
