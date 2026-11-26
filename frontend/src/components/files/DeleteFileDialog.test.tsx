import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { describe, expect, it, vi } from "vitest";

import { ApiError } from "../../services/apiClient";
import DeleteFileDialog from "./DeleteFileDialog";

function renderDialog(props: Partial<ComponentProps<typeof DeleteFileDialog>> = {}) {
  const onConfirm = vi.fn<() => void>();
  const onCancel = vi.fn<() => void>();
  render(
    <DeleteFileDialog
      file={{ name: "report.pdf", active_share_count: 0 }}
      busy={false}
      error={null}
      onConfirm={onConfirm}
      onCancel={onCancel}
      {...props}
    />,
  );
  return { onConfirm, onCancel };
}

const dialog = () => screen.getByRole("dialog", { name: "Delete this file?" });

describe("DeleteFileDialog", () => {
  it("stays closed while there is no file to delete", () => {
    renderDialog({ file: null });

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("names the file as plain text, however odd the name is", () => {
    const hostile = "<img src=x onerror=alert(1)>.txt";
    renderDialog({ file: { name: hostile, active_share_count: 0 } });

    expect(within(dialog()).getByText(hostile)).toBeInTheDocument();
    expect(dialog().querySelector("img")).toBeNull();
  });

  it.each([
    { active: 0, expected: "Every share link made for it stops working immediately. It cannot be undone." },
    { active: 1, expected: "stops working immediately, including 1 active link. It cannot be undone." },
    { active: 3, expected: "stops working immediately, including 3 active links. It cannot be undone." },
  ])("counts the active links only when there are some ($active)", ({ active, expected }) => {
    renderDialog({ file: { name: "report.pdf", active_share_count: active } });

    expect(dialog()).toHaveTextContent(expected);
  });

  it("starts on Cancel, so a stray Enter does not delete anything, and answers Cancel, Escape and the button", async () => {
    const user = userEvent.setup();
    const { onConfirm, onCancel } = renderDialog();
    expect(within(dialog()).getByRole("button", { name: "Cancel" })).toHaveFocus();

    await user.keyboard("{Escape}");
    await user.click(within(dialog()).getByRole("button", { name: "Cancel" }));

    expect(onCancel).toHaveBeenCalledTimes(2);
    expect(onConfirm).not.toHaveBeenCalled();

    await user.click(within(dialog()).getByRole("button", { name: "Delete file" }));

    expect(onConfirm).toHaveBeenCalledOnce();
  });

  it("answers nothing while the delete is in progress, and says it is working", async () => {
    const user = userEvent.setup();
    const { onConfirm, onCancel } = renderDialog({ busy: true });

    const working = within(dialog()).getByRole("button", { name: "Deleting…" });
    expect(working).toHaveAttribute("aria-disabled", "true");
    expect(within(dialog()).getByRole("button", { name: "Cancel" })).toHaveAttribute("aria-disabled", "true");

    await user.click(working);
    await user.click(within(dialog()).getByRole("button", { name: "Cancel" }));
    await user.keyboard("{Escape}");

    expect(onConfirm).not.toHaveBeenCalled();
    expect(onCancel).not.toHaveBeenCalled();
  });

  it("says why a delete failed, in words for the code, with the reference", () => {
    const error = new ApiError({
      message: "No such file.",
      status: 404,
      code: "file_not_found",
      correlationId: "req-42",
    });
    renderDialog({ error });

    const alert = within(dialog()).getByRole("alert");
    expect(alert).toHaveTextContent("The file could not be deleted");
    expect(alert).toHaveTextContent("This file no longer exists. It may have been deleted.");
    expect(alert).toHaveTextContent("Reference: req-42");
    expect(within(dialog()).getByRole("button", { name: "Delete file" })).not.toHaveAttribute("aria-disabled");
  });
});
