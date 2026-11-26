import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ApiError } from "../../services/apiClient";
import { makeSession } from "../../test/networkFixtures";
import DeleteSessionDialog from "./DeleteSessionDialog";

function setup(overrides: Partial<React.ComponentProps<typeof DeleteSessionDialog>> = {}) {
  const props = {
    target: makeSession({ packets_total: 1234, flows_total: 56, alerts_total: 7 }),
    busy: false,
    error: null,
    onConfirm: vi.fn(),
    onCancel: vi.fn(),
    ...overrides,
  };
  render(<DeleteSessionDialog {...props} />);
  return props;
}

describe("DeleteSessionDialog", () => {
  it("renders nothing without a session to delete", () => {
    setup({ target: null });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("names the session, says what goes with it and puts focus on Cancel", () => {
    setup();

    const dialog = screen.getByRole("dialog", { name: "Delete this session?" });
    expect(within(dialog).getByText("sample.pcap")).toBeInTheDocument();
    expect(within(dialog).getByText("20-05-2026 02:00:00 PM IST")).toBeInTheDocument();
    expect(within(dialog).getByText(/1,234 packets, 56 flows,\s+7 alerts/)).toBeInTheDocument();
    expect(within(dialog).getByText(/permanently removes the session with its stored flows/)).toBeInTheDocument();
    expect(within(dialog).getByText(/audit log is kept as it is/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Cancel" })).toHaveFocus();
  });

  it("names a live capture by its interface", () => {
    setup({ target: makeSession({ source_kind: "live", interface: "eth0", source_label: null }) });
    expect(screen.getByText("Live capture:")).toBeInTheDocument();
    expect(screen.getByText("eth0")).toBeInTheDocument();
  });

  it("confirms and cancels through its buttons, and cancels on Escape", async () => {
    const user = userEvent.setup();
    const { onConfirm, onCancel } = setup();

    await user.click(screen.getByRole("button", { name: "Delete session" }));
    expect(onConfirm).toHaveBeenCalledTimes(1);

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await user.keyboard("{Escape}");
    expect(onCancel).toHaveBeenCalledTimes(2);
  });

  it("ignores every way out while the deletion is under way", async () => {
    const user = userEvent.setup();
    const { onConfirm, onCancel } = setup({ busy: true });

    const confirm = screen.getByRole("button", { name: "Deleting…" });
    expect(confirm).toHaveAttribute("aria-disabled", "true");
    await user.click(confirm);
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await user.keyboard("{Escape}");

    expect(onConfirm).not.toHaveBeenCalled();
    expect(onCancel).not.toHaveBeenCalled();
  });

  it("stays open with a calm reason when the API refuses", () => {
    const error = new ApiError({ message: "Conflict.", status: 409, code: "session_running" });
    setup({ error });

    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("Session still running");
    expect(alert).toHaveTextContent("Stop the capture, or wait for the analysis to finish");
    expect(screen.getByRole("button", { name: "Delete session" })).toBeInTheDocument();
  });
});
