import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ApiError } from "../../services/apiClient";
import NetworkErrorNotice from "./NetworkErrorNotice";

function failure(status: number, code: string, extra: Partial<ConstructorParameters<typeof ApiError>[0]> = {}) {
  return new ApiError({ message: `The API said ${code}.`, status, code, ...extra });
}

describe("NetworkErrorNotice", () => {
  it("replaces a known failure with what happened and what to do, and keeps the reference", () => {
    render(<NetworkErrorNotice error={failure(409, "capture_already_running", { correlationId: "corr-77" })} />);

    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("A capture is already running");
    expect(alert).toHaveTextContent("Only one live capture can run at a time");
    expect(alert).toHaveTextContent("Reference: corr-77");
    expect(alert).not.toHaveTextContent("The API said");
  });

  it("marks a refusal the analyst can act on as a warning and a fault of the server as an error", () => {
    const { rerender } = render(<NetworkErrorNotice error={failure(409, "capture_already_running")} />);
    expect(screen.getByRole("alert")).toHaveTextContent("▲");

    rerender(<NetworkErrorNotice error={failure(503, "capture_failed")} />);
    expect(screen.getByRole("alert")).toHaveTextContent("✕");
  });

  it("names the upload limit in a too-large message only when it is known", () => {
    const { rerender } = render(<NetworkErrorNotice error={failure(413, "file_too_large")} context={{ maxUploadMb: 50 }} />);
    expect(screen.getByRole("alert")).toHaveTextContent("larger than the 50 MB upload limit");

    rerender(<NetworkErrorNotice error={failure(413, "file_too_large")} />);
    expect(screen.getByRole("alert")).toHaveTextContent("larger than the upload limit");
  });

  it("says how long to wait when the server asks for a pause", () => {
    render(<NetworkErrorNotice error={failure(429, "rate_limited", { retryAfterSeconds: 90 })} />);

    expect(screen.getByRole("alert")).toHaveTextContent("Try again in 2 minutes.");
  });

  it("falls back to the API's own message for a failure it has no words for", () => {
    render(<NetworkErrorNotice error={failure(500, "internal_error", { message: "The database is down." })} />);

    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("The API reported an error");
    expect(alert).toHaveTextContent("The database is down.");
  });

  it("offers Try again only when there is something to retry", async () => {
    const onRetry = vi.fn();
    const { rerender } = render(<NetworkErrorNotice error={failure(503, "capture_failed")} />);
    expect(screen.queryByRole("button", { name: "Try again" })).not.toBeInTheDocument();

    rerender(<NetworkErrorNotice error={failure(503, "capture_failed")} onRetry={onRetry} />);
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(onRetry).toHaveBeenCalledTimes(1);

    rerender(<NetworkErrorNotice error={failure(500, "internal_error")} onRetry={onRetry} />);
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(onRetry).toHaveBeenCalledTimes(2);
  });
});
