import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ApiError } from "../services/apiClient";
import ErrorNotice from "./ErrorNotice";

function error(init: Partial<ConstructorParameters<typeof ApiError>[0]> = {}): ApiError {
  return new ApiError({ message: "The server said no.", status: 500, code: "http_error", ...init });
}

describe("ErrorNotice", () => {
  it("says how long to wait after a rate limit, and shows the server's message and reference", () => {
    render(
      <ErrorNotice
        error={error({
          status: 429,
          code: "rate_limited",
          message: "Too many investigations. Try again shortly.",
          retryAfterSeconds: 90,
          correlationId: "req-7",
        })}
      />,
    );

    const alert = screen.getByRole("alert");
    expect(alert).toHaveTextContent("Rate limit reached");
    expect(alert).toHaveTextContent("Too many investigations. Try again shortly.");
    expect(alert).toHaveTextContent("Try again in 2 minutes.");
    expect(alert).toHaveTextContent("Reference: req-7");
  });

  it("does not invent a wait time when the server gave none", () => {
    render(<ErrorNotice error={error({ status: 429, code: "rate_limited" })} />);

    expect(screen.getByRole("alert")).toHaveTextContent("Try again shortly.");
  });

  it.each([
    [{ status: 401, code: "unauthorized" }, "Not signed in"],
    [{ status: 403, code: "forbidden" }, "Access denied"],
    [{ status: 404, code: "not_found" }, "Not found"],
    [{ status: 422, code: "validation_error" }, "That request was not accepted"],
    [{ status: 503, code: "http_error" }, "The API reported an error"],
    [{ status: 418, code: "http_error" }, "The request failed"],
    [{ status: 0, code: "timeout" }, "The request timed out"],
    [{ status: 0, code: "network_error" }, "Could not reach the API"],
    [{ status: 0, code: "unexpected_error" }, "Something went wrong"],
  ])("explains %o as %s", (init, title) => {
    render(<ErrorNotice error={error(init)} />);

    expect(screen.getByRole("alert")).toHaveTextContent(title);
  });

  it("explains an unreadable reply by its code even though the HTTP status was 200", () => {
    render(<ErrorNotice error={error({ status: 200, code: "invalid_response" })} />);

    expect(screen.getByRole("alert")).toHaveTextContent("Unexpected response from the API");
  });

  it("offers a retry button only when there is something to retry", async () => {
    const onRetry = vi.fn();
    const user = userEvent.setup();
    const { rerender } = render(<ErrorNotice error={error()} />);
    expect(screen.queryByRole("button", { name: "Try again" })).not.toBeInTheDocument();

    rerender(<ErrorNotice error={error()} onRetry={onRetry} />);
    await user.click(screen.getByRole("button", { name: "Try again" }));

    expect(onRetry).toHaveBeenCalledTimes(1);
  });
});
