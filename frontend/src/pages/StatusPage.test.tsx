import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { jsonResponse, stubFetch } from "../test/http";
import StatusPage from "./StatusPage";

const HEALTH = { status: "ok", service: "cipherforge-api", version: "0.1.0" };

describe("StatusPage", () => {
  it("shows an operational system", async () => {
    stubFetch((url) =>
      url === "/health" ? jsonResponse(HEALTH) : jsonResponse({ status: "ready", checks: { database: "ok" } }),
    );

    render(<StatusPage />);

    expect(await screen.findByText("Operational")).toBeInTheDocument();
    expect(screen.getByText("cipherforge-api")).toBeInTheDocument();
    expect(screen.getByText("0.1.0")).toBeInTheDocument();
    expect(screen.getByText("Reachable")).toBeInTheDocument();
  });

  it("shows a degraded system when the database is unavailable", async () => {
    stubFetch((url) =>
      url === "/health"
        ? jsonResponse(HEALTH)
        : jsonResponse({ status: "not_ready", checks: { database: "unavailable" } }, { status: 503 }),
    );

    render(<StatusPage />);

    expect(await screen.findByText("Degraded")).toBeInTheDocument();
    expect(screen.getByText("Unavailable")).toBeInTheDocument();
    expect(screen.getByText("Up")).toBeInTheDocument();
  });

  it("shows the API as down with a readable message when it cannot be reached", async () => {
    stubFetch(() => Promise.reject(new TypeError("Failed to fetch")));

    render(<StatusPage />);

    expect(await screen.findByText("Down")).toBeInTheDocument();
    expect(screen.getByText("Unreachable")).toBeInTheDocument();
    expect(screen.getAllByText("Could not reach the CipherForge API.")).toHaveLength(2);
  });

  it("checks again when Refresh is pressed", async () => {
    const fetchMock = stubFetch((url) =>
      url === "/health" ? jsonResponse(HEALTH) : jsonResponse({ status: "ready", checks: { database: "ok" } }),
    );
    const user = userEvent.setup();
    render(<StatusPage />);
    await screen.findByText("Operational");
    expect(fetchMock).toHaveBeenCalledTimes(2);

    await user.click(screen.getByRole("button", { name: "Refresh" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(4));
    expect(await screen.findByRole("button", { name: "Refresh" })).toBeEnabled();
  });
});
