import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { ServiceStatusProvider } from "../components/status/ServiceStatusProvider";
import { jsonResponse, stubFetch } from "../test/http";
import StatusPage from "./StatusPage";

const HEALTH = { status: "ok", service: "cipherforge-api", version: "0.1.0" };
const READY = { status: "ready", checks: { database: "ok" } };

function renderPage() {
  return render(
    <ServiceStatusProvider>
      <StatusPage />
    </ServiceStatusProvider>,
  );
}

describe("StatusPage", () => {
  it("shows an operational system", async () => {
    stubFetch((url) => (url === "/health" ? jsonResponse(HEALTH) : jsonResponse(READY)));

    renderPage();

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

    renderPage();

    expect(await screen.findByText("Degraded")).toBeInTheDocument();
    expect(screen.getByText("Unavailable")).toBeInTheDocument();
    expect(screen.getByText("Up")).toBeInTheDocument();
  });

  it("shows the API as down with a readable message when it cannot be reached", async () => {
    stubFetch(() => Promise.reject(new TypeError("Failed to fetch")));

    renderPage();

    expect(await screen.findByText("Down")).toBeInTheDocument();
    expect(screen.getByText("Unreachable")).toBeInTheDocument();
    expect(screen.getAllByText("Could not reach the CipherForge API.")).toHaveLength(2);
  });

  it("checks again when Refresh is pressed", async () => {
    const fetchMock = stubFetch((url) => (url === "/health" ? jsonResponse(HEALTH) : jsonResponse(READY)));
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("Operational");
    expect(fetchMock).toHaveBeenCalledTimes(2);

    await user.click(screen.getByRole("button", { name: "Refresh" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(4));
    expect(await screen.findByRole("button", { name: "Refresh" })).toBeEnabled();
  });

  it("keeps the keyboard on Refresh while it checks, and ignores presses until the check is done", async () => {
    let finish: (response: Response) => void = () => {};
    let hold = false;
    const fetchMock = stubFetch((url) => {
      if (url === "/health") return jsonResponse(HEALTH);
      if (!hold) return jsonResponse(READY);
      return new Promise<Response>((resolve) => {
        finish = resolve;
      });
    });
    const user = userEvent.setup();
    renderPage();
    await screen.findByText("Operational");
    hold = true;

    const refresh = screen.getByRole("button", { name: "Refresh" });
    refresh.focus();
    await user.keyboard("{Enter}");

    const busy = await screen.findByRole("button", { name: "Checking…" });
    expect(busy).toBe(refresh);
    expect(busy).toHaveFocus();
    expect(busy).toHaveAttribute("aria-disabled", "true");
    await user.keyboard("{Enter}");
    expect(fetchMock).toHaveBeenCalledTimes(4);

    finish(jsonResponse(READY));

    const idle = await screen.findByRole("button", { name: "Refresh" });
    expect(idle).toHaveFocus();
    expect(idle).not.toHaveAttribute("aria-disabled");
  });
});
