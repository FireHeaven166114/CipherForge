import { act, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { useServiceStatus } from "../../hooks/useServiceStatus";
import { jsonResponse, stubFetch } from "../../test/http";
import { ServiceStatusProvider } from "./ServiceStatusProvider";

const HEALTH = { status: "ok", service: "cipherforge-api", version: "0.1.0" };
const READY = { status: "ready", checks: { database: "ok" } };

function Reading({ name }: { name: string }) {
  const { overall } = useServiceStatus();
  return <p>{`${name} sees ${overall}`}</p>;
}

function serveHealthy() {
  return stubFetch((url) => (url === "/health" ? jsonResponse(HEALTH) : jsonResponse(READY)));
}

describe("ServiceStatusProvider", () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it("makes one check for everything that reads it, and they all see the same result", async () => {
    const fetchMock = serveHealthy();

    render(
      <ServiceStatusProvider>
        <Reading name="top bar" />
        <Reading name="page" />
      </ServiceStatusProvider>,
    );

    expect(await screen.findByText("top bar sees operational")).toBeInTheDocument();
    expect(screen.getByText("page sees operational")).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("checks again every 30 seconds, and not sooner", async () => {
    vi.useFakeTimers();
    const fetchMock = serveHealthy();
    render(
      <ServiceStatusProvider>
        <Reading name="page" />
      </ServiceStatusProvider>,
    );
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(29_999);
    });
    expect(fetchMock).toHaveBeenCalledTimes(2);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1);
    });
    expect(fetchMock).toHaveBeenCalledTimes(4);
  });
});
