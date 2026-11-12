import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ReactNode } from "react";
import { useNavigate } from "react-router";
import { describe, expect, it } from "vitest";

import {
  INDICATOR_ID,
  makeIndicator,
  makeInvestigation,
  makeNotAssessed,
  makeScore,
} from "../test/fixtures";
import { jsonResponse, stubFetch } from "../test/http";
import { renderRoute } from "../test/router";
import IndicatorDetailPage from "./IndicatorDetailPage";

const OTHER_ID = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";

/** The same indicator after a re-check lowered its score, so the two results can be told apart. */
function recheckedInvestigation() {
  return makeInvestigation({
    indicator: makeIndicator({ risk_score: 30, classification: "low", confidence: 50 }),
    score: makeScore({ score: 30, classification: "low", confidence: 50 }),
  });
}

function error(status: number, code: string, message: string, headers: Record<string, string> = {}) {
  return jsonResponse(
    { error: { code, message, correlation_id: `req-${status}` } },
    { status, headers: { "Content-Type": "application/json", ...headers } },
  );
}

function renderDetail(id = INDICATOR_ID, extra?: ReactNode) {
  return renderRoute(
    <>
      <IndicatorDetailPage />
      {extra}
    </>,
    { path: "/indicators/:indicatorId", url: `/indicators/${id}` },
  );
}

function verdict(): HTMLElement {
  const section = screen.getByRole("heading", { name: "CipherForge assessment" }).closest("section");
  if (!section) throw new Error("No verdict card found");
  return section;
}

function GoTo({ to }: { to: string }) {
  const navigate = useNavigate();
  return (
    <button type="button" onClick={() => void navigate(to)}>
      Go to {to}
    </button>
  );
}

describe("IndicatorDetailPage", () => {
  it("shows the stored record without asking any provider", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeInvestigation()));
    renderDetail();

    expect(screen.getByText("Loading the stored record…")).toBeInTheDocument();
    expect(await screen.findByRole("heading", { name: "CipherForge assessment" })).toBeInTheDocument();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe(`/api/v1/intel/indicators/${INDICATOR_ID}`);
    expect(fetchMock.mock.calls[0]?.[1]?.method).toBe("GET");
    expect(screen.getByRole("heading", { name: "Indicator details" })).toBeInTheDocument();
    expect(within(verdict()).getByText("203.0.113.9")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "AbuseIPDB" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "AlienVault OTX" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /All indicators/ })).toHaveAttribute(
      "href",
      "/indicators",
    );
    // The title is set by an effect, which React may flush a moment after the record is drawn.
    await waitFor(() => expect(document.title).toBe("Indicator 203.0.113.9 · CipherForge"));
  });

  it("re-checks with the providers and replaces the stored result with the newer one", async () => {
    let finish: (response: Response) => void = () => {};
    const fetchMock = stubFetch((_url, init) =>
      init?.method === "POST"
        ? new Promise<Response>((resolve) => {
            finish = resolve;
          })
        : jsonResponse(makeInvestigation()),
    );
    const user = userEvent.setup();
    renderDetail();
    await screen.findByRole("heading", { name: "CipherForge assessment" });
    expect(within(verdict()).getByText("High")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Re-check with providers" }));

    const busy = screen.getByRole("button", { name: "Re-checking…" });
    expect(busy).toHaveAttribute("aria-disabled", "true");
    expect(busy).toHaveFocus();
    await user.click(busy);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [url, init] = fetchMock.mock.calls[1] ?? [];
    expect(String(url)).toBe("/api/v1/intel/investigate");
    expect(JSON.parse(String(init?.body))).toEqual({ indicator: "203.0.113.9", refresh: true });

    finish(jsonResponse(recheckedInvestigation()));

    expect(await within(verdict()).findByText("Low")).toBeInTheDocument();
    expect(within(verdict()).queryByText("High")).not.toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent("Re-check complete. The record was updated.");
    expect(screen.getByRole("button", { name: "Re-check with providers" })).toBeEnabled();
  });

  it("keeps the stored record in view when a re-check is refused", async () => {
    stubFetch((_url, init) =>
      init?.method === "POST"
        ? error(429, "rate_limited", "Too many investigations. Try again shortly.", {
            "Retry-After": "20",
          })
        : jsonResponse(makeInvestigation()),
    );
    const user = userEvent.setup();
    renderDetail();
    await screen.findByRole("heading", { name: "CipherForge assessment" });

    await user.click(screen.getByRole("button", { name: "Re-check with providers" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Rate limit reached");
    expect(alert).toHaveTextContent("Try again in 20 seconds.");
    expect(within(verdict()).getByText("High")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Re-check with providers" })).toBeEnabled();
  });

  it("says so when the indicator does not exist, without offering a pointless retry", async () => {
    stubFetch(() => error(404, "not_found", "Indicator not found."));
    renderDetail();

    expect(await screen.findByRole("heading", { name: "Indicator not found" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /All indicators/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Try again" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Re-check with providers" })).not.toBeInTheDocument();
    expect(document.title).toBe("Indicator not found · CipherForge");
  });

  it.each([["not-a-uuid"], ["..%2F..%2Fhealth"], [`${INDICATOR_ID}%20`]])(
    "does not ask the API about %s, which cannot be an indicator ID",
    (id) => {
      const fetchMock = stubFetch(() => jsonResponse(makeInvestigation()));
      renderDetail(id);

      expect(screen.getByRole("heading", { name: "Indicator not found" })).toBeInTheDocument();
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it("offers to try again when the record cannot be loaded, and offers no re-check meanwhile", async () => {
    let calls = 0;
    stubFetch(() => {
      calls += 1;
      return calls === 1
        ? error(500, "internal_error", "Something failed.")
        : jsonResponse(makeInvestigation());
    });
    const user = userEvent.setup();
    renderDetail();

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The API reported an error");
    expect(screen.queryByRole("button", { name: "Re-check with providers" })).not.toBeInTheDocument();

    await user.click(within(alert).getByRole("button", { name: "Try again" }));

    expect(await screen.findByRole("heading", { name: "CipherForge assessment" })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("does not carry a re-check over when moving to a different indicator", async () => {
    const other = makeNotAssessed();
    stubFetch((url, init) => {
      if (init?.method === "POST") return jsonResponse(recheckedInvestigation());
      return url.endsWith(INDICATOR_ID)
        ? jsonResponse(makeInvestigation())
        : jsonResponse({ ...other, indicator: { ...other.indicator, indicator_id: OTHER_ID } });
    });
    const user = userEvent.setup();
    renderDetail(INDICATOR_ID, <GoTo to={`/indicators/${OTHER_ID}`} />);
    await screen.findByRole("heading", { name: "CipherForge assessment" });
    await user.click(screen.getByRole("button", { name: "Re-check with providers" }));
    expect(await within(verdict()).findByText("Low")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: `Go to /indicators/${OTHER_ID}` }));

    // The other indicator's own record is shown, not the previous indicator's re-check result.
    expect(await within(verdict()).findByText("203.0.113.50")).toBeInTheDocument();
    expect(within(verdict()).getByText("Not assessed")).toBeInTheDocument();
    expect(within(verdict()).queryByText("203.0.113.9")).not.toBeInTheDocument();
    expect(screen.getByRole("status")).not.toHaveTextContent("Re-check complete");
  });
});
