import { act, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useNavigate } from "react-router";
import { describe, expect, it } from "vitest";

import { createIntent } from "../features/intel/investigateIntent";
import { INDICATOR_ID, makeInvestigation, makeNotAssessed } from "../test/fixtures";
import { jsonResponse, stubFetch } from "../test/http";
import { currentState, renderRoute } from "../test/router";
import InvestigatePage from "./InvestigatePage";

function renderPage() {
  return renderRoute(<InvestigatePage />, { url: "/investigate" });
}

function indicatorInput(): HTMLElement {
  return screen.getByRole("textbox", { name: "Indicator" });
}

function submit(user: ReturnType<typeof userEvent.setup>) {
  return user.click(screen.getByRole("button", { name: "Investigate" }));
}

function sentBody(fetchMock: ReturnType<typeof stubFetch>, call = 0): unknown {
  return JSON.parse(String(fetchMock.mock.calls[call]?.[1]?.body));
}

function error(status: number, code: string, message: string, headers: Record<string, string> = {}) {
  return jsonResponse(
    { error: { code, message, correlation_id: `req-${status}` } },
    { status, headers: { "Content-Type": "application/json", ...headers } },
  );
}

describe("InvestigatePage", () => {
  it("tells the analyst, before sending anything, that third parties will see the indicator", () => {
    stubFetch(() => jsonResponse(makeInvestigation()));
    renderPage();

    expect(screen.getByText(/outside your organisation/)).toBeInTheDocument();
    expect(document.title).toBe("Investigate · CipherForge");
  });

  it.each([
    { typed: "", description: "nothing" },
    { typed: "   ", description: "only spaces" },
  ])(
    "asks for an indicator instead of sending a request when given $description",
    async ({ typed }) => {
      const fetchMock = stubFetch(() => jsonResponse(makeInvestigation()));
      const user = userEvent.setup();
      renderPage();
      if (typed) await user.type(indicatorInput(), typed);

      await submit(user);

      const alert = screen.getByRole("alert");
      expect(alert).toHaveTextContent("Enter an indicator to investigate.");
      expect(indicatorInput()).toHaveAttribute("aria-invalid", "true");
      expect(indicatorInput()).toHaveAccessibleDescription(/Enter an indicator to investigate\./);
      expect(fetchMock).not.toHaveBeenCalled();
    },
  );

  it("refuses an indicator longer than the API accepts and says how long it is", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeInvestigation()));
    const user = userEvent.setup();
    renderPage();
    await user.click(indicatorInput());
    await user.paste("a".repeat(2049));

    await submit(user);

    expect(screen.getByRole("alert")).toHaveTextContent("at most 2048 characters");
    expect(screen.getByRole("alert")).toHaveTextContent("2049");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("investigates the trimmed indicator, showing progress and then the full result", async () => {
    let finish: (response: Response) => void = () => {};
    const pending = new Promise<Response>((resolve) => {
      finish = resolve;
    });
    const fetchMock = stubFetch(() => pending);
    const user = userEvent.setup();
    renderPage();

    await user.type(indicatorInput(), "  203.0.113.9  ");
    await submit(user);

    expect(sentBody(fetchMock)).toEqual({ indicator: "203.0.113.9", refresh: false });
    const busy = screen.getByRole("button", { name: "Investigating…" });
    expect(busy).toHaveAttribute("aria-disabled", "true");
    expect(busy).toHaveFocus();
    expect(screen.getByText(/Asking the providers about 203\.0\.113\.9/)).toBeInTheDocument();

    // Neither the busy button nor Enter in the field may start the lookup over.
    await user.click(busy);
    await user.type(indicatorInput(), "{Enter}");
    expect(fetchMock).toHaveBeenCalledTimes(1);

    finish(jsonResponse(makeInvestigation()));

    expect(await screen.findByRole("heading", { name: "CipherForge assessment" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Provider answers" })).toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(
      "203.0.113.9 is classified High, with score 80 and confidence 90.",
    );
    expect(screen.getByRole("link", { name: "Open the saved record" })).toHaveAttribute(
      "href",
      `/indicators/${INDICATOR_ID}`,
    );
    expect(screen.getByRole("button", { name: "Investigate" })).toBeEnabled();
  });

  it("asks the providers again only when the box is ticked", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeInvestigation()));
    const user = userEvent.setup();
    renderPage();
    await user.type(indicatorInput(), "203.0.113.9");

    await submit(user);
    await screen.findByRole("heading", { name: "CipherForge assessment" });
    await user.click(screen.getByRole("checkbox", { name: /Ask the providers again/ }));
    await submit(user);

    await screen.findByRole("heading", { name: "CipherForge assessment" });
    expect(sentBody(fetchMock, 0)).toEqual({ indicator: "203.0.113.9", refresh: false });
    expect(sentBody(fetchMock, 1)).toEqual({ indicator: "203.0.113.9", refresh: true });
  });

  it("does not present an unanswered lookup as a clean result", async () => {
    stubFetch(() => jsonResponse(makeNotAssessed()));
    const user = userEvent.setup();
    renderPage();
    await user.type(indicatorInput(), "203.0.113.50");

    await submit(user);

    const verdict = (await screen.findByRole("heading", { name: "CipherForge assessment" })).closest(
      "section",
    );
    expect(within(verdict as HTMLElement).getByText("Not assessed")).toBeInTheDocument();
    expect(within(verdict as HTMLElement).queryByText("Informational")).not.toBeInTheDocument();
    expect(screen.getByRole("status")).toHaveTextContent(
      "203.0.113.50 was not assessed because no provider answered.",
    );
  });

  it("explains a rejected indicator, keeps what was typed and allows another attempt", async () => {
    let calls = 0;
    stubFetch(() => {
      calls += 1;
      return calls === 1
        ? error(422, "validation_error", "That is not an IP address, domain, URL or SHA-256 hash.")
        : jsonResponse(makeInvestigation());
    });
    const user = userEvent.setup();
    renderPage();
    await user.type(indicatorInput(), "not an indicator");

    await submit(user);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("That request was not accepted");
    expect(alert).toHaveTextContent("That is not an IP address, domain, URL or SHA-256 hash.");
    expect(alert).toHaveTextContent("Reference: req-422");
    expect(indicatorInput()).toHaveValue("not an indicator");
    expect(screen.getByRole("button", { name: "Investigate" })).toBeEnabled();

    await user.clear(indicatorInput());
    await user.type(indicatorInput(), "203.0.113.9");
    await submit(user);

    expect(await screen.findByRole("heading", { name: "CipherForge assessment" })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("says how long to wait when the rate limit is reached", async () => {
    stubFetch(() =>
      error(429, "rate_limited", "Too many investigations. Try again shortly.", {
        "Retry-After": "45",
      }),
    );
    const user = userEvent.setup();
    renderPage();
    await user.type(indicatorInput(), "203.0.113.9");

    await submit(user);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Rate limit reached");
    expect(alert).toHaveTextContent("Try again in 45 seconds.");
    expect(screen.queryByRole("heading", { name: "CipherForge assessment" })).not.toBeInTheDocument();
  });

  it("removes the previous result while the next lookup is running", async () => {
    let calls = 0;
    let finish: (response: Response) => void = () => {};
    stubFetch(() => {
      calls += 1;
      return calls === 1
        ? jsonResponse(makeInvestigation())
        : new Promise<Response>((resolve) => {
            finish = resolve;
          });
    });
    const user = userEvent.setup();
    renderPage();
    await user.type(indicatorInput(), "203.0.113.9");
    await submit(user);
    await screen.findByRole("heading", { name: "CipherForge assessment" });

    await submit(user);

    // Showing 203.0.113.9's verdict under a different lookup's progress note would mislead.
    expect(screen.queryByRole("heading", { name: "CipherForge assessment" })).not.toBeInTheDocument();
    finish(jsonResponse(makeNotAssessed()));
    expect(await screen.findByText("Not assessed")).toBeInTheDocument();
  });

  it("shows what kind of indicator is being typed, and stays quiet when it cannot tell", async () => {
    stubFetch(() => jsonResponse(makeInvestigation()));
    const user = userEvent.setup();
    renderPage();

    await user.type(indicatorInput(), "2001:4860:4860::8888");
    expect(screen.getByText("Looks like", { exact: false }).parentElement).toHaveTextContent(
      "Looks like IPv6",
    );

    await user.clear(indicatorInput());
    await user.type(indicatorInput(), "not an indicator");
    expect(screen.queryByText("Looks like", { exact: false })).not.toBeInTheDocument();
  });

  it("fills the field from an example, clears the complaint and sends nothing", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeInvestigation()));
    const user = userEvent.setup();
    renderPage();
    await submit(user);
    expect(screen.getByRole("alert")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /^Domain/ }));

    expect(indicatorInput()).toHaveValue("example.com");
    expect(indicatorInput()).toHaveFocus();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /^SHA-256/ }));
    expect((indicatorInput() as HTMLInputElement).value).toMatch(/^e3b0c442[0-9a-f]{56}$/);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

/** Gives a request that should not have been sent the chance to go out. */
function settle() {
  return act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 20));
  });
}

function AskAbout({ indicator }: { indicator: string }) {
  const navigate = useNavigate();
  return (
    <button type="button" onClick={() => void navigate("/investigate", { state: createIntent(indicator) })}>
      Ask about {indicator}
    </button>
  );
}

describe("InvestigatePage opened from the command palette", () => {
  it("starts the lookup straight away and spends the request", async () => {
    let finish: (response: Response) => void = () => {};
    const fetchMock = stubFetch(
      () =>
        new Promise<Response>((resolve) => {
          finish = resolve;
        }),
    );
    renderRoute(<InvestigatePage />, { url: "/investigate", state: createIntent("203.0.113.9") });

    expect(indicatorInput()).toHaveValue("203.0.113.9");
    expect(screen.getByRole("button", { name: "Investigating…" })).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByText(/Asking the providers about 203\.0\.113\.9/)).toBeInTheDocument();

    finish(jsonResponse(makeInvestigation()));

    expect(await screen.findByRole("heading", { name: "CipherForge assessment" })).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(sentBody(fetchMock)).toEqual({ indicator: "203.0.113.9", refresh: false });
    // A reload or a trip back to this entry must not ask the providers again.
    await waitFor(() =>
      expect(currentState()).toMatchObject({ indicator: "203.0.113.9", autorun: false }),
    );
    expect(screen.getByTestId("location")).toHaveTextContent("/investigate");
  });

  it("only fills the field when the request has already been spent", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeInvestigation()));
    renderRoute(<InvestigatePage />, {
      url: "/investigate",
      state: { ...createIntent("example.com"), autorun: false },
    });

    await settle();

    expect(indicatorInput()).toHaveValue("example.com");
    expect(screen.getByRole("button", { name: "Investigate" })).toBeEnabled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("ignores router state that the palette did not create", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeInvestigation()));
    renderRoute(<InvestigatePage />, { url: "/investigate", state: { indicator: "203.0.113.9" } });

    await settle();

    expect(indicatorInput()).toHaveValue("");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("looks an indicator up again when it is asked about twice in a row", async () => {
    const fetchMock = stubFetch(() => jsonResponse(makeInvestigation()));
    const user = userEvent.setup();
    renderRoute(
      <>
        <AskAbout indicator="203.0.113.9" />
        <InvestigatePage />
      </>,
      { url: "/investigate" },
    );

    await user.click(screen.getByRole("button", { name: "Ask about 203.0.113.9" }));
    await screen.findByRole("heading", { name: "CipherForge assessment" });
    await user.click(screen.getByRole("button", { name: "Ask about 203.0.113.9" }));

    await waitFor(() => expect(fetchMock).toHaveBeenCalledTimes(2));
    expect(await screen.findByRole("heading", { name: "CipherForge assessment" })).toBeInTheDocument();
  });
});
