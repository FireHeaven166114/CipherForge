import { act, screen, waitFor } from "@testing-library/react";
import userEvent, { type UserEvent } from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { setTokenProvider } from "../services/apiClient";
import {
  SHARE_TOKEN,
  type SentRequest,
  describeRequest,
  failure,
  makeGate,
  makePublicShareInfo,
  only,
  sentRequests,
  stubBlobDownload,
} from "../test/filesFixtures";
import { hangingFetch, jsonResponse, stubFetch } from "../test/http";
import { renderRoute } from "../test/router";
import SharePage from "./SharePage";

type FetchMock = ReturnType<typeof stubFetch>;

const SHARE_PATH = `/api/v1/shares/${SHARE_TOKEN}`;
const PASSWORD = "correct horse battery";
const STARTED = "Your download has started";

// Links that can never work again, and what the page tells the recipient about each.
const ENDED_LINKS = [
  { status: 404, code: "share_not_found", title: "This link does not work" },
  { status: 410, code: "share_expired", title: "This link has expired" },
  { status: 410, code: "share_revoked", title: "This link has been revoked" },
  { status: 410, code: "share_limit_reached", title: "This link has reached its download limit" },
];

// Troubles that can pass: asking again can work, so the page offers to.
const TROUBLES: { name: string; title: string; respond: () => Response | Promise<Response> }[] = [
  {
    name: "a server that is not set up",
    title: "Sharing is not available right now",
    respond: () => failure(503, "feature_not_configured"),
  },
  {
    name: "an unexpected server error",
    title: "Something went wrong",
    respond: () => failure(500, "internal_error"),
  },
  {
    name: "a network that is down",
    title: "Could not reach CipherForge",
    respond: () => Promise.reject(new TypeError("Failed to fetch")),
  },
];

const strays: string[] = [];

afterEach(() => {
  setTokenProvider(null);
  vi.useRealTimers();
  // A page that asks for something the server does not have would show a failure, not crash.
  expect(strays.splice(0)).toEqual([]);
});

interface ShareServer {
  /** The answer to looking the link up. */
  info?: () => Response | Promise<Response>;
  /** The answer to each attempt to download. */
  download?: (request: SentRequest) => Response | Promise<Response>;
}

function fileResponse(disposition: string | null = `attachment; filename="report.pdf"`): Response {
  const headers = new Headers({ "Content-Type": "application/octet-stream" });
  if (disposition !== null) headers.set("Content-Disposition", disposition);
  return new Response("file bytes", { status: 200, headers });
}

function serveShare({
  info = () => jsonResponse(makePublicShareInfo()),
  download = () => fileResponse(),
}: ShareServer = {}): FetchMock {
  return stubFetch((url, init) => {
    const request = describeRequest(url, init);
    if (request.method === "GET" && request.path === SHARE_PATH) return info();
    if (request.method === "POST" && request.path === `${SHARE_PATH}/download`) return download(request);
    strays.push(`${request.method} ${request.path}`);
    return failure(500, "unexpected_request");
  });
}

/** A link that needs a password, so the file's name is held back. */
function passwordProtected(): Response {
  return jsonResponse(makePublicShareInfo({ file_name: null, password_required: true }));
}

/** Answers the first call with a trouble and every later one with `then`. */
function troubleOnce(trouble: () => Response | Promise<Response>, then: () => Response) {
  let calls = 0;
  return () => {
    calls += 1;
    return calls === 1 ? trouble() : then();
  };
}

function renderShare() {
  return renderRoute(<SharePage />, { url: `/share/${SHARE_TOKEN}`, path: "/share/:token" });
}

function downloadsOf(fetchMock: FetchMock): SentRequest[] {
  return sentRequests(fetchMock).filter(({ method }) => method === "POST");
}

async function pressDownload(user: UserEvent) {
  await user.click(await screen.findByRole("button", { name: "Download" }));
}

/**
 * The token and the password belong in a request and nowhere a recipient, a tab strip or a history
 * entry could show them. The test router prints the address, so only the page itself is searched.
 */
function expectNotOnPage(secret: string) {
  expect(screen.getByRole("main").innerHTML).not.toContain(secret);
  expect(document.title).not.toContain(secret);
  expect(document.head.innerHTML).not.toContain(secret);
}

/** Collects whatever is printed to the console from now on, instead of printing it. */
function watchConsole(): () => string {
  const printed: string[] = [];
  for (const method of ["debug", "error", "info", "log", "warn"] as const) {
    vi.spyOn(console, method).mockImplementation((...args: unknown[]) => {
      printed.push(args.map(String).join(" "));
    });
  }
  return () => printed.join("\n");
}

describe("SharePage lookup", () => {
  it("says it is checking the link while the server answers", () => {
    stubFetch(hangingFetch());
    renderShare();

    expect(screen.getByText("Checking this link…")).toBeInTheDocument();
    expect(screen.getByText("CIPHERFORGE")).toBeInTheDocument();
    expect(document.title).toBe("Shared file · CipherForge");
  });

  it("offers the file with its size, its expiry in IST and the downloads left", async () => {
    const fetchMock = serveShare();
    renderShare();

    expect(await screen.findByRole("heading", { level: 1, name: "report.pdf" })).toBeInTheDocument();
    expect(screen.getByText("Someone shared this file with you through CipherForge.")).toBeInTheDocument();
    expect(screen.getByText("Size").nextElementSibling).toHaveTextContent("2.00 KB");
    expect(screen.getByText("Link expires").nextElementSibling).toHaveTextContent("21-05-2026 02:00:00 PM IST");
    expect(screen.getByText("Downloads left").nextElementSibling).toHaveTextContent(/^3$/);
    expect(screen.getByRole("button", { name: "Download" })).not.toHaveAttribute("aria-disabled");
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();
    // The title never carries the file's name: it would end up in history and in the tab strip.
    expect(document.title).toBe("Shared file · CipherForge");

    const lookup = only(sentRequests(fetchMock));
    expect(lookup).toMatchObject({ method: "GET", path: SHARE_PATH });
    expect(lookup.headers.has("Authorization")).toBe(false);
  });

  it("shows a file name that looks like markup as plain text", async () => {
    const name = "<img src=x onerror=alert(1)>.txt";
    serveShare({ info: () => jsonResponse(makePublicShareInfo({ file_name: name })) });
    renderShare();

    expect(await screen.findByRole("heading", { level: 1, name })).toBeInTheDocument();
    expect(screen.getByRole("main").querySelector("img")).toBeNull();
  });

  it("stands alone: no navigation, no sign-in state and nothing to click through to", async () => {
    serveShare();
    renderShare();
    await screen.findByRole("heading", { level: 1, name: "report.pdf" });

    expect(screen.getAllByRole("main")).toHaveLength(1);
    expect(screen.queryByRole("navigation")).not.toBeInTheDocument();
    expect(screen.queryByRole("banner")).not.toBeInTheDocument();
    expect(screen.queryAllByRole("link")).toHaveLength(0);
  });

  it("asks search engines to leave the page out while it is open, and only then", () => {
    stubFetch(hangingFetch());
    const { unmount } = renderShare();

    const robots = document.head.querySelectorAll('meta[name="robots"]');
    expect(robots).toHaveLength(1);
    expect(robots[0]).toHaveAttribute("content", "noindex,nofollow");

    unmount();

    expect(document.head.querySelector('meta[name="robots"]')).toBeNull();
  });

  it("treats an address with no token as a link that does not work, and asks nothing", () => {
    const fetchMock = stubFetch(() => failure(500, "unexpected_request"));
    renderRoute(<SharePage />, { url: "/share", path: "/share" });

    expect(screen.getByRole("heading", { level: 1, name: "This link does not work" })).toBeInTheDocument();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("keeps the console's sign-in token off every request, even when the app holds one", async () => {
    const provider = vi.fn<() => string>(() => "console-sign-in-token");
    setTokenProvider(provider);
    stubBlobDownload();
    const fetchMock = serveShare();
    const user = userEvent.setup();
    renderShare();

    await pressDownload(user);
    await screen.findByRole("heading", { level: 1, name: STARTED });

    const requests = sentRequests(fetchMock);
    expect(requests.map(({ method }) => method)).toEqual(["GET", "POST"]);
    for (const request of requests) expect(request.headers.has("Authorization")).toBe(false);
    expect(provider).not.toHaveBeenCalled();
  });

  it("never shows or prints the link's token, before or after the download", async () => {
    stubBlobDownload();
    const logged = watchConsole();
    serveShare();
    const user = userEvent.setup();
    renderShare();

    await screen.findByRole("heading", { level: 1, name: "report.pdf" });
    expectNotOnPage(SHARE_TOKEN);

    await pressDownload(user);
    await screen.findByRole("heading", { level: 1, name: STARTED });
    expectNotOnPage(SHARE_TOKEN);
    expect(logged()).toBe("");
  });

  it.each(ENDED_LINKS)(
    "says $title for a lookup answered $code, and offers no way forward",
    async ({ status, code, title }) => {
      const fetchMock = serveShare({ info: () => failure(status, code) });
      renderShare();

      expect(await screen.findByRole("heading", { level: 1, name: title })).toBeInTheDocument();
      expect(screen.getByRole("alert")).toHaveTextContent("Reference: req-test");
      expect(screen.queryByRole("button")).not.toBeInTheDocument();
      expect(sentRequests(fetchMock)).toHaveLength(1);
      expectNotOnPage(SHARE_TOKEN);
    },
  );

  it.each(TROUBLES)("explains $name and looks again when asked", async ({ respond, title }) => {
    const fetchMock = serveShare({ info: troubleOnce(respond, () => jsonResponse(makePublicShareInfo())) });
    const user = userEvent.setup();
    renderShare();

    expect(await screen.findByRole("heading", { level: 1, name: title })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Try again" }));

    expect(await screen.findByRole("heading", { level: 1, name: "report.pdf" })).toBeInTheDocument();
    expect(sentRequests(fetchMock)).toHaveLength(2);
  });

  it("says how long the server asked the recipient to wait when looking links up is limited", async () => {
    serveShare({
      info: troubleOnce(
        () => failure(429, "rate_limited", { "Retry-After": "20" }),
        () => jsonResponse(makePublicShareInfo()),
      ),
    });
    const user = userEvent.setup();
    renderShare();

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Too many attempts");
    expect(alert).toHaveTextContent("The server asked you to wait 20 seconds.");

    await user.click(screen.getByRole("button", { name: "Try again" }));

    expect(await screen.findByRole("heading", { level: 1, name: "report.pdf" })).toBeInTheDocument();
  });
});

describe("SharePage download", () => {
  it("downloads a link with no password and saves the file under the name the server gave", async () => {
    const saved = stubBlobDownload();
    const fetchMock = serveShare();
    const user = userEvent.setup();
    renderShare();

    await pressDownload(user);

    const heading = await screen.findByRole("heading", { level: 1, name: STARTED });
    await waitFor(() => expect(heading).toHaveFocus());
    expect(screen.getByText("report.pdf")).toBeInTheDocument();
    expect(screen.getByText("This link can be used 2 more times.")).toBeInTheDocument();
    expect(saved.clicks).toEqual([{ download: "report.pdf", href: "blob:cipherforge-test" }]);

    const [blob] = only(saved.createObjectURL.mock.calls);
    expect(await blob.text()).toBe("file bytes");

    const attempt = only(downloadsOf(fetchMock));
    expect(attempt.path).toBe(`${SHARE_PATH}/download`);
    expect(attempt.body).toBeUndefined();
    expect(attempt.headers.has("Content-Type")).toBe(false);
  });

  it.each([
    { left: 3, note: "This link can be used 2 more times." },
    { left: 2, note: "This link can be used 1 more time." },
    { left: 1, note: "This link has no downloads left." },
  ])("tells the recipient how many uses are left when $left remain", async ({ left, note }) => {
    stubBlobDownload();
    serveShare({ info: () => jsonResponse(makePublicShareInfo({ downloads_remaining: left })) });
    const user = userEvent.setup();
    renderShare();

    await pressDownload(user);

    expect(await screen.findByText(note)).toBeInTheDocument();
  });

  it.each([
    {
      name: "the extended name over the plain one",
      disposition: `attachment; filename="resume.pdf"; filename*=UTF-8''r%C3%A9sum%C3%A9.pdf`,
      expected: "résumé.pdf",
    },
    {
      name: "a quoted name",
      disposition: `attachment; filename="quarterly report.pdf"`,
      expected: "quarterly report.pdf",
    },
    {
      name: "only the last part of a name that climbs out of the folder",
      disposition: `attachment; filename*=UTF-8''..%2F..%2Fetc%2Fpasswd`,
      expected: "passwd",
    },
    { name: "the fallback when the header has no name", disposition: "attachment", expected: "download" },
    { name: "the fallback when there is no header", disposition: null, expected: "download" },
  ])("saves under $name", async ({ disposition, expected }) => {
    const saved = stubBlobDownload();
    serveShare({ download: () => fileResponse(disposition) });
    const user = userEvent.setup();
    renderShare();

    await pressDownload(user);

    await screen.findByRole("heading", { level: 1, name: STARTED });
    expect(saved.clicks.map(({ download }) => download)).toEqual([expected]);
    expect(screen.getByText(expected)).toBeInTheDocument();
  });

  it("saves the file again on request without using up another download", async () => {
    const saved = stubBlobDownload();
    const fetchMock = serveShare();
    const user = userEvent.setup();
    renderShare();
    await pressDownload(user);
    await screen.findByRole("heading", { level: 1, name: STARTED });

    await user.click(screen.getByRole("button", { name: "Save again" }));

    expect(saved.clicks).toHaveLength(2);
    expect(screen.getByRole("heading", { level: 1, name: STARTED })).toBeInTheDocument();
    expect(downloadsOf(fetchMock)).toHaveLength(1);
  });

  it("says so when the browser would not start the save, and saves again without a new download", async () => {
    const saved = stubBlobDownload();
    saved.createObjectURL.mockImplementationOnce(() => {
      throw new Error("blocked");
    });
    const fetchMock = serveShare();
    const user = userEvent.setup();
    renderShare();

    await pressDownload(user);

    expect(
      await screen.findByRole("heading", { level: 1, name: "Your browser did not start the download" }),
    ).toBeInTheDocument();
    expect(screen.getByText(/This does not use up another download\./)).toBeInTheDocument();
    expect(saved.clicks).toEqual([]);

    await user.click(screen.getByRole("button", { name: "Save again" }));

    expect(await screen.findByRole("heading", { level: 1, name: STARTED })).toBeInTheDocument();
    expect(saved.clicks).toEqual([{ download: "report.pdf", href: "blob:cipherforge-test" }]);
    expect(downloadsOf(fetchMock)).toHaveLength(1);
  });

  it("holds a second press while the first download is running", async () => {
    stubBlobDownload();
    const gate = makeGate();
    const fetchMock = serveShare({
      download: async () => {
        await gate.passed;
        return fileResponse();
      },
    });
    const user = userEvent.setup();
    renderShare();

    await pressDownload(user);

    const busy = await screen.findByRole("button", { name: "Downloading…" });
    expect(busy).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByText("Decrypting and checking the file. This can take a moment.")).toBeInTheDocument();

    await user.click(busy);
    expect(downloadsOf(fetchMock)).toHaveLength(1);

    gate.open();

    expect(await screen.findByRole("heading", { level: 1, name: STARTED })).toBeInTheDocument();
    expect(downloadsOf(fetchMock)).toHaveLength(1);
  });
});

describe("SharePage password", () => {
  it("asks for the password and keeps the file's name hidden until it is downloaded", async () => {
    serveShare({ info: passwordProtected });
    renderShare();

    expect(
      await screen.findByRole("heading", { level: 1, name: "A password-protected file" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(
        "Someone shared a file with you through CipherForge. Its name stays hidden until it is downloaded.",
      ),
    ).toBeInTheDocument();
    expect(screen.queryByText("report.pdf")).not.toBeInTheDocument();

    const input = screen.getByLabelText("Password");
    expect(input).toHaveAttribute("type", "password");
    expect(input).toHaveAttribute("autocomplete", "current-password");
    expect(input).toHaveValue("");
    expect(input).toHaveAccessibleDescription("The person who sent you this link gave you the password separately.");
  });

  it("sends nothing and says so when the password box is empty", async () => {
    const fetchMock = serveShare({ info: passwordProtected });
    const user = userEvent.setup();
    renderShare();

    await pressDownload(user);

    const input = screen.getByLabelText("Password");
    expect(screen.getByText("Enter the password to download this file.")).toBeInTheDocument();
    expect(input).toHaveFocus();
    expect(input).toBeInvalid();
    expect(input).toHaveAccessibleDescription(/Enter the password to download this file\./);
    expect(downloadsOf(fetchMock)).toHaveLength(0);

    await user.type(input, "x");

    expect(screen.queryByText("Enter the password to download this file.")).not.toBeInTheDocument();
    expect(input).toBeValid();
  });

  it("sends the password once, in the request body, and keeps it out of the page and the console", async () => {
    const saved = stubBlobDownload();
    const logged = watchConsole();
    const fetchMock = serveShare({
      info: passwordProtected,
      download: () => fileResponse(`attachment; filename="secret-plans.pdf"`),
    });
    const user = userEvent.setup();
    renderShare();

    await user.type(await screen.findByLabelText("Password"), `${PASSWORD}{Enter}`);

    expect(await screen.findByRole("heading", { level: 1, name: STARTED })).toBeInTheDocument();
    expect(screen.getByText("secret-plans.pdf")).toBeInTheDocument();
    expect(saved.clicks.map(({ download }) => download)).toEqual(["secret-plans.pdf"]);

    const attempt = only(downloadsOf(fetchMock));
    expect(attempt.path).toBe(`${SHARE_PATH}/download`);
    expect(attempt.query.toString()).toBe("");
    expect(attempt.headers.get("Content-Type")).toBe("application/json");
    expect(attempt.body).toEqual({ password: PASSWORD });

    expectNotOnPage(PASSWORD);
    expect(screen.getByTestId("location")).not.toHaveTextContent(PASSWORD);
    expect(localStorage).toHaveLength(0);
    expect(sessionStorage).toHaveLength(0);
    expect(logged()).toBe("");
  });

  it("keeps what was typed after a wrong password and lets the recipient try again", async () => {
    stubBlobDownload();
    const fetchMock = serveShare({
      info: passwordProtected,
      download: troubleOnce(() => failure(403, "invalid_password"), fileResponse),
    });
    const user = userEvent.setup();
    renderShare();

    const input = await screen.findByLabelText("Password");
    await user.type(input, "wrong-password{Enter}");

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("That password is not correct");
    expect(alert).toHaveTextContent("Check the password you were given and try again.");
    expect(alert).toHaveTextContent("Reference: req-test");
    expect(input).toHaveValue("wrong-password");
    await waitFor(() => expect(input).toHaveFocus());
    expect(input).toBeInvalid();
    expect(input).toHaveAccessibleDescription(/That password is not correct/);
    expect(screen.getByRole("main")).not.toHaveTextContent("wrong-password");
    expect(screen.getByRole("button", { name: "Download" })).not.toHaveAttribute("aria-disabled");

    await user.clear(input);
    await user.type(input, `${PASSWORD}{Enter}`);

    expect(await screen.findByRole("heading", { level: 1, name: STARTED })).toBeInTheDocument();
    expect(downloadsOf(fetchMock).map(({ body }) => body)).toEqual([
      { password: "wrong-password" },
      { password: PASSWORD },
    ]);
    expect(sentRequests(fetchMock).filter(({ method }) => method === "GET")).toHaveLength(1);
  });

  it("holds the button while the server asks for a wait, then allows another try", async () => {
    // Only the clock is replaced: the countdown ticks on it, and the rest of the page keeps real time.
    vi.useFakeTimers({ toFake: ["setInterval", "clearInterval", "Date"] });
    stubBlobDownload();
    const fetchMock = serveShare({
      info: passwordProtected,
      download: troubleOnce(() => failure(429, "too_many_attempts", { "Retry-After": "30" }), fileResponse),
    });
    const user = userEvent.setup();
    renderShare();

    await user.type(await screen.findByLabelText("Password"), `${PASSWORD}{Enter}`);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Too many attempts");
    expect(alert).toHaveTextContent("The server asked you to wait 30 seconds.");
    const waiting = screen.getByRole("button", { name: "Try again in 30 s" });
    expect(waiting).toHaveAttribute("aria-disabled", "true");

    await user.click(waiting);
    expect(downloadsOf(fetchMock)).toHaveLength(1);

    await act(async () => {
      vi.advanceTimersByTime(29_000);
    });
    expect(screen.getByRole("button", { name: "Try again in 1 s" })).toHaveAttribute("aria-disabled", "true");

    await act(async () => {
      vi.advanceTimersByTime(1000);
    });
    const ready = screen.getByRole("button", { name: "Download" });
    expect(ready).not.toHaveAttribute("aria-disabled");
    expect(screen.getByText("You can try again now.")).toBeInTheDocument();

    await user.click(ready);

    expect(await screen.findByRole("heading", { level: 1, name: STARTED })).toBeInTheDocument();
    expect(downloadsOf(fetchMock).map(({ body }) => body)).toEqual([{ password: PASSWORD }, { password: PASSWORD }]);
  });

  it("waits ten seconds when the server limits attempts without saying for how long", async () => {
    serveShare({ info: passwordProtected, download: () => failure(429, "rate_limited") });
    const user = userEvent.setup();
    renderShare();

    await user.type(await screen.findByLabelText("Password"), `${PASSWORD}{Enter}`);

    expect(await screen.findByRole("button", { name: "Try again in 10 s" })).toHaveAttribute(
      "aria-disabled",
      "true",
    );
    expect(screen.getByRole("alert")).toHaveTextContent("Too many attempts");
    expect(screen.getByRole("alert")).not.toHaveTextContent("The server asked you to wait");
  });

  it("asks for the password when a link that looked open turns out to need one", async () => {
    stubBlobDownload();
    const fetchMock = serveShare({ download: troubleOnce(() => failure(403, "password_required"), fileResponse) });
    const user = userEvent.setup();
    renderShare();

    await pressDownload(user);

    expect(await screen.findByRole("alert")).toHaveTextContent("A password is needed");
    const input = screen.getByLabelText("Password");
    await waitFor(() => expect(input).toHaveFocus());

    await user.type(input, `${PASSWORD}{Enter}`);

    expect(await screen.findByRole("heading", { level: 1, name: STARTED })).toBeInTheDocument();
    expect(downloadsOf(fetchMock).map(({ body }) => body)).toEqual([undefined, { password: PASSWORD }]);
  });
});

describe("SharePage refused downloads", () => {
  it.each([
    ...ENDED_LINKS,
    { status: 409, code: "file_unavailable", title: "This file could not be verified and was not released" },
  ])("replaces the offer with $title for a download answered $code", async ({ status, code, title }) => {
    const saved = stubBlobDownload();
    const fetchMock = serveShare({ download: () => failure(status, code) });
    const user = userEvent.setup();
    renderShare();

    await pressDownload(user);

    expect(await screen.findByRole("heading", { level: 1, name: title })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "report.pdf" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button")).not.toBeInTheDocument();
    expect(saved.createObjectURL).not.toHaveBeenCalled();
    expect(downloadsOf(fetchMock)).toHaveLength(1);
    expectNotOnPage(SHARE_TOKEN);
  });

  it("explains that nothing was released when the stored copy fails its check", async () => {
    stubBlobDownload();
    serveShare({ download: () => failure(409, "file_unavailable") });
    const user = userEvent.setup();
    renderShare();

    await pressDownload(user);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The stored copy did not pass its integrity check, so nothing was sent to you.");
    expect(alert).toHaveTextContent("Reference: req-test");
  });

  it.each(TROUBLES)(
    "keeps the offer after $name and downloads when the recipient tries again",
    async ({ respond, title }) => {
      const saved = stubBlobDownload();
      const fetchMock = serveShare({ download: troubleOnce(respond, fileResponse) });
      const user = userEvent.setup();
      renderShare();

      await pressDownload(user);

      expect(await screen.findByRole("alert")).toHaveTextContent(title);
      expect(screen.getByRole("heading", { level: 1, name: "report.pdf" })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Download" })).not.toHaveAttribute("aria-disabled");

      await pressDownload(user);

      expect(await screen.findByRole("heading", { level: 1, name: STARTED })).toBeInTheDocument();
      expect(saved.clicks).toHaveLength(1);
      expect(downloadsOf(fetchMock)).toHaveLength(2);
    },
  );
});
