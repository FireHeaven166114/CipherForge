import { act, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { apiError, networkApi, requested, type NetworkCall } from "../../test/networkApi";
import { OTHER_SESSION_ID, SESSION_ID, makeSession, makeSessionPage } from "../../test/networkFixtures";
import SessionHistory from "./SessionHistory";

type Handlers = Parameters<typeof networkApi>[0];
type Props = ComponentProps<typeof SessionHistory>;

const SESSIONS_URL = "/api/v1/network/sessions?limit=5&offset=0";
const hang = () => new Promise<never>(() => undefined);

function setup(props: Partial<Props> = {}, handlers: Handlers = {}) {
  const fetchMock = networkApi(handlers);
  const onSelect = vi.fn();
  const onDelete = vi.fn();
  const initial: Props = { selectedId: null, intervalMs: 60_000, version: 0, onSelect, onDelete, ...props };
  const view = render(<SessionHistory {...initial} />);
  const rerender = (next: Partial<Props>) => view.rerender(<SessionHistory {...initial} {...next} />);
  return { fetchMock, onSelect, onDelete, rerender };
}

const live = makeSession({
  id: OTHER_SESSION_ID,
  source_kind: "live",
  interface: "eth0",
  source_label: null,
  status: "running",
  ended_at: null,
  duration_seconds: 12.4,
  packets_total: 1234,
  alerts_total: 0,
});

/** `count` sessions, numbered from the offset, on a list of `total`. */
function page(offset: number, count: number, total: number) {
  const items = Array.from({ length: count }, (_, index) => {
    const number = offset + index + 1;
    return makeSession({ id: `session-${number}`, source_label: `capture-${number}.pcap` });
  });
  return { items, total, limit: 5, offset };
}

const offsetOf = ({ url }: NetworkCall) => Number(url.searchParams.get("offset"));

/** A list of `total` sessions, served five at a time as the API does. */
function listOf(total: () => number) {
  return (call: NetworkCall) => {
    const offset = offsetOf(call);
    return page(offset, Math.max(0, Math.min(5, total() - offset)), total());
  };
}

describe("SessionHistory", () => {
  it("says that the sessions are being loaded", () => {
    setup({}, { sessions: hang });

    expect(screen.getByRole("heading", { level: 2, name: "Session history" })).toBeInTheDocument();
    expect(screen.getByText("Loading sessions…")).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("lists each session with its source, status, start time in IST, duration, packets and alerts", async () => {
    setup({}, { sessions: () => makeSessionPage([makeSession(), live]) });

    const table = await screen.findByRole("table", { name: "Capture sessions, newest first" });
    expect(
      within(table)
        .getAllByRole("columnheader")
        .map((header) => header.textContent),
    ).toEqual(["Source", "Status", "Started", "Duration", "Packets", "Alerts", "Actions"]);
    const [, file, interfaceRow] = within(table).getAllByRole("row");
    if (file === undefined || interfaceRow === undefined) throw new Error("Both rows are expected.");

    const fileSource = within(file).getByRole("rowheader");
    expect(fileSource).toHaveTextContent("Capture file");
    expect(fileSource).toHaveTextContent("sample.pcap");
    const [fileStatus, fileStart, fileDuration, filePackets, fileAlerts] = within(file).getAllByRole("cell");
    expect(fileStatus).toHaveTextContent("Completed");
    expect(fileStart?.textContent).toMatch(/^20-05-2026 02:00:00 PM IST/);
    expect(fileDuration).toHaveTextContent("1 min 30 s");
    expect(filePackets).toHaveTextContent("40");
    expect(fileAlerts).toHaveTextContent("1");

    const liveSource = within(interfaceRow).getByRole("rowheader");
    expect(liveSource).toHaveTextContent("Live capture");
    expect(liveSource).toHaveTextContent("eth0");
    const [liveStatus, , liveDuration, livePackets, liveAlerts] = within(interfaceRow).getAllByRole("cell");
    expect(liveStatus).toHaveTextContent("Running");
    expect(liveDuration).toHaveTextContent("12 s");
    expect(livePackets).toHaveTextContent("1,234");
    expect(liveAlerts).toHaveTextContent("0");
  });

  it("asks for the newest five sessions", async () => {
    const { fetchMock } = setup();

    await screen.findByRole("table");

    expect(requested(fetchMock)).toEqual([SESSIONS_URL]);
  });

  it("shows a name as text, whatever it contains", async () => {
    const name = "<img src=x onerror=alert(1)>.pcap";
    setup({}, { sessions: () => makeSessionPage([makeSession({ source_label: name })]) });

    expect(await screen.findByText(name)).toBeInTheDocument();
    expect(document.querySelector("img")).toBeNull();
  });

  it("falls back to a plain name for a session without one", async () => {
    setup(
      {},
      {
        sessions: () =>
          makeSessionPage([
            makeSession({ source_label: null }),
            makeSession({ id: OTHER_SESSION_ID, source_kind: "live", interface: null, source_label: null }),
          ]),
      },
    );

    expect(await screen.findByText("Unnamed file")).toBeInTheDocument();
    expect(screen.getByText("Unknown interface")).toBeInTheDocument();
  });

  describe("choosing a session", () => {
    it("opens the session that was picked", async () => {
      const { onSelect } = setup({}, { sessions: () => makeSessionPage([makeSession(), live]) });
      const user = userEvent.setup();

      await user.click(await screen.findByRole("button", { name: "View session eth0" }));

      expect(onSelect).toHaveBeenCalledExactlyOnceWith(OTHER_SESSION_ID);
    });

    it("marks the session that is open, and does not offer to open it again", async () => {
      const { onSelect } = setup(
        { selectedId: SESSION_ID },
        { sessions: () => makeSessionPage([makeSession(), live]) },
      );
      const user = userEvent.setup();

      const current = await screen.findByRole("button", { name: "Viewing session sample.pcap" });
      expect(current).toHaveAttribute("aria-current", "true");
      await user.click(current);
      expect(onSelect).not.toHaveBeenCalled();

      const other = screen.getByRole("button", { name: "View session eth0" });
      expect(other).not.toHaveAttribute("aria-current");
    });

    it("can be done from the keyboard", async () => {
      const { onSelect } = setup();
      const user = userEvent.setup();
      await screen.findByRole("table");

      await user.tab();
      expect(screen.getByRole("button", { name: "View session sample.pcap" })).toHaveFocus();
      await user.keyboard("{Enter}");

      expect(onSelect).toHaveBeenCalledWith(SESSION_ID);
    });
  });

  describe("deleting a session", () => {
    it("passes the session on, so the page can ask for confirmation", async () => {
      const { onDelete } = setup();
      const user = userEvent.setup();

      await user.click(await screen.findByRole("button", { name: "Delete session sample.pcap" }));

      expect(onDelete).toHaveBeenCalledExactlyOnceWith(
        expect.objectContaining({ id: SESSION_ID, source_label: "sample.pcap" }),
      );
    });

    it("cannot delete a session that is still running, and says why", async () => {
      const { onDelete } = setup({}, { sessions: () => makeSessionPage([live]) });
      const user = userEvent.setup();

      const button = await screen.findByRole("button", { name: "Delete session eth0" });
      expect(button).toHaveAttribute("aria-disabled", "true");
      expect(button).toHaveAccessibleDescription("A session cannot be deleted while it is running.");
      await user.click(button);

      expect(onDelete).not.toHaveBeenCalled();
    });
  });

  describe("paging", () => {
    it("shows where the page is in the list, and goes to the next page", async () => {
      const { fetchMock } = setup({}, { sessions: listOf(() => 12) });
      const user = userEvent.setup();

      expect(await screen.findByText("Showing 1–5 of 12")).toBeInTheDocument();
      expect(screen.getByRole("navigation", { name: "Session history pagination" })).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Previous" })).toBeDisabled();
      await user.click(screen.getByRole("button", { name: "Next" }));

      expect(await screen.findByText("Showing 6–10 of 12")).toBeInTheDocument();
      expect(screen.getByText("capture-6.pcap")).toBeInTheDocument();
      expect(screen.queryByText("capture-1.pcap")).not.toBeInTheDocument();
      expect(requested(fetchMock)).toEqual([SESSIONS_URL, "/api/v1/network/sessions?limit=5&offset=5"]);

      await user.click(screen.getByRole("button", { name: "Previous" }));
      expect(await screen.findByText("Showing 1–5 of 12")).toBeInTheDocument();
    });

    it("has no next page after the last one", async () => {
      setup({}, { sessions: listOf(() => 7) });
      const user = userEvent.setup();

      await user.click(await screen.findByRole("button", { name: "Next" }));

      expect(await screen.findByText("Showing 6–7 of 7")).toBeInTheDocument();
      expect(screen.getByRole("button", { name: "Next" })).toBeDisabled();
    });

    it("goes back to the new last page when deleting leaves the page it was on empty", async () => {
      let total = 11;
      const { fetchMock, rerender } = setup({}, { sessions: listOf(() => total) });
      const user = userEvent.setup();
      await user.click(await screen.findByRole("button", { name: "Next" }));
      await user.click(await screen.findByRole("button", { name: "Next" }));
      expect(await screen.findByText("Showing 11–11 of 11")).toBeInTheDocument();

      total = 10;
      rerender({ version: 1 });

      expect(await screen.findByText("Showing 6–10 of 10")).toBeInTheDocument();
      expect(screen.getByText("capture-10.pcap")).toBeInTheDocument();
      expect(requested(fetchMock).at(-1)).toBe("/api/v1/network/sessions?limit=5&offset=5");
    });

    it("shows the empty message, not a page of nothing, when the last session is deleted", async () => {
      let total = 6;
      const { rerender } = setup({}, { sessions: listOf(() => total) });
      const user = userEvent.setup();
      await user.click(await screen.findByRole("button", { name: "Next" }));
      expect(await screen.findByText("Showing 6–6 of 6")).toBeInTheDocument();

      total = 0;
      rerender({ version: 1 });

      expect(await screen.findByText(/^No sessions yet\./)).toBeInTheDocument();
      expect(screen.queryByRole("navigation", { name: "Session history pagination" })).not.toBeInTheDocument();
    });
  });

  describe("when there is nothing to list, or the list cannot be read", () => {
    it("explains how a session comes about when there are none", async () => {
      setup({}, { sessions: () => makeSessionPage([]) });

      expect(
        await screen.findByText(
          "No sessions yet. Start a live capture or analyse a PCAP file, and it will be listed here.",
        ),
      ).toBeInTheDocument();
      expect(screen.queryByRole("table")).not.toBeInTheDocument();
      expect(screen.queryByRole("navigation", { name: "Session history pagination" })).not.toBeInTheDocument();
    });

    it("shows the failure with the API's message, and tries again on request", async () => {
      let failing = true;
      const { fetchMock } = setup(
        {},
        { sessions: () => (failing ? apiError(500, "internal_error", "The database is down.") : makeSessionPage()) },
      );
      const user = userEvent.setup();

      const notice = await screen.findByRole("alert");
      expect(notice).toHaveTextContent("The database is down.");
      failing = false;
      await user.click(within(notice).getByRole("button", { name: "Try again" }));

      expect(await screen.findByRole("table")).toBeInTheDocument();
      expect(screen.queryByRole("alert")).not.toBeInTheDocument();
      expect(requested(fetchMock)).toHaveLength(2);
    });

    it("says in calm words that the role is missing", async () => {
      setup({}, { sessions: () => apiError(403, "forbidden", "No.") });

      expect(await screen.findByRole("alert")).toHaveTextContent("Network monitoring needs the security analyst role.");
    });
  });

  describe("staying current", () => {
    afterEach(() => {
      vi.useRealTimers();
    });

    async function flush(ms = 0): Promise<void> {
      await act(async () => {
        await vi.advanceTimersByTimeAsync(ms);
        for (let pass = 0; pass < 5; pass += 1) await vi.advanceTimersByTimeAsync(0);
      });
    }

    it("reads the list again on the interval it was given, and shows the new numbers", async () => {
      vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
      vi.useFakeTimers();
      let packets = 10;
      const { fetchMock } = setup(
        { intervalMs: 2000 },
        { sessions: () => makeSessionPage([makeSession({ packets_total: packets })]) },
      );
      await flush();
      const cells = () => within(screen.getAllByRole("row")[1] as HTMLElement).getAllByRole("cell");
      expect(cells()[3]).toHaveTextContent("10");

      packets = 25;
      await flush(1999);
      expect(requested(fetchMock)).toHaveLength(1);
      await flush(1);

      expect(requested(fetchMock)).toHaveLength(2);
      expect(cells()[3]).toHaveTextContent("25");
    });

    it("keeps the list on screen and says so when a later read fails", async () => {
      vi.spyOn(document, "visibilityState", "get").mockReturnValue("visible");
      vi.useFakeTimers();
      let failing = false;
      setup(
        { intervalMs: 2000 },
        { sessions: () => (failing ? apiError(503, "internal_error", "Down.") : makeSessionPage()) },
      );
      await flush();
      expect(screen.getByRole("table")).toBeInTheDocument();

      failing = true;
      await flush(2000);

      expect(screen.getByRole("table")).toBeInTheDocument();
      expect(screen.getByRole("alert")).toHaveTextContent(
        /The session list could not be refreshed\. It is from \d{2}:\d{2}:\d{2} (AM|PM) IST\./,
      );
    });

    it("reads the list again as soon as the page asks, without waiting for the interval", async () => {
      const { fetchMock, rerender } = setup();
      await screen.findByRole("table");
      expect(requested(fetchMock)).toHaveLength(1);

      rerender({ version: 1 });

      await vi.waitFor(() => expect(requested(fetchMock)).toHaveLength(2));
      rerender({ version: 1 });
      expect(requested(fetchMock)).toHaveLength(2);
    });
  });
});
