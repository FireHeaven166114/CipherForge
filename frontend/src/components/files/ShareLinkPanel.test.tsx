import { fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  SHARE_TOKEN,
  makeShare,
  removeClipboardStubs,
  stubClipboard,
  stubExecCommand,
} from "../../test/filesFixtures";
import type { Share } from "../../types/files";
import ShareLinkPanel from "./ShareLinkPanel";

const LINK = `${window.location.origin}/share/${SHARE_TOKEN}`;

afterEach(removeClipboardStubs);

function renderPanel(share: Share = makeShare()) {
  const onDismiss = vi.fn<() => void>();
  render(<ShareLinkPanel link={LINK} share={share} onDismiss={onDismiss} />);
  return { onDismiss, panel: screen.getByRole("region", { name: "Your new share link" }) };
}

describe("ShareLinkPanel", () => {
  it("shows the link to read and select, takes focus, and warns that it is shown only once", () => {
    const { panel } = renderPanel();

    expect(within(panel).getByRole("heading", { name: "Your new share link" })).toHaveFocus();
    const input = within(panel).getByLabelText("Share link");
    expect(input).toHaveValue(LINK);
    expect(input).toHaveAttribute("readonly");
    expect(panel).toHaveTextContent("Copy it now: this link is shown only once.");
    expect(panel).toHaveTextContent("cannot be shown again");
  });

  it("says what the link gives away: the file to anyone, and never the key", () => {
    const { panel } = renderPanel(makeShare({ max_downloads: 3 }));

    expect(panel).toHaveTextContent(
      "Anyone who has this link can download the file, with no password. The encryption key is not part of the link.",
    );
    expect(within(panel).getByText("21-05-2026 02:00:00 PM IST")).toBeInTheDocument();
    expect(within(panel).getByText("3 downloads")).toBeInTheDocument();
    expect(within(panel).getByText("None")).toBeInTheDocument();
  });

  it("says the password is needed as well when the link has one", () => {
    const { panel } = renderPanel(makeShare({ password_protected: true, max_downloads: 1 }));

    expect(panel).toHaveTextContent("as long as they also know the password you set");
    expect(within(panel).getByText("Needed to download")).toBeInTheDocument();
    expect(within(panel).getByText("1 download")).toBeInTheDocument();
    expect(panel).not.toHaveTextContent("with no password");
  });

  it("selects the whole link when it is focused, ready to copy by hand", () => {
    const { panel } = renderPanel();
    const input = within(panel).getByLabelText<HTMLInputElement>("Share link");

    fireEvent.focus(input);

    expect(input.selectionStart).toBe(0);
    expect(input.selectionEnd).toBe(LINK.length);
  });

  it("puts the link on the clipboard and says so", async () => {
    const user = userEvent.setup();
    const writeText = stubClipboard();
    const { panel } = renderPanel();

    await user.click(within(panel).getByRole("button", { name: "Copy link" }));

    expect(writeText).toHaveBeenCalledExactlyOnceWith(LINK);
    expect(await within(panel).findByText("The link is on your clipboard.")).toBeInTheDocument();
    expect(within(panel).getByRole("button", { name: "Copied" })).toBeInTheDocument();
  });

  it("selects the link and copies it the old way when the clipboard refuses", async () => {
    const user = userEvent.setup();
    stubClipboard(() => Promise.reject(new Error("denied")));
    const execCommand = stubExecCommand(true);
    const { panel } = renderPanel();
    const input = within(panel).getByLabelText<HTMLInputElement>("Share link");

    await user.click(within(panel).getByRole("button", { name: "Copy link" }));

    expect(await within(panel).findByText("The link is on your clipboard.")).toBeInTheDocument();
    expect(execCommand).toHaveBeenCalledExactlyOnceWith("copy");
    expect(input.selectionStart).toBe(0);
    expect(input.selectionEnd).toBe(LINK.length);
  });

  it("leaves the link selected and says how to copy it when nothing else works", async () => {
    const user = userEvent.setup();
    removeClipboardStubs();
    stubExecCommand(false);
    const { panel } = renderPanel();
    const input = within(panel).getByLabelText<HTMLInputElement>("Share link");

    await user.click(within(panel).getByRole("button", { name: "Copy link" }));

    expect(
      await within(panel).findByText(
        "Your browser would not copy it. The link is selected: press Ctrl+C (Command+C on a Mac) to copy it.",
      ),
    ).toBeInTheDocument();
    expect(within(panel).getByRole("button", { name: "Copy link" })).toBeInTheDocument();
    expect(input).toHaveFocus();
    expect(input.selectionEnd).toBe(LINK.length);
  });

  it("hides the link on request, and says that hiding is not revoking", async () => {
    const user = userEvent.setup();
    const { onDismiss, panel } = renderPanel();

    expect(panel).toHaveTextContent("Hiding it does not revoke it. Once hidden, the link cannot be shown again.");
    await user.click(within(panel).getByRole("button", { name: "Hide link" }));

    expect(onDismiss).toHaveBeenCalledOnce();
  });
});
