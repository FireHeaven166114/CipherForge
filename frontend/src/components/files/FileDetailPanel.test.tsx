import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent, { type UserEvent } from "@testing-library/user-event";
import type { ComponentProps } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  FILE_ID,
  SHARE_ID,
  SHARE_TOKEN,
  failure,
  makeFileStatus,
  makeGate,
  makeShare,
  makeStoredFileDetail,
  only,
  serveVault,
  takeStrayRequests,
} from "../../test/filesFixtures";
import FileDetailPanel from "./FileDetailPanel";

const FILE_PATH = `/api/v1/files/${FILE_ID}`;
const SHARES_PATH = `${FILE_PATH}/shares`;
const REVOKE_PATH = `${SHARES_PATH}/${SHARE_ID}/revoke`;
const SHARE_TABLE = "Share links for this file, newest first";
const NO_LINKS = "No links have been made for this file yet. Create the first one below.";
const SHORT_SHARE = SHARE_ID.slice(0, 8);
const REVOKED_NOTICE = `Link ${SHORT_SHARE} was revoked. It no longer works.`;
const LINK = `${window.location.origin}/share/${SHARE_TOKEN}`;

afterEach(() => {
  expect(takeStrayRequests()).toEqual([]);
});

function renderPanel(props: Partial<ComponentProps<typeof FileDetailPanel>> = {}) {
  const onChanged = vi.fn<() => void>();
  const onClose = vi.fn<() => void>();
  render(
    <FileDetailPanel
      fileId={FILE_ID}
      status={makeFileStatus()}
      focusOnOpen={false}
      onChanged={onChanged}
      onClose={onClose}
      onDelete={vi.fn()}
      {...props}
    />,
  );
  return { onChanged, onClose };
}

const isRevoke = (method: string, path: string) => method === "POST" && path === REVOKE_PATH;

async function askToRevoke(user: UserEvent): Promise<HTMLElement> {
  await user.click(await screen.findByRole("button", { name: `Revoke link ${SHORT_SHARE}` }));
  return screen.getByRole("dialog", { name: "Revoke this link?" });
}

describe("FileDetailPanel new links", () => {
  it("makes a link, shows it once, and lists it with the activity it caused", async () => {
    const vault = serveVault();
    const user = userEvent.setup();
    const { onChanged } = renderPanel();
    expect(await screen.findByText(NO_LINKS)).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Create link" }));

    const panel = await screen.findByRole("region", { name: "Your new share link" });
    expect(within(panel).getByLabelText("Share link")).toHaveValue(LINK);
    expect(only(vault.changes())).toMatchObject({ method: "POST", path: SHARES_PATH });
    expect(onChanged).toHaveBeenCalledOnce();

    const table = await screen.findByRole("table", { name: SHARE_TABLE });
    expect(within(table).getByRole("button", { name: "Revoke link 00000001" })).toBeEnabled();
    expect(screen.queryByText(NO_LINKS)).not.toBeInTheDocument();
    expect(await screen.findByText("Link created")).toBeInTheDocument();
  });

  it("forgets the link once it is hidden, and puts focus back on the form's area", async () => {
    serveVault();
    const user = userEvent.setup();
    renderPanel();
    await user.click(await screen.findByRole("button", { name: "Create link" }));
    const panel = await screen.findByRole("region", { name: "Your new share link" });
    expect(screen.getByDisplayValue(LINK)).toBeInTheDocument();

    await user.click(within(panel).getByRole("button", { name: "Hide link" }));

    expect(screen.queryByRole("region", { name: "Your new share link" })).not.toBeInTheDocument();
    expect(screen.queryByDisplayValue(LINK)).not.toBeInTheDocument();
    expect(document.body.innerHTML).not.toContain(SHARE_TOKEN);
    expect(document.title).not.toContain(SHARE_TOKEN);
    expect(screen.getByRole("form", { name: "Create a share link" }).parentElement).toHaveFocus();
  });

  it("shows only the newest link when another is made before the first was hidden", async () => {
    serveVault();
    const user = userEvent.setup();
    renderPanel();
    await user.click(await screen.findByRole("button", { name: "Create link" }));
    await screen.findByRole("region", { name: "Your new share link" });

    const downloads = screen.getByLabelText("Maximum downloads");
    await user.clear(downloads);
    await user.type(downloads, "5");
    await user.click(screen.getByRole("button", { name: "Create link" }));

    const table = screen.getByRole("table", { name: SHARE_TABLE });
    await within(table).findByRole("button", { name: "Revoke link 00000002" });
    const panel = only(screen.getAllByRole("region", { name: "Your new share link" }));
    expect(within(panel).getByText("5 downloads")).toBeInTheDocument();
    expect(within(table).getByRole("button", { name: "Revoke link 00000001" })).toBeEnabled();
  });

  it("keeps the links it already has when they cannot be refreshed, and says so", async () => {
    let reads = 0;
    serveVault({
      files: [makeStoredFileDetail({ shares: [makeShare()] })],
      override: ({ method, path }) =>
        method === "GET" && path === FILE_PATH && ++reads === 2 ? failure(500, "internal_error") : undefined,
    });
    const user = userEvent.setup();
    renderPanel();
    const table = await screen.findByRole("table", { name: SHARE_TABLE });
    expect(within(table).getAllByRole("row")).toHaveLength(2);

    await user.click(screen.getByRole("button", { name: "Create link" }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The API reported an error");
    expect(within(table).getAllByRole("row")).toHaveLength(2);
    expect(screen.getByRole("region", { name: "Your new share link" })).toBeInTheDocument();

    await user.click(within(alert).getByRole("button", { name: "Try again" }));

    await waitFor(() => expect(within(table).getAllByRole("row")).toHaveLength(3));
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("FileDetailPanel revoking", () => {
  const withLink = () => [makeStoredFileDetail({ shares: [makeShare()] })];

  it("asks first, and sends nothing when the answer is no", async () => {
    const vault = serveVault({ files: withLink() });
    const user = userEvent.setup();
    const { onChanged } = renderPanel();

    const dialog = await askToRevoke(user);
    expect(dialog).toHaveTextContent(`Link ${SHORT_SHARE}: 0 of 3 downloads used.`);
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(vault.changes()).toEqual([]);
    expect(onChanged).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: `Revoke link ${SHORT_SHARE}` })).toBeEnabled();
  });

  it("revokes after confirmation, and shows the link as revoked, with a notice and in the activity", async () => {
    const vault = serveVault({ files: withLink() });
    const user = userEvent.setup();
    const { onChanged } = renderPanel();

    const dialog = await askToRevoke(user);
    await user.click(within(dialog).getByRole("button", { name: "Revoke link" }));

    const notice = (await screen.findByText(REVOKED_NOTICE)).closest<HTMLElement>("[role=status]");
    expect(notice).toHaveFocus();
    expect(only(vault.changes())).toMatchObject({ method: "POST", path: REVOKE_PATH });
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(onChanged).toHaveBeenCalledOnce();

    const row = only(within(screen.getByRole("table", { name: SHARE_TABLE })).getAllByRole("row").slice(1));
    await within(row).findByText("Revoked");
    expect(within(row).getByText("20-05-2026 03:00:00 PM IST")).toBeInTheDocument();
    expect(within(row).getByRole("button", { name: `Revoke link ${SHORT_SHARE}` })).toBeDisabled();
    expect(await screen.findByText("Link revoked")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Dismiss" }));

    expect(screen.queryByText(REVOKED_NOTICE)).not.toBeInTheDocument();
  });

  it("keeps the dialog open and says why when revoking fails, then revokes on the next try", async () => {
    let attempts = 0;
    const vault = serveVault({
      files: withLink(),
      override: ({ method, path }) =>
        isRevoke(method, path) && ++attempts === 1 ? failure(500, "internal_error") : undefined,
    });
    const user = userEvent.setup();
    const { onChanged } = renderPanel();
    const dialog = await askToRevoke(user);

    await user.click(within(dialog).getByRole("button", { name: "Revoke link" }));

    const alert = await within(dialog).findByRole("alert");
    expect(alert).toHaveTextContent("The link could not be revoked");
    expect(alert).toHaveTextContent("Reference: req-test");
    expect(onChanged).not.toHaveBeenCalled();

    await user.click(within(dialog).getByRole("button", { name: "Revoke link" }));

    expect(await screen.findByText(REVOKED_NOTICE)).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(vault.changes()).toHaveLength(2);
  });

  it("sends one revoke however often the button is pressed, and lets nothing close the dialog meanwhile", async () => {
    const gate = makeGate();
    const vault = serveVault({
      files: withLink(),
      override: async ({ method, path }) => {
        if (isRevoke(method, path)) await gate.passed;
        return undefined;
      },
    });
    const user = userEvent.setup();
    renderPanel();
    const dialog = await askToRevoke(user);
    await user.click(within(dialog).getByRole("button", { name: "Revoke link" }));

    const busy = await within(dialog).findByRole("button", { name: "Revoking…" });
    expect(busy).toHaveAttribute("aria-disabled", "true");
    await user.click(busy);
    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    await user.keyboard("{Escape}");

    expect(screen.getByRole("dialog", { name: "Revoke this link?" })).toBeInTheDocument();
    expect(vault.changes()).toHaveLength(1);

    gate.open();

    expect(await screen.findByText(REVOKED_NOTICE)).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(vault.changes()).toHaveLength(1);
  });
});

describe("FileDetailPanel missing file", () => {
  it("says the file is gone, and tells the page to reload its list and close", async () => {
    serveVault({ files: [] });
    const user = userEvent.setup();
    const { onChanged, onClose } = renderPanel();

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("This file no longer exists. It may have been deleted.");
    expect(onChanged).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Close" }));

    expect(onChanged).toHaveBeenCalledOnce();
    expect(onClose).toHaveBeenCalledOnce();
  });
});
