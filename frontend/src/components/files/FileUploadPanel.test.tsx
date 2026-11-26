import { fireEvent, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { failure, makeFileStatus, makeGate, only, serveVault, takeStrayRequests } from "../../test/filesFixtures";
import { renderRoute } from "../../test/router";
import type { FileFeatureStatus, StoredFile } from "../../types/files";
import FileUploadPanel from "./FileUploadPanel";

const FIRST_ID = "00000001-0000-4000-8000-000000000000";

afterEach(() => {
  expect(takeStrayRequests()).toEqual([]);
});

function renderPanel(status: FileFeatureStatus = makeFileStatus()) {
  const onUploaded = vi.fn<(file: StoredFile) => void>();
  renderRoute(
    <FileUploadPanel status={status} fileHref={(id) => `/files?file=${id}`} onUploaded={onUploaded} />,
    { url: "/files" },
  );
  return { onUploaded };
}

const chooser = () => screen.getByLabelText("choose a file");
const uploadButton = () => screen.getByRole("button", { name: "Encrypt and upload" });
const isUpload = (method: string, path: string) => method === "POST" && path === "/api/v1/files";

/** What a browser hands over when files are dropped. jsdom has no DataTransfer, so this is the part the panel reads. */
function dropOf(...files: File[]) {
  return { dataTransfer: { files: Object.assign([...files], { item: (index: number) => files[index] ?? null }) } };
}

function dropZone(): HTMLElement {
  const zone = screen.getByText("Drag a file here, or").closest("div");
  if (zone === null) throw new Error("The drop zone was not found.");
  return zone;
}

describe("FileUploadPanel", () => {
  it("explains what happens to a file, and what the server allows", () => {
    renderPanel(makeFileStatus({ max_file_size_bytes: 5 * 1024 * 1024 }));

    expect(screen.getByText(/encrypted on the server with AES-256-GCM before it is stored/)).toBeInTheDocument();
    expect(screen.getByText(/the people you share it with never receive a key/)).toBeInTheDocument();
    expect(screen.getByText("Largest file: 5.00 MB.")).toBeInTheDocument();
    expect(screen.getByText("No file chosen.")).toBeInTheDocument();
  });

  it("asks for a file when the button is pressed with none chosen, and sends nothing", async () => {
    const vault = serveVault({ files: [] });
    const user = userEvent.setup();
    renderPanel();

    await user.click(uploadButton());

    expect(screen.getByText("Choose a file to upload first.")).toBeInTheDocument();
    expect(chooser()).toHaveFocus();
    expect(chooser()).toBeInvalid();
    expect(vault.requests()).toEqual([]);
  });

  it("refuses an empty file, saying why, and sends nothing", async () => {
    const vault = serveVault({ files: [] });
    const user = userEvent.setup();
    renderPanel();

    await user.upload(chooser(), new File([], "empty.txt"));
    await user.click(uploadButton());

    expect(screen.getByText("That file is empty, so there is nothing to encrypt.")).toBeInTheDocument();
    expect(chooser()).toHaveAccessibleDescription(expect.stringContaining("nothing to encrypt"));
    expect(chooser()).toHaveFocus();
    expect(vault.changes()).toEqual([]);
  });

  it("tells its page what was stored, and offers to share it at the address the page chose", async () => {
    serveVault({ files: [] });
    const user = userEvent.setup();
    const { onUploaded } = renderPanel();
    await user.upload(chooser(), new File(["data"], "a.txt"));

    await user.click(uploadButton());

    expect(await screen.findByRole("link", { name: "Share this file" })).toHaveAttribute(
      "href",
      `/files?file=${FIRST_ID}`,
    );
    expect(onUploaded).toHaveBeenCalledExactlyOnceWith(
      expect.objectContaining({ id: FIRST_ID, name: "a.txt", size_bytes: 4 }),
    );
    expect(screen.getByText("No file chosen.")).toBeInTheDocument();
  });

  it("forgets the last outcome as soon as another file is chosen", async () => {
    let attempts = 0;
    serveVault({
      files: [],
      override: ({ method, path }) =>
        isUpload(method, path) && ++attempts === 1 ? failure(503, "feature_not_configured") : undefined,
    });
    const user = userEvent.setup();
    renderPanel();
    await user.upload(chooser(), new File(["data"], "a.txt"));
    await user.click(uploadButton());
    await screen.findByRole("alert");

    await user.upload(chooser(), new File(["more data"], "b.txt"));

    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(screen.getByText("b.txt")).toBeInTheDocument();

    await user.click(uploadButton());
    await screen.findByText("is encrypted and stored (9 B).");

    await user.upload(chooser(), new File(["x"], "c.txt"));

    expect(screen.queryByText("is encrypted and stored (9 B).")).not.toBeInTheDocument();
  });

  it("takes a dropped file as the chosen one, and sends it only when the button is pressed", async () => {
    const vault = serveVault({ files: [] });
    const user = userEvent.setup();
    const { onUploaded } = renderPanel();

    fireEvent.drop(dropZone(), dropOf(new File(["data"], "dropped.txt")));

    expect(screen.getByText("dropped.txt")).toBeInTheDocument();
    expect(vault.changes()).toEqual([]);

    await user.click(uploadButton());

    await waitFor(() => expect(onUploaded).toHaveBeenCalledOnce());
    expect(only(vault.changes()).headers.get("X-File-Name")).toBe("dropped.txt");
  });

  it("takes one file at a time, and says so when several are dropped", () => {
    renderPanel();

    fireEvent.drop(dropZone(), dropOf(new File(["a"], "a.txt"), new File(["b"], "b.txt")));

    expect(screen.getByText("Choose one file at a time.")).toBeInTheDocument();
    expect(screen.getByText("No file chosen.")).toBeInTheDocument();
  });

  it("ignores a drop while a file is being encrypted", async () => {
    const gate = makeGate();
    const vault = serveVault({
      files: [],
      override: async ({ method, path }) => {
        if (isUpload(method, path)) await gate.passed;
        return undefined;
      },
    });
    const user = userEvent.setup();
    const { onUploaded } = renderPanel();
    await user.upload(chooser(), new File(["data"], "first.txt"));
    await user.click(uploadButton());
    await screen.findByRole("button", { name: "Encrypting and uploading…" });

    fireEvent.drop(dropZone(), dropOf(new File(["more"], "second.txt")));

    expect(screen.getByText("first.txt")).toBeInTheDocument();
    expect(screen.queryByText("second.txt")).not.toBeInTheDocument();

    gate.open();

    await waitFor(() => expect(onUploaded).toHaveBeenCalledOnce());
    expect(vault.changes()).toHaveLength(1);
  });

  it("is switched off without a master key: nothing can be chosen, dropped or sent", async () => {
    const vault = serveVault({ files: [] });
    const user = userEvent.setup();
    renderPanel(makeFileStatus({ configured: false }));

    expect(screen.getByText("Uploading is switched off until the server has a master key.")).toBeInTheDocument();
    expect(chooser()).toBeDisabled();
    expect(uploadButton()).toBeDisabled();

    fireEvent.drop(dropZone(), dropOf(new File(["data"], "dropped.txt")));
    await user.click(uploadButton());

    expect(screen.getByText("No file chosen.")).toBeInTheDocument();
    expect(vault.requests()).toEqual([]);
  });
});
