import { screen, waitFor, within } from "@testing-library/react";
import userEvent, { type UserEvent } from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import {
  FILE_ID,
  OTHER_FILE_ID,
  SHARE_ID,
  SHARE_TOKEN,
  type Vault,
  failure,
  makeActivityItem,
  makeFileStatus,
  makeGate,
  makeShare,
  makeStoredFileDetail,
  only,
  removeClipboardStubs,
  serveVault,
  takeStrayRequests,
} from "../test/filesFixtures";
import { hangingFetch, stubFetch } from "../test/http";
import { renderRoute } from "../test/router";
import FilesPage from "./FilesPage";

const FILE_TABLE = "Encrypted files, newest first";
const SHARE_TABLE = "Share links for this file, newest first";
const ACTIVITY_TABLE = "Activity for this file, newest first";
const EMPTY_LIST = "No files have been uploaded yet. Upload one above to encrypt it and share it.";

afterEach(() => {
  removeClipboardStubs();
  // A page that asks for something the API does not have would show a failure, not crash.
  expect(takeStrayRequests()).toEqual([]);
});

function renderPage(url = "/files") {
  return renderRoute(<FilesPage />, { url });
}

function address(): string {
  return screen.getByTestId("location").textContent ?? "";
}

function rowOf(name: string): HTMLElement {
  const row = screen.getByRole("link", { name }).closest("tr");
  if (row === null) throw new Error(`No table row holds a link named ${name}.`);
  return row;
}

/** Each GET of the list, in order. */
function listReads(vault: Vault) {
  return vault.requests().filter((request) => request.method === "GET" && request.path === "/api/v1/files");
}

/** Answers one matching request with a failure, then lets the vault answer as usual. */
function failOnce(matches: (method: string, path: string) => boolean, response: () => Response) {
  let pending = true;
  return ({ method, path }: { method: string; path: string }) => {
    if (!pending || !matches(method, path)) return undefined;
    pending = false;
    return response();
  };
}

function manyFiles(count: number) {
  return Array.from({ length: count }, (_, index) =>
    makeStoredFileDetail({ id: `file-${index + 1}`, name: `file-${index + 1}.txt` }),
  );
}

const isUpload = (method: string, path: string) => method === "POST" && path === "/api/v1/files";
const isDeleteOfFile = (method: string, path: string) =>
  method === "DELETE" && path === `/api/v1/files/${FILE_ID}`;

async function chooseAndUpload(user: UserEvent, file: File) {
  await user.upload(screen.getByLabelText("choose a file"), file);
  await user.click(screen.getByRole("button", { name: "Encrypt and upload" }));
}

/** The status region that holds a message, which is where the page puts focus after a change. */
async function findNotice(text: string): Promise<HTMLElement> {
  const notice = (await screen.findByText(text)).closest<HTMLElement>("[role=status]");
  if (notice === null) throw new Error(`"${text}" is not inside a status region.`);
  return notice;
}

describe("FilesPage feature status", () => {
  it("names the page and says it is checking while the server's limits load", () => {
    stubFetch(hangingFetch());
    renderPage();

    expect(screen.getByRole("heading", { level: 1, name: "Files" })).toBeInTheDocument();
    expect(screen.getByText("Checking whether encrypted files are available…")).toBeInTheDocument();
    expect(document.title).toBe("Files · CipherForge");
    expect(screen.queryByRole("button", { name: "Encrypt and upload" })).not.toBeInTheDocument();
  });

  it("reports a failure with its reference and tries again on request", async () => {
    serveVault({
      override: failOnce(
        (_method, path) => path === "/api/v1/files/status",
        () => failure(500, "internal_error"),
      ),
    });
    const user = userEvent.setup();
    renderPage();

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The API reported an error");
    expect(alert).toHaveTextContent("Reference: req-test");

    await user.click(within(alert).getByRole("button", { name: "Try again" }));

    expect(await screen.findByRole("heading", { name: "Upload a file" })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("says what is missing when the server has no master key, and turns uploading and sharing off", async () => {
    serveVault({ status: makeFileStatus({ configured: false }) });
    renderPage(`/files?file=${FILE_ID}`);

    const note = await screen.findByRole("note");
    expect(note).toHaveTextContent("Encrypted files are not set up on this server");
    expect(note).toHaveTextContent("CIPHERFORGE_MASTER_KEY");
    expect(note).toHaveTextContent("docs/");

    expect(screen.getByLabelText("choose a file")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Encrypt and upload" })).toBeDisabled();
    expect(screen.getByText("Uploading is switched off until the server has a master key.")).toBeInTheDocument();

    // Files stored earlier can still be seen, and a link cannot be made for them.
    expect(await screen.findByRole("table", { name: FILE_TABLE })).toBeInTheDocument();
    expect(await screen.findByText("Sharing is switched off until the server has a master key.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Create link" })).toBeDisabled();
  });
});

describe("FilesPage list", () => {
  it("says so when nothing has been uploaded", async () => {
    serveVault({ files: [] });
    renderPage();

    expect(await screen.findByText(EMPTY_LIST)).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("shows a name as plain text, with its size, upload time in IST, state and links", async () => {
    const hostile = "<img src=x onerror=alert(1)>.txt";
    serveVault({
      files: [
        makeStoredFileDetail({
          id: FILE_ID,
          name: hostile,
          size_bytes: 2048,
          shares: [makeShare({ id: SHARE_ID }), makeShare({ id: OTHER_FILE_ID, status: "revoked" })],
        }),
        makeStoredFileDetail({ id: OTHER_FILE_ID, name: "broken.bin", size_bytes: 10 * 1024 * 1024, status: "corrupt" }),
      ],
    });
    renderPage();

    await screen.findByRole("table", { name: FILE_TABLE });
    expect(document.querySelector("img")).toBeNull();
    expect(screen.getByText("2 files stored")).toBeInTheDocument();

    const row = rowOf(hostile);
    expect(within(row).getByText("2.00 KB")).toBeInTheDocument();
    expect(within(row).getByText("20-05-2026 02:00:00 PM IST")).toBeInTheDocument();
    expect(within(row).getByText("Ready")).toBeInTheDocument();
    expect(within(row).getByText("1 active of 2 links")).toBeInTheDocument();

    const broken = rowOf("broken.bin");
    expect(within(broken).getByText("10.0 MB")).toBeInTheDocument();
    expect(within(broken).getByText("Integrity problem")).toBeInTheDocument();
    expect(within(broken).getByText("Cannot be shared")).toBeInTheDocument();
  });

  it("pages through the list and keeps the page in the address", async () => {
    const vault = serveVault({ files: manyFiles(12) });
    const user = userEvent.setup();
    renderPage();

    expect(await screen.findByText("Showing 1–10 of 12")).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: /^file-\d+\.txt$/ })).toHaveLength(10);

    await user.click(screen.getByRole("button", { name: "Next" }));

    expect(await screen.findByText("Showing 11–12 of 12")).toBeInTheDocument();
    expect(address()).toBe("/files?page=2");
    expect(screen.getAllByRole("link", { name: /^file-\d+\.txt$/ })).toHaveLength(2);
    const reads = listReads(vault);
    expect(reads.map((read) => read.query.get("offset"))).toEqual(["0", "10"]);
    expect(reads.map((read) => read.query.get("limit"))).toEqual(["10", "10"]);
  });

  it("offers the first page when the address is past the end", async () => {
    serveVault();
    const user = userEvent.setup();
    renderPage("/files?page=9");

    expect(await screen.findByText("This page has no files.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Go to the first page" }));

    expect(await screen.findByRole("table", { name: FILE_TABLE })).toBeInTheDocument();
    expect(address()).toBe("/files");
  });

  it("explains a list that failed to load and loads it again on request", async () => {
    serveVault({
      override: failOnce(
        (method, path) => method === "GET" && path === "/api/v1/files",
        () => failure(500, "internal_error"),
      ),
    });
    const user = userEvent.setup();
    renderPage();

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Reference: req-test");
    await user.click(within(alert).getByRole("button", { name: "Try again" }));

    expect(await screen.findByRole("table", { name: FILE_TABLE })).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});

describe("FilesPage file details", () => {
  it("opens the file named in the address with its links and activity, leaving focus alone", async () => {
    serveVault({
      files: [makeStoredFileDetail({ shares: [makeShare()] })],
      activity: { [FILE_ID]: [makeActivityItem({ action: "SHARE_CREATE", share_id: SHARE_ID })] },
    });
    renderPage(`/files?file=${FILE_ID}`);

    const heading = await screen.findByRole("heading", { level: 3, name: "report.pdf" });
    expect(heading).not.toHaveFocus();
    expect(within(screen.getByRole("table", { name: SHARE_TABLE })).getAllByRole("row")).toHaveLength(2);
    expect(await screen.findByRole("table", { name: ACTIVITY_TABLE })).toBeInTheDocument();
    expect(screen.getByText("AES-256-GCM")).toBeInTheDocument();
    // Once in the file's row and once in its summary.
    expect(screen.getAllByText("1 active of 1 link")).toHaveLength(2);
  });

  it("opens a file from its row, moves focus to it, and gives focus back to the row on close", async () => {
    serveVault();
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("link", { name: "report.pdf" }));

    const heading = await screen.findByRole("heading", { level: 3, name: "report.pdf" });
    expect(address()).toBe(`/files?file=${FILE_ID}`);
    expect(heading).toHaveFocus();
    expect(screen.getByRole("link", { name: "report.pdf" })).toHaveAttribute("aria-current", "true");

    await user.click(screen.getByRole("button", { name: "Close" }));

    expect(address()).toBe("/files");
    expect(screen.queryByRole("heading", { level: 3, name: "report.pdf" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "report.pdf" })).toHaveFocus();
  });

  it("says a file is gone when the address names one that does not exist", async () => {
    serveVault({ files: [] });
    const user = userEvent.setup();
    renderPage(`/files?file=${OTHER_FILE_ID}`);

    expect(await screen.findByText("This file no longer exists. It may have been deleted.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Close" }));

    expect(address()).toBe("/files");
    expect(screen.queryByText("This file no longer exists. It may have been deleted.")).not.toBeInTheDocument();
  });

  it("explains a file that could not be loaded and tries again on request", async () => {
    serveVault({
      override: failOnce(
        (method, path) => method === "GET" && path === `/api/v1/files/${FILE_ID}`,
        () => failure(500, "internal_error"),
      ),
    });
    const user = userEvent.setup();
    renderPage(`/files?file=${FILE_ID}`);

    const alert = await screen.findByRole("alert");
    await user.click(within(alert).getByRole("button", { name: "Try again" }));

    expect(await screen.findByRole("heading", { level: 3, name: "report.pdf" })).toBeInTheDocument();
  });

  it("ignores an address that names something that cannot be a file id", async () => {
    const vault = serveVault();
    renderPage("/files?file=..%2F..%2Fsecret");

    await screen.findByRole("table", { name: FILE_TABLE });

    expect(screen.queryByRole("heading", { level: 3 })).not.toBeInTheDocument();
    expect(vault.requests().map((request) => request.path)).toEqual(["/api/v1/files/status", "/api/v1/files"]);
  });

  it("explains a file that failed its integrity check and does not offer to share it", async () => {
    const vault = serveVault({ files: [makeStoredFileDetail({ name: "broken.bin", status: "corrupt" })] });
    const user = userEvent.setup();
    renderPage(`/files?file=${FILE_ID}`);

    const note = await screen.findByRole("note");
    expect(note).toHaveTextContent("Integrity problem");
    expect(note).toHaveTextContent("it cannot be shared");

    const form = screen.getByRole("form", { name: "Create a share link" });
    expect(within(form).getByText("This file failed its integrity check, so it cannot be shared.")).toBeInTheDocument();
    expect(within(form).getByRole("button", { name: "Create link" })).toBeDisabled();
    expect(within(form).getByLabelText("Maximum downloads")).toBeDisabled();
    await user.click(within(form).getByRole("button", { name: "Create link" }));
    expect(vault.changes()).toEqual([]);

    // The file can still be deleted, which is how a bad copy is replaced.
    expect(screen.getByRole("button", { name: "Delete file" })).toBeEnabled();
  });
});

describe("FilesPage activity", () => {
  it("says so when nothing has been recorded", async () => {
    serveVault();
    renderPage(`/files?file=${FILE_ID}`);

    expect(await screen.findByText("Nothing has been recorded for this file yet.")).toBeInTheDocument();
    expect(screen.queryByRole("table", { name: ACTIVITY_TABLE })).not.toBeInTheDocument();
  });

  it("loads the newest events again when asked", async () => {
    const activity = { [FILE_ID]: [makeActivityItem({ action: "FILE_CREATE" })] };
    const vault = serveVault({ activity });
    const user = userEvent.setup();
    renderPage(`/files?file=${FILE_ID}`);

    const table = await screen.findByRole("table", { name: ACTIVITY_TABLE });
    expect(within(table).getAllByRole("row")).toHaveLength(2);

    activity[FILE_ID].unshift(makeActivityItem({ action: "SHARE_DOWNLOAD", share_id: SHARE_ID }));
    await user.click(screen.getByRole("button", { name: "Refresh activity" }));

    await within(table).findByText("File downloaded");
    expect(within(table).getAllByRole("row")).toHaveLength(3);
    const reads = vault.requests().filter((request) => request.path === `/api/v1/files/${FILE_ID}/activity`);
    expect(reads).toHaveLength(2);
  });

  it("keeps the rest of the file's details when its activity cannot be loaded", async () => {
    serveVault({
      override: failOnce(
        (method, path) => method === "GET" && path === `/api/v1/files/${FILE_ID}/activity`,
        () => failure(500, "internal_error"),
      ),
    });
    const user = userEvent.setup();
    renderPage(`/files?file=${FILE_ID}`);

    const alert = await screen.findByRole("alert");
    expect(screen.getByRole("heading", { level: 3, name: "report.pdf" })).toBeInTheDocument();
    expect(screen.getByRole("form", { name: "Create a share link" })).toBeInTheDocument();

    await user.click(within(alert).getByRole("button", { name: "Try again" }));

    expect(await screen.findByText("Nothing has been recorded for this file yet.")).toBeInTheDocument();
    expect(only(screen.queryAllByRole("heading", { level: 3 }))).toHaveTextContent("report.pdf");
  });
});

describe("FilesPage upload", () => {
  it("encrypts the chosen file when the button is pressed, then lists it and offers to share it", async () => {
    const vault = serveVault({ files: [] });
    const user = userEvent.setup();
    renderPage();
    await screen.findByText(EMPTY_LIST);

    const file = new File(["quarterly figures"], "résumé & notes.txt", { type: "text/plain" });
    await user.upload(screen.getByLabelText("choose a file"), file);

    // Choosing a file sends nothing: the button does.
    expect(screen.getByText("résumé & notes.txt")).toBeInTheDocument();
    expect(vault.changes()).toEqual([]);

    await user.click(screen.getByRole("button", { name: "Encrypt and upload" }));

    const stored = await findNotice("is encrypted and stored (17 B).");
    expect(within(stored).getByText("résumé & notes.txt")).toBeInTheDocument();
    const sent = only(vault.changes());
    expect(sent.method).toBe("POST");
    expect(sent.path).toBe("/api/v1/files");
    expect(sent.headers.get("Content-Type")).toBe("application/octet-stream");
    expect(sent.headers.get("X-File-Name")).toBe("r%C3%A9sum%C3%A9%20%26%20notes.txt");
    expect(sent.body).toBe(file);

    // The list is read again and holds the file; the choice is cleared for the next one.
    expect(await screen.findByRole("link", { name: "résumé & notes.txt" })).toBeInTheDocument();
    expect(listReads(vault)).toHaveLength(2);
    expect(screen.queryByText(EMPTY_LIST)).not.toBeInTheDocument();
    expect(screen.getByText("No file chosen.")).toBeInTheDocument();

    await user.click(within(stored).getByRole("link", { name: "Share this file" }));

    expect(await screen.findByRole("heading", { level: 3, name: "résumé & notes.txt" })).toBeInTheDocument();
    expect(address()).toBe("/files?file=00000001-0000-4000-8000-000000000000");
  });

  it("refuses a file over the server's limit without sending any of it", async () => {
    const vault = serveVault({ files: [], status: makeFileStatus({ max_file_size_bytes: 1024 }) });
    const user = userEvent.setup();
    renderPage();
    await screen.findByText(EMPTY_LIST);
    expect(screen.getByText("Largest file: 1.00 KB.")).toBeInTheDocument();

    await user.upload(screen.getByLabelText("choose a file"), new File([new Uint8Array(2048)], "big.bin"));

    const input = screen.getByLabelText("choose a file");
    expect(screen.getByText("That file is 2.00 KB, which is over the 1.00 KB limit.")).toBeInTheDocument();
    expect(input).toBeInvalid();

    await user.click(screen.getByRole("button", { name: "Encrypt and upload" }));

    expect(vault.changes()).toEqual([]);
    expect(input).toHaveFocus();
  });

  interface UploadFailure {
    when: string;
    status: number;
    code: string;
    headers?: Record<string, string>;
    message: string;
  }

  const UPLOAD_FAILURES: UploadFailure[] = [
    {
      when: "the file is over the server's limit",
      status: 413,
      code: "file_too_large",
      message: "That file is larger than the 25.0 MB limit. Choose a smaller file.",
    },
    {
      when: "the server refuses the file name",
      status: 422,
      code: "invalid_filename",
      message: "That file name cannot be used. Rename the file and try again.",
    },
    {
      when: "the server refuses the content type",
      status: 415,
      code: "unsupported_media_type",
      message: "The server refused this kind of upload. Reload the page and try again.",
    },
    {
      when: "the server has no master key",
      status: 503,
      code: "feature_not_configured",
      message: "Encrypted files are not set up on this server. An administrator must set CIPHERFORGE_MASTER_KEY.",
    },
    {
      when: "too many requests were made",
      status: 429,
      code: "rate_limited",
      headers: { "Retry-After": "30" },
      message: "Too many requests. Try again in 30 seconds.",
    },
  ];

  it.each(UPLOAD_FAILURES)("says what to do when $when", async ({ status, code, headers, message }) => {
    const vault = serveVault({
      files: [],
      override: ({ method, path }) => (isUpload(method, path) ? failure(status, code, headers) : undefined),
    });
    const user = userEvent.setup();
    renderPage();
    await screen.findByText(EMPTY_LIST);

    await chooseAndUpload(user, new File(["data"], "a.txt"));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The upload failed");
    expect(alert).toHaveTextContent(message);
    expect(alert).toHaveTextContent("Reference: req-test");
    // Nothing was stored, so the list is not read again, and the file stays chosen for another try.
    expect(listReads(vault)).toHaveLength(1);
    expect(screen.getByText("a.txt")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Encrypt and upload" })).not.toHaveAttribute("aria-disabled");
  });

  it("lets the same file be sent again after a failure", async () => {
    const vault = serveVault({
      files: [],
      override: failOnce(isUpload, () => failure(503, "feature_not_configured")),
    });
    const user = userEvent.setup();
    renderPage();
    await screen.findByText(EMPTY_LIST);
    await chooseAndUpload(user, new File(["data"], "a.txt"));
    await screen.findByRole("alert");

    await user.click(screen.getByRole("button", { name: "Encrypt and upload" }));

    expect(await findNotice("is encrypted and stored (4 B).")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(vault.changes()).toHaveLength(2);
  });

  it("sends one upload however often the button is pressed, and says it is working", async () => {
    const gate = makeGate();
    const vault = serveVault({
      files: [],
      override: async ({ method, path }) => {
        if (isUpload(method, path)) await gate.passed;
        return undefined;
      },
    });
    const user = userEvent.setup();
    renderPage();
    await screen.findByText(EMPTY_LIST);
    await user.upload(screen.getByLabelText("choose a file"), new File(["data"], "a.txt"));

    await user.dblClick(screen.getByRole("button", { name: "Encrypt and upload" }));

    const busy = await screen.findByRole("button", { name: "Encrypting and uploading…" });
    expect(busy).toHaveAttribute("aria-disabled", "true");
    expect(screen.getByText("Encrypting and uploading. Large files take a while.")).toBeInTheDocument();
    expect(screen.getByLabelText("choose a file")).toBeDisabled();
    await user.click(busy);
    expect(vault.changes()).toHaveLength(1);

    gate.open();

    expect(await findNotice("is encrypted and stored (4 B).")).toBeInTheDocument();
    expect(vault.changes()).toHaveLength(1);
    expect(screen.getByRole("button", { name: "Encrypt and upload" })).not.toHaveAttribute("aria-disabled");
  });

  it("returns to the first page after an upload, where the newest file is", async () => {
    const vault = serveVault({ files: manyFiles(12) });
    const user = userEvent.setup();
    renderPage("/files?page=2");
    await screen.findByRole("link", { name: "file-11.txt" });

    await chooseAndUpload(user, new File(["data"], "fresh.txt"));

    expect(await screen.findByRole("link", { name: "fresh.txt" })).toBeInTheDocument();
    expect(address()).toBe("/files");
    expect(listReads(vault).map((read) => read.query.get("offset"))).toEqual(["10", "0"]);
  });
});

describe("FilesPage deleting", () => {
  it("deletes a file only after confirmation, and says what stopped working", async () => {
    const vault = serveVault({
      files: [
        makeStoredFileDetail({ shares: [makeShare()] }),
        makeStoredFileDetail({ id: OTHER_FILE_ID, name: "notes.txt" }),
      ],
    });
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: "Delete report.pdf" }));
    const dialog = screen.getByRole("dialog", { name: "Delete this file?" });
    expect(dialog).toHaveTextContent("report.pdf");
    expect(dialog).toHaveTextContent("Every share link made for it stops working immediately, including 1 active link.");
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveFocus();

    await user.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(vault.changes()).toEqual([]);

    await user.click(screen.getByRole("button", { name: "Delete report.pdf" }));
    const confirm = within(screen.getByRole("dialog", { name: "Delete this file?" }));
    await user.click(confirm.getByRole("button", { name: "Delete file" }));

    const notice = await findNotice("report.pdf was deleted. Every link made for it stopped working.");
    expect(notice).toHaveFocus();
    expect(only(vault.changes())).toMatchObject({ method: "DELETE", path: `/api/v1/files/${FILE_ID}` });
    await waitFor(() => expect(screen.queryByRole("link", { name: "report.pdf" })).not.toBeInTheDocument());
    expect(screen.getByRole("link", { name: "notes.txt" })).toBeInTheDocument();
    expect(listReads(vault)).toHaveLength(2);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    await user.click(within(notice).getByRole("button", { name: "Dismiss" }));
    expect(screen.queryByText("report.pdf was deleted. Every link made for it stopped working.")).not.toBeInTheDocument();
  });

  it("keeps the dialog open and says why when the delete fails, then deletes on the next try", async () => {
    const vault = serveVault({ override: failOnce(isDeleteOfFile, () => failure(500, "internal_error")) });
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: "Delete report.pdf" }));
    const dialog = screen.getByRole("dialog", { name: "Delete this file?" });
    await user.click(within(dialog).getByRole("button", { name: "Delete file" }));

    const alert = await within(dialog).findByRole("alert");
    expect(alert).toHaveTextContent("The file could not be deleted");
    expect(alert).toHaveTextContent("The API reported an error. Try again shortly.");
    expect(alert).toHaveTextContent("Reference: req-test");
    expect(screen.getByRole("link", { name: "report.pdf" })).toBeInTheDocument();

    await user.click(within(dialog).getByRole("button", { name: "Delete file" }));

    await findNotice("report.pdf was deleted. Every link made for it stopped working.");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(vault.changes()).toHaveLength(2);
  });

  it("sends one delete however often the button is pressed, and lets nothing dismiss it meanwhile", async () => {
    const gate = makeGate();
    const vault = serveVault({
      override: async ({ method, path }) => {
        if (isDeleteOfFile(method, path)) await gate.passed;
        return undefined;
      },
    });
    const user = userEvent.setup();
    renderPage();

    await user.click(await screen.findByRole("button", { name: "Delete report.pdf" }));
    const dialog = screen.getByRole("dialog", { name: "Delete this file?" });
    await user.dblClick(within(dialog).getByRole("button", { name: "Delete file" }));

    const busy = await within(dialog).findByRole("button", { name: "Deleting…" });
    const cancel = within(dialog).getByRole("button", { name: "Cancel" });
    expect(busy).toHaveAttribute("aria-disabled", "true");
    expect(cancel).toHaveAttribute("aria-disabled", "true");

    await user.click(cancel);
    await user.keyboard("{Escape}");
    await user.click(busy);
    expect(screen.getByRole("dialog", { name: "Delete this file?" })).toBeInTheDocument();
    expect(vault.changes()).toHaveLength(1);

    gate.open();

    await findNotice("report.pdf was deleted. Every link made for it stopped working.");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(vault.changes()).toHaveLength(1);
  });

  it("closes a file's details when that file is deleted from them", async () => {
    const vault = serveVault();
    const user = userEvent.setup();
    renderPage(`/files?file=${FILE_ID}`);

    await user.click(await screen.findByRole("button", { name: "Delete file" }));
    const dialog = screen.getByRole("dialog", { name: "Delete this file?" });
    await user.click(within(dialog).getByRole("button", { name: "Delete file" }));

    await findNotice("report.pdf was deleted. Every link made for it stopped working.");
    // The router applies the new address as a transition, which can land just after the notice.
    await waitFor(() => expect(address()).toBe("/files"));
    expect(screen.queryByRole("heading", { level: 3 })).not.toBeInTheDocument();
    expect(await screen.findByText(EMPTY_LIST)).toBeInTheDocument();
    expect(only(vault.changes()).path).toBe(`/api/v1/files/${FILE_ID}`);
  });

  it("goes back to the last page that still has files when this page's only file is deleted", async () => {
    serveVault({ files: manyFiles(11) });
    const user = userEvent.setup();
    renderPage("/files?page=2");

    await user.click(await screen.findByRole("button", { name: "Delete file-11.txt" }));
    const dialog = screen.getByRole("dialog", { name: "Delete this file?" });
    await user.click(within(dialog).getByRole("button", { name: "Delete file" }));

    await findNotice("file-11.txt was deleted. Every link made for it stopped working.");
    expect(await screen.findByRole("link", { name: "file-1.txt" })).toBeInTheDocument();
    expect(address()).toBe("/files");
    expect(screen.getByText("10 files stored")).toBeInTheDocument();
    expect(screen.queryByText("This page has no files.")).not.toBeInTheDocument();
  });
});

describe("FilesPage links", () => {
  it("keeps the file's row up to date as links are made and revoked, and keeps the link out of the address", async () => {
    serveVault();
    const user = userEvent.setup();
    renderPage(`/files?file=${FILE_ID}`);
    const table = await screen.findByRole("table", { name: FILE_TABLE });
    expect(within(table).getByText("No links")).toBeInTheDocument();

    await user.click(await screen.findByRole("button", { name: "Create link" }));

    expect(await screen.findByRole("region", { name: "Your new share link" })).toBeInTheDocument();
    await waitFor(() => expect(within(rowOf("report.pdf")).getByText("1 active of 1 link")).toBeInTheDocument());

    await user.click(await screen.findByRole("button", { name: "Revoke link 00000001" }));
    const dialog = screen.getByRole("dialog", { name: "Revoke this link?" });
    await user.click(within(dialog).getByRole("button", { name: "Revoke link" }));

    await waitFor(() => expect(within(rowOf("report.pdf")).getByText("0 active of 1 link")).toBeInTheDocument());
    expect(address()).toBe(`/files?file=${FILE_ID}`);
    expect(document.title).toBe("Files · CipherForge");
    expect(`${address()} ${document.title}`).not.toContain(SHARE_TOKEN);
  });
});
