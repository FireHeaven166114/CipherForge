import { type Mock, vi } from "vitest";

import type {
  ActivityItem,
  ActivityList,
  FileFeatureStatus,
  FileList,
  PublicShareInfo,
  Share,
  ShareCreated,
  ShareRequest,
  StoredFile,
  StoredFileDetail,
} from "../types/files";
import { jsonResponse, stubFetch } from "./http";

// Test data only. The token below is not a working link: it only has the shape of one.

export const FILE_ID = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d";
export const OTHER_FILE_ID = "b2c3d4e5-f6a7-4b8c-9d0e-1f2a3b4c5d6e";
export const SHARE_ID = "c3d4e5f6-a7b8-4c9d-8e1f-2a3b4c5d6e7f";
export const SHARE_TOKEN = "Zk3p_Q8rT0-vN1xLw5yU7aB9cD2eF4gH6iJ8kM0nO1p";

export const CREATED_AT = "2026-05-20T08:30:00Z";
export const EXPIRES_AT = "2026-05-21T08:30:00Z";

export function makeFileStatus(overrides: Partial<FileFeatureStatus> = {}): FileFeatureStatus {
  return {
    configured: true,
    max_file_size_bytes: 25 * 1024 * 1024,
    default_share_expiry_hours: 24,
    max_share_expiry_hours: 720,
    max_share_downloads: 100,
    min_password_length: 8,
    max_password_length: 128,
    ...overrides,
  };
}

export function makeShare(overrides: Partial<Share> = {}): Share {
  return {
    id: SHARE_ID,
    file_id: FILE_ID,
    created_at: CREATED_AT,
    expires_at: EXPIRES_AT,
    max_downloads: 3,
    download_count: 0,
    downloads_remaining: 3,
    last_downloaded_at: null,
    revoked_at: null,
    password_protected: false,
    status: "active",
    ...overrides,
  };
}

export function makeStoredFile(overrides: Partial<StoredFile> = {}): StoredFile {
  return {
    id: FILE_ID,
    name: "report.pdf",
    size_bytes: 2048,
    status: "active",
    algorithm: "AES-256-GCM",
    created_at: CREATED_AT,
    share_count: 0,
    active_share_count: 0,
    ...overrides,
  };
}

export function makeStoredFileDetail(overrides: Partial<StoredFileDetail> = {}): StoredFileDetail {
  return { ...makeStoredFile(), shares: [], ...overrides };
}

export function makeFileList(items: StoredFile[] = [makeStoredFile()]): FileList {
  return { items, total: items.length };
}

export function makeShareCreated(overrides: Partial<ShareCreated> = {}): ShareCreated {
  return {
    share: makeShare(),
    token: SHARE_TOKEN,
    path: `/share/${SHARE_TOKEN}`,
    ...overrides,
  };
}

export function makeActivityItem(overrides: Partial<ActivityItem> = {}): ActivityItem {
  return {
    timestamp: CREATED_AT,
    action: "FILE_CREATE",
    result: "success",
    share_id: null,
    reason: null,
    ...overrides,
  };
}

export function makeActivityList(items: ActivityItem[] = [makeActivityItem()]): ActivityList {
  return { items };
}

export function makePublicShareInfo(overrides: Partial<PublicShareInfo> = {}): PublicShareInfo {
  return {
    state: "available",
    file_name: "report.pdf",
    size_bytes: 2048,
    password_required: false,
    expires_at: EXPIRES_AT,
    downloads_remaining: 3,
    ...overrides,
  };
}

export interface BlobDownloadStub {
  createObjectURL: Mock<(blob: Blob) => string>;
  revokeObjectURL: Mock<(url: string) => void>;
  /** Each anchor that was clicked: the name it asked to save as and the address it pointed at. */
  clicks: { download: string; href: string }[];
}

/**
 * jsdom has no object URLs and does not navigate, so saving a download is replaced by a record of
 * what would have been saved. The URL stubs stay defined for the rest of the file, so a revoke
 * timer that fires late cannot throw. The anchor spy is restored after each test.
 */
export function stubBlobDownload(): BlobDownloadStub {
  const createObjectURL = vi.fn<(blob: Blob) => string>(() => "blob:cipherforge-test");
  const revokeObjectURL = vi.fn<(url: string) => void>();
  Object.defineProperty(URL, "createObjectURL", { configurable: true, writable: true, value: createObjectURL });
  Object.defineProperty(URL, "revokeObjectURL", { configurable: true, writable: true, value: revokeObjectURL });

  const clicks: BlobDownloadStub["clicks"] = [];
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
    clicks.push({ download: this.download, href: this.href });
  });
  return { createObjectURL, revokeObjectURL, clicks };
}

/** Gives the page a clipboard whose `writeText` is a mock; undo with `removeClipboardStubs`. */
export function stubClipboard(
  writeText: (text: string) => Promise<void> = () => Promise.resolve(),
): Mock<(text: string) => Promise<void>> {
  const mock = vi.fn<(text: string) => Promise<void>>(writeText);
  Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: mock } });
  return mock;
}

/** Gives the page the old `document.execCommand("copy")`, which jsdom does not have. */
export function stubExecCommand(result = true): Mock<(command: string) => boolean> {
  const mock = vi.fn<(command: string) => boolean>(() => result);
  Object.defineProperty(document, "execCommand", { configurable: true, writable: true, value: mock });
  return mock;
}

/** Takes away whatever `stubClipboard` and `stubExecCommand` gave the page. */
export function removeClipboardStubs(): void {
  Reflect.deleteProperty(navigator, "clipboard");
  Reflect.deleteProperty(document, "execCommand");
}

type FetchMock = ReturnType<typeof stubFetch>;

/** An answer in the API's error envelope. Extra headers, such as Retry-After, go in `headers`. */
export function failure(status: number, code: string, headers: Record<string, string> = {}): Response {
  return jsonResponse(
    { error: { code, message: `The API reported ${code}.`, correlation_id: "req-test" } },
    { status, headers: { "Content-Type": "application/json", ...headers } },
  );
}

/** One request a page sent. A JSON body is already parsed; any other body is as it was sent. */
export interface SentRequest {
  method: string;
  path: string;
  query: URLSearchParams;
  headers: Headers;
  body: unknown;
}

export function describeRequest(url: string, init: RequestInit | undefined): SentRequest {
  const { pathname, searchParams } = new URL(url, "http://localhost");
  const body = init?.body;
  return {
    method: init?.method ?? "GET",
    path: pathname,
    query: searchParams,
    headers: new Headers(init?.headers),
    body: typeof body === "string" ? (JSON.parse(body) as unknown) : body,
  };
}

/** Every request made through a stubbed fetch, in order. */
export function sentRequests(fetchMock: FetchMock): SentRequest[] {
  return fetchMock.mock.calls.map(([input, init]) => describeRequest(String(input), init));
}

/** The one item of a list that must have exactly one. */
export function only<T>(items: readonly T[]): T {
  const [first] = items;
  if (first === undefined || items.length !== 1) {
    throw new Error(`Expected exactly one item but found ${items.length}.`);
  }
  return first;
}

const strays: string[] = [];

/** A door a test holds shut to keep a request waiting, then opens to let it through. */
export function makeGate(): { passed: Promise<void>; open: () => void } {
  let open: () => void = () => undefined;
  const passed = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { passed, open };
}

/** The requests no vault had an answer for since the last call. A test expects there to be none. */
export function takeStrayRequests(): string[] {
  return strays.splice(0);
}

const REVOKED_AT = "2026-05-20T09:30:00Z";

export interface VaultOptions {
  status?: FileFeatureStatus;
  /** The stored files, newest first, each with its links. Link counts are worked out from the links. */
  files?: StoredFileDetail[];
  /** What happened to each file, newest first, by file id. */
  activity?: Record<string, ActivityItem[]>;
  /**
   * Gets the first say on a request: a response replaces what the vault would have answered, and
   * `undefined` lets the vault answer. It may wait first, which holds the request open.
   */
  override?: (request: SentRequest) => Response | Promise<Response | undefined> | undefined;
}

export interface Vault {
  fetchMock: FetchMock;
  /** The files as they are now. */
  files: StoredFileDetail[];
  /** Everything the page sent, in order. */
  requests: () => SentRequest[];
  /** What the page sent that was not a read: uploads, new links, revokes and deletes. */
  changes: () => SentRequest[];
}

/**
 * A small stand-in for the files API that remembers what it is told: an upload adds a file, a new
 * link is added to its file, a revoke marks a link revoked and a delete removes the file. A request
 * it does not know is answered with a 500 and noted for `takeStrayRequests`.
 */
export function serveVault(options: VaultOptions = {}): Vault {
  const status = options.status ?? makeFileStatus();
  const files = [...(options.files ?? [makeStoredFileDetail()])];
  const activity = options.activity ?? {};
  let issued = 0;
  const nextId = () => `${String(++issued).padStart(8, "0")}-0000-4000-8000-000000000000`;

  const summary = (file: StoredFileDetail): StoredFile => ({
    id: file.id,
    name: file.name,
    size_bytes: file.size_bytes,
    status: file.status,
    algorithm: file.algorithm,
    created_at: file.created_at,
    share_count: file.shares.length,
    active_share_count: file.shares.filter((share) => share.status === "active").length,
  });
  const record = (fileId: string, entry: ActivityItem) => {
    activity[fileId] = [entry, ...(activity[fileId] ?? [])];
  };

  function upload(request: SentRequest): Response {
    const stored = makeStoredFileDetail({
      id: nextId(),
      name: decodeURIComponent(request.headers.get("X-File-Name") ?? ""),
      size_bytes: request.body instanceof Blob ? request.body.size : 0,
    });
    files.unshift(stored);
    record(stored.id, makeActivityItem({ action: "FILE_CREATE" }));
    return jsonResponse(summary(stored), { status: 201 });
  }

  function createLink(file: StoredFileDetail, request: SentRequest): Response {
    const asked = request.body as ShareRequest;
    const maxDownloads = asked.max_downloads ?? 1;
    const share = makeShare({
      id: nextId(),
      file_id: file.id,
      max_downloads: maxDownloads,
      downloads_remaining: maxDownloads,
      password_protected: asked.password !== undefined,
    });
    file.shares.unshift(share);
    record(file.id, makeActivityItem({ action: "SHARE_CREATE", share_id: share.id }));
    return jsonResponse({ share, token: SHARE_TOKEN, path: `/share/${SHARE_TOKEN}` }, { status: 201 });
  }

  function revoke(file: StoredFileDetail, shareId: string | undefined): Response {
    const index = file.shares.findIndex((share) => share.id === shareId);
    const current = file.shares[index];
    if (current === undefined) return failure(404, "share_not_found");
    const revoked: Share = { ...current, status: "revoked", revoked_at: REVOKED_AT };
    file.shares[index] = revoked;
    record(file.id, makeActivityItem({ action: "SHARE_REVOKE", share_id: revoked.id }));
    return jsonResponse(revoked);
  }

  function answer(request: SentRequest): Response {
    const { method, path, query } = request;
    const base = "/api/v1/files";
    if (path === base || path.startsWith(`${base}/`)) {
      const parts = path
        .slice(base.length)
        .split("/")
        .filter((part) => part !== "")
        .map(decodeURIComponent);
      const [first, second, third, fourth] = parts;

      if (parts.length === 0 && method === "GET") {
        const limit = Number(query.get("limit") ?? 50);
        const offset = Number(query.get("offset") ?? 0);
        return jsonResponse({ items: files.slice(offset, offset + limit).map(summary), total: files.length });
      }
      if (parts.length === 0 && method === "POST") return upload(request);
      if (parts.length === 1 && first === "status" && method === "GET") return jsonResponse(status);

      const file = files.find((candidate) => candidate.id === first);
      if (file === undefined) return failure(404, "file_not_found");
      if (parts.length === 1 && method === "GET") {
        return jsonResponse({ ...summary(file), shares: file.shares });
      }
      if (parts.length === 1 && method === "DELETE") {
        files.splice(files.indexOf(file), 1);
        return new Response(null, { status: 204 });
      }
      if (parts.length === 2 && second === "activity" && method === "GET") {
        return jsonResponse({ items: activity[file.id] ?? [] });
      }
      if (parts.length === 2 && second === "shares" && method === "POST") return createLink(file, request);
      if (parts.length === 4 && second === "shares" && fourth === "revoke" && method === "POST") {
        return revoke(file, third);
      }
    }
    strays.push(`${method} ${path}`);
    return failure(500, "unexpected_request");
  }

  const fetchMock = stubFetch(async (url, init) => {
    const request = describeRequest(url, init);
    return (await options.override?.(request)) ?? answer(request);
  });
  const requests = () => sentRequests(fetchMock);
  return {
    fetchMock,
    files,
    requests,
    changes: () => requests().filter((request) => request.method !== "GET"),
  };
}
