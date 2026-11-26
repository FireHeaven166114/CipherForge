import type { ApiErrorEnvelope } from "../types/api";

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_RETRY_AFTER_SECONDS = 3600;

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly correlationId: string | undefined;
  /** How long the server asked the caller to wait, when it said (429 responses). */
  readonly retryAfterSeconds: number | undefined;

  constructor(init: {
    message: string;
    status: number;
    code: string;
    correlationId?: string;
    retryAfterSeconds?: number;
  }) {
    super(init.message);
    this.name = "ApiError";
    this.status = init.status;
    this.code = init.code;
    this.correlationId = init.correlationId;
    this.retryAfterSeconds = init.retryAfterSeconds;
  }
}

/** Callers of `request` only ever handle ApiError; anything else becomes a generic one. */
export function toApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error;
  return new ApiError({
    message: "Something went wrong while contacting the API.",
    status: 0,
    code: "unexpected_error",
  });
}

type TokenProvider = () => Promise<string | null> | string | null;

let tokenProvider: TokenProvider | null = null;

/**
 * Registers where bearer tokens come from (for example an MSAL wrapper).
 * The token is requested per call and is never stored by this module.
 */
export function setTokenProvider(provider: TokenProvider | null): void {
  tokenProvider = provider;
}

export interface RequestOptions<T> {
  method?: "GET" | "POST" | "DELETE";
  body?: unknown;
  /** Cancels the request; the original AbortError is rethrown untouched. */
  signal?: AbortSignal;
  timeoutMs?: number;
  /** Non-2xx statuses whose JSON body is a normal result (for example 503 from /ready). */
  acceptStatuses?: readonly number[];
  /** Runtime check for the response body; a mismatch becomes an `invalid_response` error. */
  guard?: (value: unknown) => value is T;
  /**
   * Set to false for endpoints that anyone holding a link may call. The bearer token is then
   * never attached, so a signed-in analyst's credentials cannot reach a public endpoint.
   */
  authenticated?: boolean;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function isErrorEnvelope(value: unknown): value is ApiErrorEnvelope {
  if (!isRecord(value) || !isRecord(value.error)) return false;
  return typeof value.error.code === "string" && typeof value.error.message === "string";
}

async function readJson(response: Response): Promise<unknown> {
  try {
    return await response.json();
  } catch {
    return undefined;
  }
}

/** Only the delta-seconds form, which is what the API sends, is understood. */
function parseRetryAfter(value: string | null): number | undefined {
  if (value === null || !/^\d{1,7}$/.test(value.trim())) return undefined;
  return Math.min(Number(value), MAX_RETRY_AFTER_SECONDS);
}

function invalidResponse(status: number, correlationId: string | undefined): ApiError {
  return new ApiError({
    message: "The API returned a response this app cannot read.",
    status,
    code: "invalid_response",
    correlationId,
  });
}

interface Transport {
  method: string;
  headers: Record<string, string>;
  body?: BodyInit;
  signal?: AbortSignal;
  timeoutMs: number;
  authenticated: boolean;
}

/** Adds the bearer token (when there is one and the endpoint wants it) and sends the request. */
async function send(path: string, transport: Transport): Promise<Response> {
  const { method, headers, body, signal, timeoutMs, authenticated } = transport;
  const token = authenticated && tokenProvider ? await tokenProvider() : null;
  const sent = token ? { ...headers, Authorization: `Bearer ${token}` } : headers;

  const timeoutSignal = AbortSignal.timeout(timeoutMs);
  const combinedSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;

  try {
    return await fetch(path, {
      method,
      headers: sent,
      body,
      signal: combinedSignal,
      cache: "no-store",
      credentials: "same-origin",
    });
  } catch (error) {
    if (signal?.aborted) throw error;
    if (timeoutSignal.aborted) {
      throw new ApiError({ message: "The request timed out.", status: 0, code: "timeout" });
    }
    throw new ApiError({
      message: "Could not reach the CipherForge API.",
      status: 0,
      code: "network_error",
    });
  }
}

/** Only the server's sanitised envelope is surfaced, never a raw response body. */
function failureOf(response: Response, payload: unknown, correlationId: string | undefined): ApiError {
  const envelope = isErrorEnvelope(payload) ? payload.error : undefined;
  return new ApiError({
    message: envelope?.message ?? `The API responded with HTTP ${response.status}.`,
    status: response.status,
    code: envelope?.code ?? "http_error",
    correlationId: envelope?.correlation_id ?? correlationId,
    retryAfterSeconds: parseRetryAfter(response.headers.get("Retry-After")),
  });
}

export async function request<T>(path: string, options: RequestOptions<T> = {}): Promise<T> {
  const {
    method = "GET",
    body,
    signal,
    timeoutMs = DEFAULT_TIMEOUT_MS,
    acceptStatuses = [],
    guard,
    authenticated = true,
  } = options;

  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const response = await send(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
    timeoutMs,
    authenticated,
  });

  const headerCorrelationId = response.headers.get("X-Correlation-ID") ?? undefined;
  const payload = await readJson(response);

  if (response.ok || acceptStatuses.includes(response.status)) {
    if (payload === undefined || (guard && !guard(payload))) {
      throw invalidResponse(response.status, headerCorrelationId);
    }
    return payload as T;
  }
  throw failureOf(response, payload, headerCorrelationId);
}

// A file takes longer to send than a JSON request, and the server reads, checks and (for a share)
// encrypts it before it answers.
const UPLOAD_TIMEOUT_MS = 120_000;

export interface NoContentOptions {
  method?: "POST" | "DELETE";
  signal?: AbortSignal;
  timeoutMs?: number;
}

/** For calls that answer 204 No Content, such as a delete: success carries no body to check. */
export async function requestNoContent(
  path: string,
  { method = "DELETE", signal, timeoutMs = DEFAULT_TIMEOUT_MS }: NoContentOptions = {},
): Promise<void> {
  const response = await send(path, {
    method,
    headers: { Accept: "application/json" },
    signal,
    timeoutMs,
    authenticated: true,
  });
  if (response.ok) return;
  const correlationId = response.headers.get("X-Correlation-ID") ?? undefined;
  throw failureOf(response, await readJson(response), correlationId);
}

export interface UploadOptions<T> {
  /** The name to record for the file. It is sent percent-encoded, so any Unicode name is safe. */
  fileName: string;
  signal?: AbortSignal;
  timeoutMs?: number;
  guard?: (value: unknown) => value is T;
}

/**
 * Sends the raw bytes of a file as `application/octet-stream` with the name in `X-File-Name`.
 * The API does not accept multipart forms, because those would put the plaintext in a temporary
 * file on the server.
 */
export async function uploadFile<T>(
  path: string,
  file: Blob,
  { fileName, signal, timeoutMs = UPLOAD_TIMEOUT_MS, guard }: UploadOptions<T>,
): Promise<T> {
  const response = await send(path, {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/octet-stream",
      "X-File-Name": encodeURIComponent(fileName),
    },
    body: file,
    signal,
    timeoutMs,
    authenticated: true,
  });

  const headerCorrelationId = response.headers.get("X-Correlation-ID") ?? undefined;
  const payload = await readJson(response);
  if (!response.ok) throw failureOf(response, payload, headerCorrelationId);
  if (payload === undefined || (guard && !guard(payload))) {
    throw invalidResponse(response.status, headerCorrelationId);
  }
  return payload as T;
}

export interface DownloadOptions {
  method?: "GET" | "POST";
  body?: unknown;
  signal?: AbortSignal;
  timeoutMs?: number;
  authenticated?: boolean;
}

export interface DownloadedFile {
  data: Blob;
  /** The value of the Content-Disposition header, which the caller turns into a file name. */
  contentDisposition: string | null;
}

/** Fetches a binary answer. A failure still arrives as the API's JSON error envelope. */
export async function downloadFile(
  path: string,
  { method = "GET", body, signal, timeoutMs = UPLOAD_TIMEOUT_MS, authenticated = true }: DownloadOptions = {},
): Promise<DownloadedFile> {
  const headers: Record<string, string> = { Accept: "application/octet-stream, application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";

  const response = await send(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
    timeoutMs,
    authenticated,
  });

  const headerCorrelationId = response.headers.get("X-Correlation-ID") ?? undefined;
  if (!response.ok) throw failureOf(response, await readJson(response), headerCorrelationId);

  let data: Blob;
  try {
    data = await response.blob();
  } catch {
    throw invalidResponse(response.status, headerCorrelationId);
  }
  return { data, contentDisposition: response.headers.get("Content-Disposition") };
}
