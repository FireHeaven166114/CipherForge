import type { ApiErrorEnvelope } from "../types/api";

const DEFAULT_TIMEOUT_MS = 10_000;

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly correlationId: string | undefined;

  constructor(init: { message: string; status: number; code: string; correlationId?: string }) {
    super(init.message);
    this.name = "ApiError";
    this.status = init.status;
    this.code = init.code;
    this.correlationId = init.correlationId;
  }
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
  method?: "GET" | "POST";
  body?: unknown;
  /** Cancels the request; the original AbortError is rethrown untouched. */
  signal?: AbortSignal;
  timeoutMs?: number;
  /** Non-2xx statuses whose JSON body is a normal result (for example 503 from /ready). */
  acceptStatuses?: readonly number[];
  /** Runtime check for the response body; a mismatch becomes an `invalid_response` error. */
  guard?: (value: unknown) => value is T;
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

function invalidResponse(status: number, correlationId: string | undefined): ApiError {
  return new ApiError({
    message: "The API returned a response this app cannot read.",
    status,
    code: "invalid_response",
    correlationId,
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
  } = options;

  const headers: Record<string, string> = { Accept: "application/json" };
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const token = tokenProvider ? await tokenProvider() : null;
  if (token) headers.Authorization = `Bearer ${token}`;

  const timeoutSignal = AbortSignal.timeout(timeoutMs);
  const combinedSignal = signal ? AbortSignal.any([signal, timeoutSignal]) : timeoutSignal;

  let response: Response;
  try {
    response = await fetch(path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
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

  const headerCorrelationId = response.headers.get("X-Correlation-ID") ?? undefined;
  const payload = await readJson(response);

  if (response.ok || acceptStatuses.includes(response.status)) {
    if (payload === undefined || (guard && !guard(payload))) {
      throw invalidResponse(response.status, headerCorrelationId);
    }
    return payload as T;
  }

  // Only the server's sanitised envelope is surfaced, never a raw response body.
  const envelope = isErrorEnvelope(payload) ? payload.error : undefined;
  throw new ApiError({
    message: envelope?.message ?? `The API responded with HTTP ${response.status}.`,
    status: response.status,
    code: envelope?.code ?? "http_error",
    correlationId: envelope?.correlation_id ?? headerCorrelationId,
  });
}
