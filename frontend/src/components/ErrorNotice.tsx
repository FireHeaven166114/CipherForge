import { formatWait } from "../features/intel/format";
import type { ApiError } from "../services/apiClient";
import { BUTTON } from "./styles";

interface Explanation {
  title: string;
  hint?: string;
}

/**
 * Turns an API failure into something an analyst can act on. The `message` shown beneath the
 * title is the server's own sanitised text, so this adds context without hiding the detail.
 */
function explain(error: ApiError): Explanation {
  switch (error.code) {
    case "timeout":
      return {
        title: "The request timed out",
        hint: "The API or a provider is slow to answer. Try again in a moment.",
      };
    case "network_error":
      return {
        title: "Could not reach the API",
        hint: "Check that the API is running and that your network connection works.",
      };
    case "invalid_response":
      return {
        title: "Unexpected response from the API",
        hint: "The reply was not in a shape this console understands. The console and API may be different versions.",
      };
    case "unexpected_error":
      return { title: "Something went wrong" };
  }

  switch (error.status) {
    case 401:
      return {
        title: "Not signed in",
        hint: "The API requires authentication, and this console cannot sign in yet. It works against an API running in development authentication mode.",
      };
    case 403:
      return {
        title: "Access denied",
        hint: "Threat-intelligence data needs the SecurityAnalyst or Admin role.",
      };
    case 404:
      return { title: "Not found" };
    case 422:
      return { title: "That request was not accepted" };
    case 429:
      return {
        title: "Rate limit reached",
        hint:
          error.retryAfterSeconds === undefined
            ? "Try again shortly."
            : `Try again in ${formatWait(error.retryAfterSeconds)}.`,
      };
  }

  if (error.status >= 500) {
    return {
      title: "The API reported an error",
      hint: "Try again shortly. If it keeps happening, give the reference below to an administrator.",
    };
  }
  return { title: "The request failed" };
}

interface ErrorNoticeProps {
  error: ApiError;
  onRetry?: () => void;
}

export default function ErrorNotice({ error, onRetry }: ErrorNoticeProps) {
  const { title, hint } = explain(error);
  return (
    <div role="alert" className="rounded-lg border border-red-700 bg-red-950 p-4 text-sm text-red-100">
      <p className="flex items-center gap-2 font-semibold">
        <span aria-hidden="true">✕</span>
        {title}
      </p>
      <p className="mt-1">{error.message}</p>
      {hint ? <p className="mt-1 text-red-200">{hint}</p> : null}
      {error.correlationId ? (
        <p className="mt-2 text-xs text-red-200">Reference: {error.correlationId}</p>
      ) : null}
      {onRetry ? (
        <button type="button" onClick={onRetry} className={`${BUTTON} mt-3`}>
          Try again
        </button>
      ) : null}
    </div>
  );
}
