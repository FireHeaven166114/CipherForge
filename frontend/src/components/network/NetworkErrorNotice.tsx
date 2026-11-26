import { describeNetworkError, type MessageContext } from "../../features/network/messages";
import type { ApiError } from "../../services/apiClient";
import ErrorNotice from "../ErrorNotice";
import { BUTTON } from "../styles";
import Notice from "./Notice";

interface NetworkErrorNoticeProps {
  error: ApiError;
  context?: MessageContext;
  onRetry?: () => void;
}

/**
 * An API failure in the words this page has for it: what happened and what to do. A failure it
 * has no words for falls back to the console's own notice, which shows the API's message.
 */
export default function NetworkErrorNotice({ error, context, onRetry }: NetworkErrorNoticeProps) {
  const mapped = describeNetworkError(error, context);
  if (mapped === null) return <ErrorNotice error={error} onRetry={onRetry} />;

  // A refusal the analyst can act on is a warning; a fault of the server or the network is an error.
  const tone = error.status === 0 || error.status >= 500 ? "bad" : "warn";
  return (
    <Notice tone={tone} role="alert" title={mapped.title}>
      <p>{mapped.message}</p>
      {error.correlationId ? (
        <p className="font-mono text-xs text-ink-300">Reference: {error.correlationId}</p>
      ) : null}
      {onRetry ? (
        <button type="button" onClick={onRetry} className={`${BUTTON} mt-1`}>
          Try again
        </button>
      ) : null}
    </Notice>
  );
}
