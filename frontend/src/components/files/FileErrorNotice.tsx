import { type ErrorContext, describeFileError } from "../../features/files/messages";
import type { ApiError } from "../../services/apiClient";

interface FileErrorNoticeProps {
  /** What was being attempted, in a few words: "The upload failed". */
  title: string;
  error: ApiError;
  context?: ErrorContext;
}

/**
 * A failed change, worded for the person who pressed the button. The shared ErrorNotice shows the
 * server's own message; for files the code decides the wording, because the codes say what to do
 * (rename the file, pick a smaller one, wait a while). The button that was pressed stays where it
 * was, so it is also how to try again.
 */
export default function FileErrorNotice({ title, error, context }: FileErrorNoticeProps) {
  return (
    <div
      role="alert"
      className="cf-plate rounded-ui border border-crit/60 p-4 text-sm text-ink-100 shadow-glow-crit [--plate:var(--color-crit)]"
    >
      <p className="flex items-center gap-2 font-semibold text-crit">
        <span aria-hidden="true">✕</span>
        {title}
      </p>
      <p className="mt-1">{describeFileError(error, context)}</p>
      {error.correlationId ? (
        <p className="mt-2 font-mono text-xs text-ink-300">Reference: {error.correlationId}</p>
      ) : null}
    </div>
  );
}
