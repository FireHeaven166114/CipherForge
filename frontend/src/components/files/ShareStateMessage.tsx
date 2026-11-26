import { SHARE_STATE_TEXT, type ShareFailure, type ShareFailureKind } from "../../features/files/shareStates";
import { formatWait } from "../../features/intel/format";
import { BUTTON } from "../styles";

interface ShareStateMessageProps {
  failure: ShareFailure;
  /**
   * "page" is the whole answer to opening a link, so it carries the page's heading. "inline" sits
   * above a form the recipient can still use, so it is an alert and not a heading.
   */
  variant: "page" | "inline";
  /** Offered when asking again can help. */
  onRetry?: () => void;
  /** Ties an input to this message through aria-describedby. */
  id?: string;
}

// Only a file that failed its check is a hard failure. Everything else is a state the recipient
// can read calmly: a link that ended, or a server that needs a moment.
const SEVERE: ReadonlySet<ShareFailureKind> = new Set(["integrity", "unknown"]);

/** What went wrong with a share link, in plain words and without any server detail. */
export default function ShareStateMessage({ failure, variant, onRetry, id }: ShareStateMessageProps) {
  const text = SHARE_STATE_TEXT[failure.kind];
  const severe = SEVERE.has(failure.kind);
  const glyph = (
    <span aria-hidden="true" className={severe ? "text-crit" : "text-warn"}>
      {severe ? "✕" : "▲"}
    </span>
  );
  const details = (
    <>
      <p className="mt-2 text-ink-100">{text.message}</p>
      {failure.waitSeconds === undefined ? null : (
        <p className="mt-1 text-ink-100">The server asked you to wait {formatWait(failure.waitSeconds)}.</p>
      )}
      {failure.reference === undefined ? null : (
        <p className="mt-3 font-mono text-xs text-ink-300">Reference: {failure.reference}</p>
      )}
    </>
  );

  if (variant === "page") {
    return (
      <div id={id} role="alert">
        <h1 className="flex items-start gap-2 text-xl font-semibold text-ink-50">
          {glyph}
          <span className="min-w-0">{text.title}</span>
        </h1>
        {details}
        {text.retry && onRetry ? (
          <button type="button" onClick={onRetry} className={`${BUTTON} mt-4`}>
            Try again
          </button>
        ) : null}
      </div>
    );
  }

  return (
    <div
      id={id}
      role="alert"
      className={`cf-plate rounded-ui border p-3 ${
        severe
          ? "border-crit/60 [--plate:var(--color-crit)]"
          : "border-warn/50 [--plate:var(--color-warn)]"
      }`}
    >
      <p className={`flex items-start gap-2 font-semibold ${severe ? "text-crit" : "text-warn"}`}>
        {glyph}
        <span className="min-w-0">{text.title}</span>
      </p>
      {details}
    </div>
  );
}
