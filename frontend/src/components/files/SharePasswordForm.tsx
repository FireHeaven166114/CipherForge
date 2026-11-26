import { type FormEvent, useEffect, useId, useRef, useState } from "react";

import type { ShareFailure } from "../../features/files/shareStates";
import { useShareCountdown } from "../../hooks/useShareCountdown";
import { DownloadIcon } from "../hud/Icons";
import { FIELD, LABEL, PRIMARY_BUTTON } from "../styles";
import ShareStateMessage from "./ShareStateMessage";

interface SharePasswordFormProps {
  /** Whether the link is protected, so a password has to be typed before anything is sent. */
  passwordRequired: boolean;
  downloading: boolean;
  /** The last attempt's failure, and when another attempt will be accepted (epoch milliseconds). */
  failed: { failure: ShareFailure; retryAt: number | null } | null;
  /** The password is handed over once, as typed, and is not kept by anything but the input. */
  onSubmit: (password: string | null) => void;
}

/** The recipient's one control: a password when the link needs one, and the Download button. */
export default function SharePasswordForm({
  passwordRequired,
  downloading,
  failed,
  onSubmit,
}: SharePasswordFormProps) {
  const [password, setPassword] = useState("");
  const [missing, setMissing] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  const inputId = useId();
  const hintId = `${inputId}-hint`;
  const missingId = `${inputId}-missing`;
  const alertId = `${inputId}-alert`;
  const secondsLeft = useShareCountdown(failed?.retryAt ?? null);
  const waiting = secondsLeft > 0;
  const kind = failed?.failure.kind;
  const wrong = kind === "wrong_password";

  // After a refusal the next move is to retype the password, so the cursor goes back to it.
  useEffect(() => {
    if (kind === "wrong_password" || kind === "password_required") input.current?.focus();
  }, [failed, kind]);

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (downloading || waiting) return;
    if (passwordRequired && password === "") {
      setMissing(true);
      input.current?.focus();
      return;
    }
    onSubmit(passwordRequired ? password : null);
  }

  const describedBy = [hintId, missing ? missingId : null, wrong ? alertId : null]
    .filter((part) => part !== null)
    .join(" ");

  return (
    <form onSubmit={submit} noValidate className="mt-6 space-y-4">
      {passwordRequired ? (
        <div>
          <label htmlFor={inputId} className={`${LABEL} block`}>
            Password
          </label>
          <input
            ref={input}
            id={inputId}
            type="password"
            autoComplete="current-password"
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
            readOnly={downloading}
            value={password}
            onChange={(event) => {
              setPassword(event.target.value);
              setMissing(false);
            }}
            aria-invalid={missing || wrong}
            aria-describedby={describedBy}
            className={`${FIELD} mt-1.5 font-mono`}
          />
          <p id={hintId} className="mt-1.5 text-xs text-ink-300">
            The person who sent you this link gave you the password separately.
          </p>
          {missing ? (
            <p id={missingId} className="mt-1.5 flex items-start gap-2 text-crit">
              <span aria-hidden="true">✕</span>
              <span>Enter the password to download this file.</span>
            </p>
          ) : null}
        </div>
      ) : null}

      {failed ? <ShareStateMessage id={alertId} failure={failed.failure} variant="inline" /> : null}

      <div>
        <button
          type="submit"
          aria-disabled={downloading || waiting || undefined}
          className={`${PRIMARY_BUTTON} w-full justify-center`}
        >
          <DownloadIcon className="size-4" />
          {downloading ? "Downloading…" : waiting ? `Try again in ${secondsLeft} s` : "Download"}
        </button>
        <p role="status" className="mt-2 min-h-5 text-center text-xs text-ink-200">
          {downloading
            ? "Decrypting and checking the file. This can take a moment."
            : failed !== null && failed.retryAt !== null && !waiting
              ? "You can try again now."
              : ""}
        </p>
      </div>
    </form>
  );
}
