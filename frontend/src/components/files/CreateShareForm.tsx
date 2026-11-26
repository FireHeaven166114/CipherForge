import { type FormEvent, type RefObject, useId, useRef, useState } from "react";

import {
  type ShareField,
  defaultShareValues,
  passwordLength,
  validateShareForm,
} from "../../features/files/validation";
import { useFileAction } from "../../hooks/useFileAction";
import { createShare } from "../../services/filesService";
import type { FileFeatureStatus, ShareCreated } from "../../types/files";
import { LinkIcon } from "../hud/Icons";
import { BUTTON, FIELD, LABEL, PRIMARY_BUTTON } from "../styles";
import FileErrorNotice from "./FileErrorNotice";

const FIELD_ORDER: readonly ShareField[] = ["expiresInHours", "maxDownloads", "password"];

interface CreateShareFormProps {
  fileId: string;
  status: FileFeatureStatus;
  /** Why no link can be made for this file right now; null when one can. */
  blockedReason: string | null;
  /** Hands over the answer, whose token exists nowhere else and is shown once. */
  onCreated: (created: ShareCreated) => void;
}

interface ProblemProps {
  id: string;
  children: string;
}

function Problem({ id, children }: ProblemProps) {
  return (
    <p id={id} className="mt-1.5 flex items-start gap-2 text-sm text-crit">
      <span aria-hidden="true">✕</span>
      <span>{children}</span>
    </p>
  );
}

interface NumberFieldProps {
  label: string;
  hint: string;
  value: string;
  max: number;
  error: string | undefined;
  inputRef: RefObject<HTMLInputElement | null>;
  onChange: (value: string) => void;
  onBlur: () => void;
}

function NumberField({ label, hint, value, max, error, inputRef, onChange, onBlur }: NumberFieldProps) {
  const id = useId();
  const hintId = `${id}-hint`;
  const errorId = `${id}-error`;
  return (
    <div className="min-w-44 flex-1">
      <label htmlFor={id} className={`${LABEL} block`}>
        {label}
      </label>
      <input
        ref={inputRef}
        id={id}
        type="number"
        inputMode="numeric"
        min={1}
        max={max}
        step={1}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        onBlur={onBlur}
        aria-invalid={error !== undefined}
        aria-describedby={error === undefined ? hintId : `${hintId} ${errorId}`}
        className={`${FIELD} mt-1.5 font-mono`}
      />
      <p id={hintId} className="mt-1.5 text-xs text-ink-300">
        {hint}
      </p>
      {error === undefined ? null : <Problem id={errorId}>{error}</Problem>}
    </div>
  );
}

/**
 * Makes a share link. The limits come from the server's status, the form checks them as the person
 * types, and the server still has the last word. The password is only ever in this form's state: it
 * is sent once, in the request body, and cleared when the link has been made.
 */
export default function CreateShareForm({ fileId, status, blockedReason, onCreated }: CreateShareFormProps) {
  const action = useFileAction();
  const [values, setValues] = useState(() => defaultShareValues(status));
  const [touched, setTouched] = useState<Partial<Record<ShareField, boolean>>>({});
  const [attempted, setAttempted] = useState(false);
  const [reveal, setReveal] = useState(false);
  const passwordId = useId();
  const passwordHintId = `${passwordId}-hint`;
  const passwordErrorId = `${passwordId}-error`;
  const hoursRef = useRef<HTMLInputElement>(null);
  const downloadsRef = useRef<HTMLInputElement>(null);
  const passwordRef = useRef<HTMLInputElement>(null);

  const { errors, request } = validateShareForm(values, status);
  const shown = (field: ShareField) => (attempted || touched[field] === true ? errors[field] : undefined);
  const passwordError = shown("password");

  function change(field: ShareField, value: string) {
    setValues((current) => ({ ...current, [field]: value }));
    setTouched((current) => ({ ...current, [field]: true }));
  }

  function leave(field: ShareField) {
    setTouched((current) => ({ ...current, [field]: true }));
  }

  function focusFirstProblem() {
    const refs: Record<ShareField, RefObject<HTMLInputElement | null>> = {
      expiresInHours: hoursRef,
      maxDownloads: downloadsRef,
      password: passwordRef,
    };
    const first = FIELD_ORDER.find((field) => errors[field] !== undefined);
    if (first !== undefined) refs[first].current?.focus();
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (action.busy || blockedReason !== null) return;
    setAttempted(true);
    if (request === null) {
      focusFirstProblem();
      return;
    }
    const created = await action.run(() => createShare(fileId, request));
    if (created === null) return;
    setValues(defaultShareValues(status));
    setTouched({});
    setAttempted(false);
    setReveal(false);
    onCreated(created);
  }

  return (
    <form
      aria-label="Create a share link"
      onSubmit={(event) => void submit(event)}
      noValidate
      className="space-y-4"
    >
      <p>
        Each link has its own expiry, download limit and optional password. The link is shown once,
        right after you make it.
      </p>
      {blockedReason !== null ? <p className="text-warn">{blockedReason}</p> : null}

      <fieldset disabled={blockedReason !== null} className="min-w-0 space-y-4">
        <legend className="sr-only">New link</legend>
        <div className="flex flex-wrap gap-x-4 gap-y-4">
          <NumberField
            label="Expires after (hours)"
            hint={`1 to ${status.max_share_expiry_hours} hours. The link stops working after that.`}
            value={values.expiresInHours}
            max={status.max_share_expiry_hours}
            error={shown("expiresInHours")}
            inputRef={hoursRef}
            onChange={(value) => change("expiresInHours", value)}
            onBlur={() => leave("expiresInHours")}
          />
          <NumberField
            label="Maximum downloads"
            hint={`1 to ${status.max_share_downloads}. The link stops working after this many downloads.`}
            value={values.maxDownloads}
            max={status.max_share_downloads}
            error={shown("maxDownloads")}
            inputRef={downloadsRef}
            onChange={(value) => change("maxDownloads", value)}
            onBlur={() => leave("maxDownloads")}
          />
        </div>

        <div className="max-w-xl">
          <label htmlFor={passwordId} className={`${LABEL} block`}>
            Password (optional)
          </label>
          <div className="mt-1.5 flex gap-2">
            <input
              ref={passwordRef}
              id={passwordId}
              type={reveal ? "text" : "password"}
              autoComplete="new-password"
              spellCheck={false}
              value={values.password}
              onChange={(event) => change("password", event.target.value)}
              onBlur={() => leave("password")}
              aria-invalid={passwordError !== undefined}
              aria-describedby={
                passwordError === undefined ? passwordHintId : `${passwordHintId} ${passwordErrorId}`
              }
              className={`${FIELD} font-mono`}
            />
            <button type="button" onClick={() => setReveal((current) => !current)} className={`${BUTTON} shrink-0`}>
              {reveal ? "Hide password" : "Show password"}
            </button>
          </div>
          <p id={passwordHintId} className="mt-1.5 text-xs text-ink-300">
            {status.min_password_length} to {status.max_password_length} characters, or leave it empty
            for no password. Whoever opens the link needs it, so send it by a different route.
            {values.password === "" ? "" : ` Typed so far: ${passwordLength(values.password)}.`}
          </p>
          {passwordError === undefined ? null : <Problem id={passwordErrorId}>{passwordError}</Problem>}
        </div>

        {action.error ? (
          <FileErrorNotice title="The link could not be created" error={action.error} />
        ) : null}

        <div className="flex flex-wrap items-center gap-3">
          <button type="submit" aria-disabled={action.busy || undefined} className={PRIMARY_BUTTON}>
            <LinkIcon className="size-4" />
            {action.busy ? "Creating link…" : "Create link"}
          </button>
        </div>
      </fieldset>
    </form>
  );
}
