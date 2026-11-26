import { type DragEvent, type FormEvent, useId, useRef, useState } from "react";
import { Link } from "react-router";

import { validateUpload } from "../../features/files/validation";
import { formatBytes } from "../../features/units";
import { useFileUpload } from "../../hooks/useFileUpload";
import type { FileFeatureStatus, StoredFile } from "../../types/files";
import { UploadIcon } from "../hud/Icons";
import Panel from "../hud/Panel";
import LoadingNote from "../LoadingNote";
import { LINK, PRIMARY_BUTTON } from "../styles";
import FileErrorNotice from "./FileErrorNotice";

interface FileUploadPanelProps {
  status: FileFeatureStatus;
  /** Where a stored file's details are shown, so the success message can offer to share it. */
  fileHref: (id: string) => string;
  /** Called once a file is stored, so the list can be refreshed. */
  onUploaded: (file: StoredFile) => void;
}

export default function FileUploadPanel({ status, fileHref, onUploaded }: FileUploadPanelProps) {
  const upload = useFileUpload();
  const inputId = useId();
  const noteId = useId();
  const problemId = useId();
  const input = useRef<HTMLInputElement>(null);
  const [chosen, setChosen] = useState<File | null>(null);
  const [problem, setProblem] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  // A new key gives the file input a clean slate, which is the only way to clear a chosen file.
  const [inputKey, setInputKey] = useState(0);

  const limit = status.max_file_size_bytes;
  const usable = status.configured;

  function choose(file: File | null) {
    upload.reset();
    setChosen(file);
    setProblem(file === null ? null : validateUpload(file, limit));
  }

  function onDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault();
    setDragging(false);
    if (!usable || upload.busy) return;
    const { files } = event.dataTransfer;
    if (files.length > 1) {
      choose(null);
      setProblem("Choose one file at a time.");
      return;
    }
    const file = files.item(0);
    if (file !== null) choose(file);
  }

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (upload.busy || !usable) return;
    if (chosen === null) {
      setProblem("Choose a file to upload first.");
      input.current?.focus();
      return;
    }
    if (problem !== null) {
      input.current?.focus();
      return;
    }
    const stored = await upload.start(chosen);
    if (stored === null) return;
    setChosen(null);
    setInputKey((key) => key + 1);
    onUploaded(stored);
  }

  return (
    <Panel title="Upload a file" code="UPL">
      <p>
        Your file is encrypted on the server with AES-256-GCM before it is stored. Its own key is
        wrapped by the server&apos;s master key, and the people you share it with never receive a key.
      </p>

      <form onSubmit={(event) => void submit(event)} noValidate className="mt-4">
        <fieldset disabled={!usable} className="min-w-0 space-y-3">
          <legend className="sr-only">Upload a file</legend>
          <div
            onDragOver={(event) => {
              event.preventDefault();
              if (usable) setDragging(true);
            }}
            onDragLeave={(event) => {
              if (!event.currentTarget.contains(event.relatedTarget as Node | null)) setDragging(false);
            }}
            onDrop={onDrop}
            className={`relative rounded-ui border-2 border-dashed p-5 text-center transition has-[:focus-visible]:border-cipher has-[:focus-visible]:bg-cipher/5 ${
              dragging ? "border-cipher bg-cipher/10" : "border-ink-500"
            }`}
          >
            <UploadIcon className="mx-auto size-7 text-cipher" />
            <p className="mt-2 text-ink-100">
              Drag a file here, or{" "}
              <label htmlFor={inputId} className={`${LINK} cursor-pointer`}>
                choose a file
              </label>
            </p>
            <p className="mt-1 text-xs text-ink-300">Largest file: {formatBytes(limit)}.</p>
            <input
              key={inputKey}
              ref={input}
              id={inputId}
              type="file"
              className="sr-only"
              disabled={upload.busy}
              aria-invalid={problem !== null}
              aria-describedby={problem !== null ? problemId : noteId}
              onChange={(event) => choose(event.target.files?.item(0) ?? null)}
            />
          </div>

          <p id={noteId} className="text-ink-200">
            {chosen === null ? (
              "No file chosen."
            ) : (
              <>
                Chosen: <span className="break-all font-mono text-ink-50">{chosen.name}</span> (
                {formatBytes(chosen.size)})
              </>
            )}
          </p>
          {problem !== null ? (
            <p id={problemId} className="flex items-start gap-2 text-crit">
              <span aria-hidden="true">✕</span>
              <span>{problem}</span>
            </p>
          ) : null}

          <div className="flex flex-wrap items-center gap-3">
            <button
              type="submit"
              aria-disabled={upload.busy || undefined}
              className={PRIMARY_BUTTON}
            >
              <UploadIcon className="size-4" />
              {upload.busy ? "Encrypting and uploading…" : "Encrypt and upload"}
            </button>
            {upload.busy ? <LoadingNote>Encrypting and uploading. Large files take a while.</LoadingNote> : null}
          </div>
        </fieldset>
      </form>

      {!usable ? (
        <p className="mt-3 text-warn">Uploading is switched off until the server has a master key.</p>
      ) : null}

      {upload.error ? (
        <div className="mt-4">
          <FileErrorNotice
            title="The upload failed"
            error={upload.error}
            context={{ maxFileSizeBytes: limit }}
          />
        </div>
      ) : null}

      {upload.uploaded ? (
        <div
          role="status"
          className="cf-plate mt-4 flex flex-wrap items-center justify-between gap-3 rounded-ui border border-ok/50 p-4 text-ink-100 [--plate:var(--color-ok)]"
        >
          <p className="flex min-w-0 items-start gap-2">
            <span aria-hidden="true" className="text-ok">
              ✓
            </span>
            <span className="min-w-0">
              <span className="break-all font-mono text-ink-50">{upload.uploaded.name}</span> is
              encrypted and stored ({formatBytes(upload.uploaded.size_bytes)}).
            </span>
          </p>
          <Link to={fileHref(upload.uploaded.id)} className={LINK}>
            Share this file
          </Link>
        </div>
      ) : null}
    </Panel>
  );
}
