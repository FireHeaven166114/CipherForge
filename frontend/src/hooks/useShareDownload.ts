import { useCallback, useEffect, useRef, useState } from "react";

import { fileNameFromDisposition } from "../features/files/disposition";
import { saveBlob } from "../features/files/download";
import { type ShareFailure, classifyShareError } from "../features/files/shareStates";
import { toApiError } from "../services/apiClient";
import { downloadShare } from "../services/shareService";

/** How long a recipient is asked to wait when the server did not say, in seconds. */
const DEFAULT_WAIT_SECONDS: Partial<Record<ShareFailure["kind"], number>> = {
  rate_limited: 10,
  busy: 5,
};

export type DownloadPhase =
  | { kind: "idle" }
  | { kind: "downloading" }
  /** `retryAt` is when another attempt will be accepted (epoch milliseconds), or null for no wait. */
  | { kind: "failed"; failure: ShareFailure; retryAt: number | null }
  /** `saved` is false when the browser refused to start the save; the file is still held to try again. */
  | { kind: "done"; fileName: string; saved: boolean };

export interface ShareDownloadControls {
  phase: DownloadPhase;
  /**
   * Fetches the file and offers it for saving. The password is passed through and never kept. Does
   * nothing while a download is already running, so a double click cannot use two downloads.
   */
  submit: (password: string | null) => Promise<void>;
  /** Offers the file that was already fetched again, without using another download. */
  saveAgain: () => void;
}

function trySave(blob: Blob, fileName: string): boolean {
  try {
    saveBlob(blob, fileName);
    return true;
  } catch {
    return false;
  }
}

function retryTime(failure: ShareFailure): number | null {
  const seconds = failure.waitSeconds ?? DEFAULT_WAIT_SECONDS[failure.kind];
  return seconds === undefined ? null : Date.now() + seconds * 1000;
}

/** Downloads one shared file and saves it. Leaving the page cancels a download that is still running. */
export function useShareDownload(token: string): ShareDownloadControls {
  const [phase, setPhase] = useState<DownloadPhase>({ kind: "idle" });
  const running = useRef(false);
  const current = useRef<AbortController | null>(null);
  const held = useRef<{ blob: Blob; fileName: string } | null>(null);

  useEffect(() => {
    return () => current.current?.abort();
  }, []);

  const submit = useCallback(
    async (password: string | null) => {
      if (running.current) return;
      running.current = true;
      const controller = new AbortController();
      current.current = controller;
      setPhase({ kind: "downloading" });
      try {
        const { data, contentDisposition } = await downloadShare(token, password, controller.signal);
        if (controller.signal.aborted) return;
        const fileName = fileNameFromDisposition(contentDisposition);
        held.current = { blob: data, fileName };
        setPhase({ kind: "done", fileName, saved: trySave(data, fileName) });
      } catch (caught) {
        if (controller.signal.aborted) return;
        const failure = classifyShareError(toApiError(caught));
        setPhase({ kind: "failed", failure, retryAt: retryTime(failure) });
      } finally {
        running.current = false;
        current.current = null;
      }
    },
    [token],
  );

  const saveAgain = useCallback(() => {
    const file = held.current;
    if (file === null) return;
    setPhase({ kind: "done", fileName: file.fileName, saved: trySave(file.blob, file.fileName) });
  }, []);

  return { phase, submit, saveAgain };
}
