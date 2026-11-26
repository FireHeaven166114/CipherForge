import { useCallback, useEffect, useRef, useState } from "react";

import { type ApiError, toApiError } from "../services/apiClient";
import { uploadStoredFile } from "../services/filesService";
import type { StoredFile } from "../types/files";

export interface FileUploadControls {
  /** True while a file is being sent and encrypted. */
  busy: boolean;
  /** Why the last upload failed, until the next one starts or `reset` is called. */
  error: ApiError | null;
  /** What the last upload stored, under the name the server gave it. */
  uploaded: StoredFile | null;
  /**
   * Sends one file. Resolves to the stored file, or to null when it failed (see `error`), when
   * another upload is still running, or when the page was left before it finished.
   */
  start: (file: File) => Promise<StoredFile | null>;
  /** Forgets the last outcome, so the form starts clean. */
  reset: () => void;
}

/** Uploads one file at a time. Leaving the page cancels an upload that is still being sent. */
export function useFileUpload(): FileUploadControls {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [uploaded, setUploaded] = useState<StoredFile | null>(null);
  const running = useRef(false);
  const current = useRef<AbortController | null>(null);

  useEffect(() => {
    return () => current.current?.abort();
  }, []);

  const start = useCallback(async (file: File): Promise<StoredFile | null> => {
    if (running.current) return null;
    running.current = true;
    const controller = new AbortController();
    current.current = controller;
    setBusy(true);
    setError(null);
    setUploaded(null);
    try {
      const stored = await uploadStoredFile(file, controller.signal);
      if (controller.signal.aborted) return null;
      setUploaded(stored);
      return stored;
    } catch (caught) {
      if (!controller.signal.aborted) setError(toApiError(caught));
      return null;
    } finally {
      running.current = false;
      current.current = null;
      if (!controller.signal.aborted) setBusy(false);
    }
  }, []);

  const reset = useCallback(() => {
    setError(null);
    setUploaded(null);
  }, []);

  return { busy, error, uploaded, start, reset };
}
