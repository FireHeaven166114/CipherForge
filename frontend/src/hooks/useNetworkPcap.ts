import { useCallback, useEffect, useRef, useState } from "react";

import { isSessionActive } from "../features/network/labels";
import { PCAP_MAX_POLL_FAILURES, PCAP_POLL_MS } from "../features/network/polling";
import { checkCaptureFile } from "../features/network/upload";
import { type ApiError, toApiError } from "../services/apiClient";
import { analysePcap, getSession } from "../services/networkService";
import type { SessionDetail } from "../types/network";

export type PcapPhase = "idle" | "uploading" | "analysing" | "completed" | "failed";

export interface PcapOptions {
  /** The server's upload limit, for the quick check before anything is sent. 0 leaves the size to the server. */
  maxUploadMb: number;
  /**
   * The caller's own analysis that the server reports as running, so a page that was opened or
   * reloaded meanwhile follows it too.
   */
  followSessionId: string | null;
  /** The server accepted the file and began analysing it. */
  onStarted?: (session: SessionDetail) => void;
  /** The analysis ended, either completed or failed. Called once per analysis. */
  onFinished?: (session: SessionDetail) => void;
  /** The server refused the file or could not be asked, so what the page knows may be out of date. */
  onRefused?: () => void;
}

export interface PcapUpload {
  phase: PcapPhase;
  /** The file being sent, while `phase` is "uploading". */
  fileName: string | null;
  /** The analysis as last seen: progress counters while it runs, the outcome once it ended. */
  session: SessionDetail | null;
  /** Why the file was not sent: the quick check on this side said no. The server stays authoritative. */
  rejection: string | null;
  /** Why the server refused the file, or why the analysis can no longer be followed. */
  error: ApiError | null;
  /** True when following the analysis stopped on a passing problem, so asking again may work. */
  canRetry: boolean;
  /** Checks the file, sends it, and follows its analysis until it ends. */
  upload: (file: File) => Promise<void>;
  /** Starts following the analysis again after it was lost. */
  retry: () => void;
  /** Clears the messages and the outcome of the last analysis. */
  dismiss: () => void;
}

interface Problem {
  error: ApiError;
  resumable: boolean;
}

// The analysis is gone or the account lost its right to see it: asking again cannot help.
const FINAL_STATUSES: readonly number[] = [401, 403, 404];

/**
 * Sends a capture file for analysis and follows the analysis, which runs in the background on
 * the server, by asking for the session until it ends. The file name is for display only.
 */
export function useNetworkPcap({
  maxUploadMb,
  followSessionId,
  onStarted,
  onFinished,
  onRefused,
}: PcapOptions): PcapUpload {
  const [uploadingName, setUploadingName] = useState<string | null>(null);
  const [ownId, setOwnId] = useState<string | null>(null);
  const [session, setSession] = useState<SessionDetail | null>(null);
  const [doneIds, setDoneIds] = useState<readonly string[]>([]);
  const [rejection, setRejection] = useState<string | null>(null);
  const [problem, setProblem] = useState<Problem | null>(null);

  const mounted = useRef(true);
  const sending = useRef(false);
  const handlers = useRef({ onStarted, onFinished, onRefused });

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  useEffect(() => {
    handlers.current = { onStarted, onFinished, onRefused };
  });

  const ownActive = ownId !== null && !doneIds.includes(ownId) ? ownId : null;
  const followed =
    followSessionId !== null && !doneIds.includes(followSessionId) ? followSessionId : null;
  const trackedId = ownActive ?? followed;
  // An analysis found running already has no first answer yet, so it is asked about at once.
  const askAtOnce = ownActive === null;
  const paused = problem?.resumable === true;

  useEffect(() => {
    if (trackedId === null || paused) return;
    const controller = new AbortController();
    const { signal } = controller;
    let timer: number | undefined;
    let failures = 0;

    const poll = () => {
      getSession(trackedId, signal).then(
        (detail) => {
          if (signal.aborted) return;
          failures = 0;
          setSession(detail);
          if (isSessionActive(detail.status)) {
            timer = window.setTimeout(poll, PCAP_POLL_MS);
            return;
          }
          setDoneIds((ids) => [...ids, detail.id]);
          handlers.current.onFinished?.(detail);
        },
        (caught: unknown) => {
          if (signal.aborted) return;
          const error = toApiError(caught);
          if (FINAL_STATUSES.includes(error.status)) {
            setDoneIds((ids) => [...ids, trackedId]);
            setProblem({ error, resumable: false });
            return;
          }
          failures += 1;
          if (failures < PCAP_MAX_POLL_FAILURES) {
            timer = window.setTimeout(poll, PCAP_POLL_MS);
            return;
          }
          setProblem({ error, resumable: true });
        },
      );
    };

    timer = window.setTimeout(poll, askAtOnce ? 0 : PCAP_POLL_MS);
    return () => {
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [trackedId, askAtOnce, paused]);

  const upload = useCallback(
    async (file: File) => {
      if (sending.current) return;
      const check = checkCaptureFile(file, maxUploadMb);
      if (!check.ok) {
        setRejection(check.reason);
        setProblem(null);
        return;
      }
      sending.current = true;
      setRejection(null);
      setProblem(null);
      setSession(null);
      setUploadingName(file.name);
      try {
        const detail = await analysePcap(file);
        if (!mounted.current) return;
        setOwnId(detail.id);
        setSession(detail);
        handlers.current.onStarted?.(detail);
        if (!isSessionActive(detail.status)) {
          setDoneIds((ids) => [...ids, detail.id]);
          handlers.current.onFinished?.(detail);
        }
      } catch (caught) {
        if (mounted.current) {
          setProblem({ error: toApiError(caught), resumable: false });
          handlers.current.onRefused?.();
        }
      } finally {
        sending.current = false;
        if (mounted.current) setUploadingName(null);
      }
    },
    [maxUploadMb],
  );

  const retry = useCallback(() => setProblem(null), []);

  const dismiss = useCallback(() => {
    setRejection(null);
    setProblem(null);
    setSession(null);
  }, []);

  // Progress belongs to the analysis being followed; once none is, only a finished one is shown.
  let shown: SessionDetail | null = null;
  if (session !== null) {
    if (trackedId !== null) shown = session.id === trackedId ? session : null;
    else if (!isSessionActive(session.status)) shown = session;
  }

  let phase: PcapPhase = "idle";
  if (uploadingName !== null) phase = "uploading";
  else if (trackedId !== null) phase = "analysing";
  else if (shown !== null) phase = shown.status === "completed" ? "completed" : "failed";

  return {
    phase,
    fileName: uploadingName,
    session: shown,
    rejection,
    error: problem?.error ?? null,
    canRetry: paused,
    upload,
    retry,
    dismiss,
  };
}
