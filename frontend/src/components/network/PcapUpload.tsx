import { useId, useRef, useState } from "react";

import { formatCount } from "../../features/intel/format";
import { countOf } from "../../features/network/labels";
import { describeErrorCode } from "../../features/network/messages";
import { FILE_ACCEPT } from "../../features/network/upload";
import { formatBytes } from "../../features/units";
import { useNetworkPcap } from "../../hooks/useNetworkPcap";
import type { AnalysisStatus, SessionDetail } from "../../types/network";
import { UploadIcon } from "../hud/Icons";
import Panel from "../hud/Panel";
import { BUTTON, LABEL, PRIMARY_BUTTON } from "../styles";
import NetworkErrorNotice from "./NetworkErrorNotice";
import Notice from "./Notice";

interface PcapUploadProps {
  analysis: AnalysisStatus;
  /** The server accepted the file: its session exists and is being analysed. */
  onStarted: (session: SessionDetail) => void;
  /** The analysis ended, completed or failed. */
  onFinished: (session: SessionDetail) => void;
  /** The server refused the upload: the status the page holds, such as who is analysing, may be out of date. */
  onRefused?: () => void;
  /** Open a session's results, such as those of an analysis that failed part way. */
  onOpen: (sessionId: string) => void;
  className?: string;
}

function Progress({ session }: { session: SessionDetail | null }) {
  if (session === null) return <>Waiting for the first progress report…</>;
  return (
    <>
      {countOf(session.packets_total, "packet")} and {formatBytes(session.bytes_total)} read so far,{" "}
      {countOf(session.flows_total, "flow")}, {countOf(session.alerts_total, "alert")}.
    </>
  );
}

function Outcome({ session, onOpen }: { session: SessionDetail; onOpen: (sessionId: string) => void }) {
  const mapped = describeErrorCode(session.error_code);
  const note = mapped?.message ?? session.message;
  if (session.status === "completed") {
    return (
      <div className="space-y-2">
        <p className="text-ok">
          <span aria-hidden="true">✓ </span>
          Analysis complete: {countOf(session.packets_total, "packet")}, {countOf(session.alerts_total, "alert")}.
        </p>
        {note !== null ? (
          <Notice tone="warn" title={mapped?.title ?? "The analysis finished with a note"}>
            <p>{note}</p>
          </Notice>
        ) : null}
      </div>
    );
  }
  const one = session.packets_total === 1;
  return (
    <Notice tone="bad" title={mapped?.title ?? "The analysis failed"}>
      <p>{note ?? "The capture file could not be analysed."}</p>
      {session.packets_total > 0 ? (
        <>
          <p>
            {countOf(session.packets_total, "packet")} {one ? "was" : "were"} read before it stopped, and{" "}
            {one ? "it is" : "they are"} kept.
          </p>
          <button type="button" onClick={() => onOpen(session.id)} className={`${BUTTON} mt-1`}>
            Open partial results
          </button>
        </>
      ) : null}
    </Notice>
  );
}

/** Sends a PCAP or PCAPNG file for analysis and follows the analysis until it ends. */
export default function PcapUpload({
  analysis,
  onStarted,
  onFinished,
  onRefused,
  onOpen,
  className,
}: PcapUploadProps) {
  const inputId = useId();
  const hintId = useId();
  const input = useRef<HTMLInputElement>(null);
  const [selected, setSelected] = useState<File | null>(null);
  const maxMb = analysis.max_upload_mb;

  const pcap = useNetworkPcap({
    maxUploadMb: maxMb,
    followSessionId: analysis.session_id,
    onStarted: (session) => {
      setSelected(null);
      if (input.current !== null) input.current.value = "";
      onStarted(session);
    },
    onFinished,
    onRefused,
  });

  const working = pcap.phase === "uploading" || pcap.phase === "analysing";
  const inProgress = analysis.running || working;
  const hasMessage = pcap.rejection !== null || pcap.error !== null || pcap.phase === "completed" || pcap.phase === "failed";

  return (
    <Panel title="Analyse a capture file" code="PCAP-01" className={className}>
      <div className="space-y-4">
        <p className="text-sm text-ink-100">
          Upload a PCAP or PCAPNG file to analyse it offline. It is analysed in the background, so you can
          leave this page and come back. The server keeps the results, not the file.
        </p>

        <div>
          <label htmlFor={inputId} className={LABEL}>
            Capture file
          </label>
          <input
            ref={input}
            id={inputId}
            type="file"
            accept={FILE_ACCEPT}
            disabled={inProgress}
            aria-describedby={hintId}
            onChange={(event) => {
              setSelected(event.target.files?.[0] ?? null);
              pcap.dismiss();
            }}
            className="mt-1.5 block w-full text-sm text-ink-100 file:mr-3 file:cursor-pointer file:rounded-control file:border file:border-white/10 file:bg-ink-800/60 file:px-3 file:py-1.5 file:text-sm file:font-medium file:text-ink-100 hover:file:border-cipher/50 disabled:cursor-not-allowed disabled:opacity-50"
          />
          <p id={hintId} className="mt-1.5 text-xs text-ink-300">
            Files ending in .pcap, .pcapng or .cap
            {maxMb > 0 ? `, up to ${formatCount(maxMb)} MB` : ""}. This page checks the name and size first to
            save you an upload; the server checks again and has the last word.
          </p>
        </div>

        {selected !== null ? (
          <p className="text-sm text-ink-100">
            Selected: <span className="break-all font-mono text-xs">{selected.name}</span> (
            {formatBytes(selected.size)})
          </p>
        ) : null}

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => {
              if (selected !== null && !inProgress) void pcap.upload(selected);
            }}
            aria-disabled={selected === null || inProgress || undefined}
            className={PRIMARY_BUTTON}
          >
            <UploadIcon className="size-4" />
            {pcap.phase === "uploading" ? "Uploading…" : "Analyse file"}
          </button>
          {hasMessage ? (
            <button type="button" onClick={pcap.dismiss} className={BUTTON}>
              Dismiss
            </button>
          ) : null}
        </div>

        <div role="status" aria-live="polite" className="space-y-2 text-sm text-ink-100">
          {pcap.phase === "uploading" ? (
            <p>
              Uploading <span className="break-all font-mono text-xs">{pcap.fileName}</span>…
            </p>
          ) : null}
          {pcap.phase === "analysing" ? (
            <p>
              Analysis in progress. <Progress session={pcap.session} />
            </p>
          ) : null}
          {pcap.phase !== "analysing" && pcap.phase !== "uploading" && analysis.running ? (
            <p>
              Analysis in progress.{" "}
              {analysis.session_id === null
                ? "A capture file is being analysed by someone else, in another tab or by another user. Uploads are paused until it finishes."
                : "Your analysis is running. Uploads are paused until it finishes."}
            </p>
          ) : null}
          {(pcap.phase === "completed" || pcap.phase === "failed") && pcap.session !== null ? (
            <Outcome session={pcap.session} onOpen={onOpen} />
          ) : null}
        </div>

        {pcap.rejection !== null ? (
          <Notice tone="warn" role="alert" title="The file was not sent">
            <p>{pcap.rejection}</p>
          </Notice>
        ) : null}
        {pcap.error !== null ? (
          <NetworkErrorNotice
            error={pcap.error}
            context={{ maxUploadMb: maxMb > 0 ? maxMb : undefined }}
            onRetry={pcap.canRetry ? pcap.retry : undefined}
          />
        ) : null}
      </div>
    </Panel>
  );
}
