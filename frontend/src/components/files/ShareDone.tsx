import { useEffect, useRef } from "react";

import { plural } from "../../features/intel/format";
import { DownloadIcon } from "../hud/Icons";
import { BUTTON } from "../styles";

interface ShareDoneProps {
  fileName: string;
  /** False when the browser would not start the save; the file is still held, so it can be tried again. */
  saved: boolean;
  /** How many more times the link can be used after this download. */
  remaining: number;
  onSaveAgain: () => void;
}

/** What the recipient sees once the file has been released to their browser. */
export default function ShareDone({ fileName, saved, remaining, onSaveAgain }: ShareDoneProps) {
  const heading = useRef<HTMLHeadingElement>(null);

  // The password form that was here is gone, so focus moves to the answer.
  useEffect(() => {
    heading.current?.focus();
  }, []);

  return (
    <div>
      <h1
        ref={heading}
        tabIndex={-1}
        className="flex items-start gap-2 text-xl font-semibold text-ink-50 focus:outline-none"
      >
        <span aria-hidden="true" className={saved ? "text-ok" : "text-warn"}>
          {saved ? "✓" : "▲"}
        </span>
        <span className="min-w-0">
          {saved ? "Your download has started" : "Your browser did not start the download"}
        </span>
      </h1>

      <p className="mt-3 break-all rounded-control border border-white/10 bg-ink-950/60 p-3 font-mono text-xs text-ink-100">
        {fileName}
      </p>

      <p className="mt-3 text-ink-100">
        {saved
          ? "The file was checked and sent to your browser, which saves it with your other downloads."
          : "The file was checked, but your browser would not save it. Try again below. This does not use up another download."}
      </p>
      <p className="mt-2 text-ink-200">
        {remaining === 0
          ? "This link has no downloads left."
          : `This link can be used ${plural(remaining, "more time")}.`}
      </p>

      <button type="button" onClick={onSaveAgain} className={`${BUTTON} mt-4`}>
        <DownloadIcon className="size-4" />
        Save again
      </button>
    </div>
  );
}
