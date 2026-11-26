import { useEffect, useId, useRef, useState } from "react";

import { copyText } from "../../features/files/link";
import { plural } from "../../features/intel/format";
import type { Share } from "../../types/files";
import DateTime from "../DateTime";
import FactList from "../FactList";
import { CheckIcon, CopyIcon, LinkIcon } from "../hud/Icons";
import { BUTTON, FIELD, LABEL } from "../styles";

interface ShareLinkPanelProps {
  /** The whole address a recipient opens. It is shown here and nowhere else. */
  link: string;
  share: Share;
  /** Hides the link. The caller drops it, so it cannot be shown again. */
  onDismiss: () => void;
}

type CopyOutcome = "idle" | "copied" | "manual";

const COPY_MESSAGES: Record<CopyOutcome, string> = {
  idle: "",
  copied: "The link is on your clipboard.",
  manual:
    "Your browser would not copy it. The link is selected: press Ctrl+C (Command+C on a Mac) to copy it.",
};

/**
 * The one chance to see a new link. Only a fingerprint of the token is stored, so once this panel
 * is gone nobody, the sender included, can see the link again.
 */
export default function ShareLinkPanel({ link, share, onDismiss }: ShareLinkPanelProps) {
  const headingId = useId();
  const inputId = useId();
  const heading = useRef<HTMLHeadingElement>(null);
  const input = useRef<HTMLInputElement>(null);
  const [outcome, setOutcome] = useState<CopyOutcome>("idle");

  // The link appears in response to a button that is about to be reset, so focus goes to the panel.
  useEffect(() => {
    heading.current?.focus();
  }, []);

  async function copy() {
    setOutcome((await copyText(link, input.current)) ? "copied" : "manual");
  }

  return (
    <section
      aria-labelledby={headingId}
      className="cf-plate rounded-ui border border-warn/50 p-4 text-sm text-ink-100 [--plate:var(--color-warn)]"
    >
      <h3
        ref={heading}
        id={headingId}
        tabIndex={-1}
        className="flex items-center gap-2 text-base font-semibold text-ink-50 focus:outline-none"
      >
        <LinkIcon className="size-4 text-cipher" />
        Your new share link
      </h3>

      <p className="mt-2 flex items-start gap-2 font-medium text-warn">
        <span aria-hidden="true">▲</span>
        <span>
          Copy it now: this link is shown only once. CipherForge keeps only a fingerprint of it, so it
          cannot be shown again. If you lose it, revoke the link and make a new one.
        </span>
      </p>
      <p className="mt-2">
        Anyone who has this link can download the file
        {share.password_protected
          ? ", as long as they also know the password you set"
          : ", with no password"}
        . The encryption key is not part of the link.
      </p>

      <label htmlFor={inputId} className={`${LABEL} mt-4 block`}>
        Share link
      </label>
      <div className="mt-1.5 flex flex-wrap gap-2">
        <input
          ref={input}
          id={inputId}
          readOnly
          value={link}
          spellCheck={false}
          autoComplete="off"
          onFocus={(event) => event.currentTarget.select()}
          className={`${FIELD} min-w-0 flex-1 font-mono`}
        />
        <button type="button" onClick={() => void copy()} className={BUTTON}>
          {outcome === "copied" ? <CheckIcon className="size-4" /> : <CopyIcon className="size-4" />}
          {outcome === "copied" ? "Copied" : "Copy link"}
        </button>
      </div>
      <p role="status" className="mt-1.5 min-h-5 text-xs text-ink-200">
        {COPY_MESSAGES[outcome]}
      </p>

      <div className="mt-3">
        <FactList
          facts={[
            { label: "Expires", value: <DateTime value={share.expires_at} /> },
            { label: "Downloads allowed", value: plural(share.max_downloads, "download") },
            { label: "Password", value: share.password_protected ? "Needed to download" : "None" },
          ]}
        />
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-3">
        <button type="button" onClick={onDismiss} className={BUTTON}>
          Hide link
        </button>
        <p className="text-xs text-ink-300">
          Hiding it does not revoke it. Once hidden, the link cannot be shown again.
        </p>
      </div>
    </section>
  );
}
