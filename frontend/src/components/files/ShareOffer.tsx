import { SHARE_STATE_TEXT } from "../../features/files/shareStates";
import { formatBytes } from "../../features/units";
import { useShareDownload } from "../../hooks/useShareDownload";
import type { PublicShareInfo } from "../../types/files";
import DateTime from "../DateTime";
import FactList from "../FactList";
import ShareDone from "./ShareDone";
import SharePasswordForm from "./SharePasswordForm";
import ShareStateMessage from "./ShareStateMessage";

interface ShareOfferProps {
  /** The link's token. It goes to the API as part of the path, and nowhere else. */
  token: string;
  info: PublicShareInfo;
}

/** A link that works: what it offers, the password box when it needs one, and the download itself. */
export default function ShareOffer({ token, info }: ShareOfferProps) {
  const { phase, submit, saveAgain } = useShareDownload(token);
  const failed = phase.kind === "failed" ? phase : null;

  if (phase.kind === "done") {
    return (
      <ShareDone
        fileName={phase.fileName}
        saved={phase.saved}
        remaining={Math.max(0, info.downloads_remaining - 1)}
        onSaveAgain={saveAgain}
      />
    );
  }

  // A link that ended while the page was open (revoked, expired, used up) cannot be tried again.
  if (failed !== null && SHARE_STATE_TEXT[failed.failure.kind].terminal) {
    return <ShareStateMessage failure={failed.failure} variant="page" />;
  }

  const passwordRequired =
    info.password_required ||
    failed?.failure.kind === "password_required" ||
    failed?.failure.kind === "wrong_password";

  return (
    <div>
      <p className="font-mono text-xs uppercase tracking-[0.18em] text-ink-300">Shared with you</p>
      <h1 className="mt-1 break-all text-xl font-semibold text-ink-50">
        {info.file_name ?? "A password-protected file"}
      </h1>
      <p className="mt-2">
        {info.file_name === null
          ? "Someone shared a file with you through CipherForge. Its name stays hidden until it is downloaded."
          : "Someone shared this file with you through CipherForge."}
      </p>

      <div className="mt-4">
        <FactList
          facts={[
            { label: "Size", value: formatBytes(info.size_bytes) },
            { label: "Link expires", value: <DateTime value={info.expires_at} /> },
            { label: "Downloads left", value: String(info.downloads_remaining) },
          ]}
        />
      </div>

      <SharePasswordForm
        passwordRequired={passwordRequired}
        downloading={phase.kind === "downloading"}
        failed={failed}
        onSubmit={(password) => void submit(password)}
      />
    </div>
  );
}
