import { MASTER_KEY_SETTING } from "../../features/files/messages";

/**
 * Shown when the server has no master key. Uploading and sharing cannot work then, and the person
 * reading this is usually the one who can fix it, so it names the setting and where to read more.
 */
export default function NotConfiguredNotice() {
  return (
    <div
      role="note"
      className="cf-plate rounded-ui border border-warn/50 p-4 text-sm text-ink-100 [--plate:var(--color-warn)]"
    >
      <p className="flex items-center gap-2 font-semibold text-warn">
        <span aria-hidden="true">▲</span>
        Encrypted files are not set up on this server
      </p>
      <p className="mt-1">
        Uploading and sharing are switched off because the server has no master key. An administrator
        must set <code className="font-mono text-ink-50">{MASTER_KEY_SETTING}</code> in the API&apos;s
        environment and restart it. The steps are in{" "}
        <code className="font-mono text-ink-50">.env.example</code> and the{" "}
        <code className="font-mono text-ink-50">docs/</code> folder.
      </p>
      <p className="mt-1 text-ink-200">
        Files stored earlier stay in the list, but their names cannot be read until the key is set.
      </p>
    </div>
  );
}
