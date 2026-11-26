import type { ReactNode } from "react";

import CipherWheel from "../hud/CipherWheel";

/**
 * The page a recipient sees: a small centred card with the product's name and nothing else. It is
 * deliberately not the console. There is no navigation, no sign-in state and no link to anything
 * else, because the person who opened a share link has no account and no reason to explore. The
 * backdrop reuses the console's still layers; the moving ones belong to the console's shell.
 */
export default function SharePageFrame({ children }: { children: ReactNode }) {
  return (
    <div className="relative flex min-h-screen flex-col items-center justify-center px-4 py-10 text-ink-100">
      <div aria-hidden="true" className="cf-atmosphere">
        <div className="cf-backdrop" />
        <div className="cf-grain" />
        <div className="cf-vignette" />
      </div>

      <main className="relative z-10 w-full max-w-lg">
        <p className="mb-5 flex items-center justify-center gap-3 font-mono text-sm tracking-[0.3em] text-ink-100">
          <CipherWheel className="size-9" />
          CIPHERFORGE
        </p>
        <div className="hud-panel rounded-ui p-6 text-sm text-ink-200 sm:p-8">{children}</div>
        <p className="mt-4 text-center text-xs text-ink-300">
          Files on CipherForge are stored encrypted, and each one is checked before it is released.
        </p>
      </main>
    </div>
  );
}
