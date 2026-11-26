import { Link } from "react-router";

import { useEffects } from "../../effects/useEffects";
import CipherWheel from "../hud/CipherWheel";
import { SearchIcon, SparkleIcon } from "../hud/Icons";
import Kbd from "../hud/Kbd";
import ApiBeacon from "./ApiBeacon";
import IdentityChip from "./IdentityChip";
import IstClock from "./IstClock";

function paletteKeys(): string {
  return /Mac|iPhone|iPad/i.test(navigator.userAgent) ? "⌘ K" : "Ctrl K";
}

const ICON_BUTTON =
  "cf-glow flex h-9 shrink-0 items-center justify-center gap-2 whitespace-nowrap rounded-control border border-white/10 bg-ink-900/60 px-2.5 text-ink-200 transition hover:border-cipher/50 hover:text-ink-50 disabled:cursor-not-allowed disabled:opacity-50";

/**
 * The bar is its own size container, and each extra only appears once the bar is wide enough to
 * hold it without squeezing the rest. Container queries measure in `rem` of the root font size, so
 * larger text makes every extra give way sooner, which a viewport media query would not do.
 * Everything that is dropped is still reachable: the palette, the effects switch and the home link
 * keep their names for screen readers.
 */
export default function TopBar({ onOpenPalette }: { onOpenPalette: () => void }) {
  const { enabled, forcedOff, toggle } = useEffects();

  return (
    <header className="@container sticky top-0 z-30 border-b border-white/10 bg-ink-950/70 backdrop-blur-xl">
      {/* A spectral hairline along the bottom edge, the way the panels carry one along the top. */}
      <span
        aria-hidden="true"
        className="pointer-events-none absolute inset-x-0 -bottom-px h-px bg-gradient-to-r from-transparent via-cipher/60 to-transparent"
      />
      <div className="flex h-14 items-center gap-2 px-3 @3xl:gap-3 @3xl:px-5">
        {/* No aria-label: the link is named by the words it shows, so the two can never disagree. */}
        <Link to="/" className="flex shrink-0 items-center gap-2.5">
          <CipherWheel className="size-9" spinning={enabled} />
          <span className="sr-only flex flex-col leading-none @lg:not-sr-only">
            <span className="text-gradient animate-aurora whitespace-nowrap text-lg font-bold tracking-[0.22em]">
              CIPHERFORGE
            </span>{" "}
            <span className="mt-1 hidden whitespace-nowrap text-[0.6rem] uppercase tracking-[0.3em] text-ink-300 @3xl:block">
              Security operations console
            </span>
          </span>
        </Link>

        <div className="ml-auto flex items-center gap-2">
          <button
            type="button"
            onClick={onOpenPalette}
            aria-keyshortcuts="Control+K Meta+K"
            className={`${ICON_BUTTON} @3xl:min-w-56 @3xl:justify-between`}
          >
            <span className="flex items-center gap-2">
              <SearchIcon className="size-4" />
              <span className="sr-only @3xl:not-sr-only">Command palette</span>
            </span>
            <span aria-hidden="true" className="hidden @3xl:block">
              <Kbd>{paletteKeys()}</Kbd>
            </span>
          </button>

          <button
            type="button"
            onClick={toggle}
            disabled={forcedOff}
            aria-pressed={enabled}
            title={forcedOff ? "Your system asks for reduced motion, so effects stay off." : undefined}
            className={`${ICON_BUTTON} ${enabled ? "border-cipher/50 text-cipher shadow-glow" : ""}`}
          >
            <SparkleIcon className="size-4" />
            <span className="sr-only @4xl:not-sr-only @4xl:text-xs @4xl:font-semibold @4xl:uppercase @4xl:tracking-[0.12em]">
              Effects
            </span>
          </button>

          <span className="hidden h-6 w-px shrink-0 bg-ink-700 @5xl:block" aria-hidden="true" />
          <span className="hidden shrink-0 whitespace-nowrap @5xl:block">
            <IstClock />
          </span>
          <IdentityChip />
          <ApiBeacon />
        </div>
      </div>
    </header>
  );
}
