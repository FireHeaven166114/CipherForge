import { useCallback, useEffect, useRef, useState } from "react";
import { Outlet, useLocation } from "react-router";

import Atmosphere from "./shell/Atmosphere";
import CommandPalette from "./shell/CommandPalette";
import MotionDirector from "./shell/MotionDirector";
import NavRail from "./shell/NavRail";
import SimulationBanner from "./shell/SimulationBanner";
import TopBar from "./shell/TopBar";
import { useShortcuts } from "./shell/useShortcuts";
import { ServiceStatusProvider } from "./status/ServiceStatusProvider";

/** The frame around every page. The API check lives here so the top bar and the pages share it. */
export default function Layout() {
  return (
    <ServiceStatusProvider>
      <Shell />
    </ServiceStatusProvider>
  );
}

function Shell() {
  const { pathname } = useLocation();
  const main = useRef<HTMLElement>(null);
  const previousPath = useRef(pathname);
  const [paletteOpen, setPaletteOpen] = useState(false);

  const openPalette = useCallback(() => setPaletteOpen(true), []);
  const closePalette = useCallback(() => setPaletteOpen(false), []);
  const togglePalette = useCallback(() => setPaletteOpen((open) => !open), []);
  useShortcuts({ onTogglePalette: togglePalette, onOpenPalette: openPalette });

  // A client-side navigation does not reload the page, so nothing tells a keyboard or
  // screen-reader user that the content changed. Moving focus to the content does.
  useEffect(() => {
    if (previousPath.current === pathname) return;
    previousPath.current = pathname;
    main.current?.focus();
  }, [pathname]);

  return (
    <div className="relative flex min-h-screen flex-col text-ink-100">
      <Atmosphere />
      <a
        href="#main-content"
        onClick={(event) => {
          // Keeps "#main-content" out of the address bar and the history.
          event.preventDefault();
          main.current?.focus();
        }}
        className="sr-only rounded-control bg-cipher px-3 py-2 text-sm font-semibold text-void focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50"
      >
        Skip to main content
      </a>
      <TopBar onOpenPalette={openPalette} />
      <SimulationBanner />
      <div className="relative z-10 flex-1 md:flex">
        <NavRail />
        <main
          id="main-content"
          ref={main}
          tabIndex={-1}
          className="@container mx-auto min-w-0 max-w-[120rem] flex-1 px-3 pb-24 pt-5 focus:outline-none md:px-6 md:pb-10 md:pt-6 lg:px-8"
        >
          <Outlet />
        </main>
      </div>
      <MotionDirector main={main} />
      <CommandPalette open={paletteOpen} onClose={closePalette} />
    </div>
  );
}
