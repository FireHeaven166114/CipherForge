import { type ReactElement, useLayoutEffect, useRef } from "react";
import { NavLink, useLocation } from "react-router";

import { createLamp, type Lamp } from "../../motion/lamp";
import { useMotion } from "../../motion/useMotion";
import { IndicatorsIcon, InvestigateIcon, OverviewIcon, StatusIcon } from "../hud/Icons";

interface NavItem {
  to: string;
  label: string;
  /** What is drawn when the full name will not fit on one line in a quarter of a phone or in the rail. */
  short?: string;
  end: boolean;
  Icon: (props: { className?: string }) => ReactElement;
}

const NAV_ITEMS: readonly NavItem[] = [
  { to: "/", label: "Overview", end: true, Icon: OverviewIcon },
  { to: "/investigate", label: "Investigate", end: false, Icon: InvestigateIcon },
  { to: "/indicators", label: "Indicators", end: false, Icon: IndicatorsIcon },
  { to: "/status", label: "System status", short: "Status", end: false, Icon: StatusIcon },
];

const LINK =
  "cf-glow relative flex h-full flex-col items-center justify-center gap-1.5 rounded-control px-1 py-2.5 text-center transition-colors md:h-auto md:py-3.5";
// With effects off the current page gets a lit edge and a tint of its own, as well as the accent
// colour. With them on, the gliding lamp (see motion/lamp.ts) draws those, and the link only
// takes the colour.
const ACTIVE_STILL =
  "bg-cipher/10 text-cipher before:absolute before:inset-x-3 before:top-0 before:h-0.5 before:bg-cipher before:shadow-glow md:before:inset-x-auto md:before:inset-y-3 md:before:left-0 md:before:top-auto md:before:h-auto md:before:w-0.5";
const ACTIVE_LAMP = "text-cipher";
const IDLE = "text-ink-300 hover:bg-white/5 hover:text-ink-50";

/**
 * The one primary navigation: a tab bar along the bottom of a phone, a rail down the left edge
 * from tablet width up. Only pages that exist are listed.
 *
 * The rail stretches the full height of the page row, so it can never make a short page scroll;
 * the links inside it stick below the top bar while a long page scrolls past.
 */
export default function NavRail() {
  const motion = useMotion();
  const { pathname } = useLocation();
  const track = useRef<HTMLDivElement>(null);
  const lampElement = useRef<HTMLSpanElement>(null);
  const lamp = useRef<Lamp | null>(null);

  useLayoutEffect(() => {
    const container = track.current;
    const light = lampElement.current;
    if (!motion || container === null || light === null) return;
    const created = createLamp(container, light);
    created.aim(false);
    lamp.current = created;
    return () => {
      created.stop();
      lamp.current = null;
    };
  }, [motion]);

  // The lamp glides when the page changes. The first placement (above) is immediate.
  useLayoutEffect(() => {
    lamp.current?.aim(true);
  }, [pathname]);

  return (
    <nav
      aria-label="Primary"
      className="fixed inset-x-0 bottom-0 z-30 h-16 border-t border-white/10 bg-ink-950/75 backdrop-blur-xl md:static md:z-auto md:h-auto md:w-24 md:flex-none md:border-r md:border-t-0"
    >
      <div ref={track} className="relative h-full md:sticky md:top-14 md:h-auto">
        {motion ? <span ref={lampElement} aria-hidden="true" className="cf-lamp" /> : null}
        <ul className="grid h-full grid-cols-4 md:block md:h-auto">
          {NAV_ITEMS.map(({ to, label, short, end, Icon }) => (
            <li key={to}>
              <NavLink
                to={to}
                end={end}
                className={({ isActive }) => `${LINK} ${isActive ? (motion ? ACTIVE_LAMP : ACTIVE_STILL) : IDLE}`}
              >
                <Icon className="size-6" />
                <span className="text-[0.62rem] font-semibold uppercase leading-tight tracking-[0.12em]">
                  {short === undefined ? (
                    label
                  ) : (
                    <>
                      {/* The short name is what is drawn; screen readers announce the full one. */}
                      <span aria-hidden="true">{short}</span>
                      <span className="sr-only">{label}</span>
                    </>
                  )}
                </span>
              </NavLink>
            </li>
          ))}
        </ul>
      </div>
    </nav>
  );
}
