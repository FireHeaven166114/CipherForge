import type { ReactElement } from "react";
import { NavLink } from "react-router";

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
  "relative flex h-full flex-col items-center justify-center gap-1.5 px-1 py-2.5 text-center transition md:h-auto md:py-3.5";
// The current page gets a lit edge and a tint as well as the accent colour.
const ACTIVE =
  "bg-cipher/10 text-cipher before:absolute before:inset-x-3 before:top-0 before:h-0.5 before:bg-cipher before:shadow-glow md:before:inset-x-auto md:before:inset-y-3 md:before:left-0 md:before:top-auto md:before:h-auto md:before:w-0.5";
const IDLE = "text-ink-300 hover:bg-ink-800/60 hover:text-ink-50";

/**
 * The one primary navigation: a tab bar along the bottom of a phone, a rail down the left edge
 * from tablet width up. Only pages that exist are listed.
 *
 * The rail stretches the full height of the page row, so it can never make a short page scroll;
 * the links inside it stick below the top bar while a long page scrolls past.
 */
export default function NavRail() {
  return (
    <nav
      aria-label="Primary"
      className="fixed inset-x-0 bottom-0 z-30 h-16 border-t border-ink-700/80 bg-ink-950/90 backdrop-blur-md md:static md:z-auto md:h-auto md:w-24 md:flex-none md:border-r md:border-t-0"
    >
      <ul className="grid h-full grid-cols-4 md:sticky md:top-14 md:block md:h-auto">
        {NAV_ITEMS.map(({ to, label, short, end, Icon }) => (
          <li key={to}>
            <NavLink to={to} end={end} className={({ isActive }) => `${LINK} ${isActive ? ACTIVE : IDLE}`}>
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
    </nav>
  );
}
