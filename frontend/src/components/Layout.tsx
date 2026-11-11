import { useEffect, useRef } from "react";
import { NavLink, Outlet, useLocation } from "react-router";

const NAV_ITEMS = [
  { to: "/", label: "Overview", end: true },
  { to: "/investigate", label: "Investigate", end: false },
  { to: "/indicators", label: "Indicators", end: false },
  { to: "/status", label: "System status", end: false },
] as const;

const NAV_LINK =
  "inline-block border-b-2 px-3 py-2 text-sm font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-cyan-400";
// The current page is marked by a bar and a background, not by colour alone.
const NAV_LINK_ACTIVE = "border-cyan-400 bg-slate-800 text-white";
const NAV_LINK_IDLE = "border-transparent text-slate-300 hover:bg-slate-900 hover:text-white";

export default function Layout() {
  const { pathname } = useLocation();
  const main = useRef<HTMLElement>(null);
  const previousPath = useRef(pathname);

  // A client-side navigation does not reload the page, so nothing tells a keyboard or
  // screen-reader user that the content changed. Moving focus to the content does.
  useEffect(() => {
    if (previousPath.current === pathname) return;
    previousPath.current = pathname;
    main.current?.focus();
  }, [pathname]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <a
        href="#main-content"
        onClick={(event) => {
          // Keeps "#main-content" out of the address bar and the history.
          event.preventDefault();
          main.current?.focus();
        }}
        className="sr-only rounded-md bg-cyan-700 px-3 py-2 text-sm font-semibold text-white focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-10 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-300"
      >
        Skip to main content
      </a>
      <header className="border-b border-slate-800">
        <div className="mx-auto flex max-w-6xl flex-wrap items-center gap-x-6 gap-y-2 px-6 pt-4">
          <div className="flex items-center gap-3 pb-2">
            <img src="/favicon.svg" alt="" className="h-8 w-8" />
            <span className="text-lg font-semibold tracking-tight">CipherForge</span>
            <span className="text-sm text-slate-400">Security operations console</span>
          </div>
          <nav aria-label="Primary">
            <ul className="flex flex-wrap gap-1">
              {NAV_ITEMS.map((item) => (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    end={item.end}
                    className={({ isActive }) =>
                      `${NAV_LINK} ${isActive ? NAV_LINK_ACTIVE : NAV_LINK_IDLE}`
                    }
                  >
                    {item.label}
                  </NavLink>
                </li>
              ))}
            </ul>
          </nav>
        </div>
      </header>
      <main
        id="main-content"
        ref={main}
        tabIndex={-1}
        className="mx-auto max-w-6xl px-6 py-8 focus:outline-none"
      >
        <Outlet />
      </main>
    </div>
  );
}
