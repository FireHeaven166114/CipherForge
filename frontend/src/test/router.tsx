import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter, Route, Routes, parsePath, useLocation } from "react-router";

/** Prints the current address and router state, so a test can check where a page sent the user. */
function LocationDisplay() {
  const { pathname, search, state } = useLocation();
  return (
    <>
      <p data-testid="location">{`${pathname}${search}`}</p>
      <p data-testid="location-state">{JSON.stringify(state ?? null)}</p>
    </>
  );
}

interface RenderRouteOptions {
  /** The address to start at. */
  url: string;
  /** The route pattern, for pages that read parameters, such as "/indicators/:indicatorId". */
  path?: string;
  /** Router state to start with, as the command palette passes to the Investigate page. */
  state?: unknown;
}

/** Renders one page inside a router at the given address. */
export function renderRoute(page: ReactElement, { url, path = "*", state }: RenderRouteOptions) {
  const entry = state === undefined ? url : { ...parsePath(url), state };
  return render(
    <MemoryRouter initialEntries={[entry]}>
      <Routes>
        <Route path={path} element={page} />
      </Routes>
      <LocationDisplay />
    </MemoryRouter>,
  );
}

/** The router state the page last saw, as printed by LocationDisplay. */
export function currentState(): unknown {
  const text = document.querySelector('[data-testid="location-state"]')?.textContent ?? "null";
  return JSON.parse(text);
}
