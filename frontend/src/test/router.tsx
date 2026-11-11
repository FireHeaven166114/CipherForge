import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router";

/** Prints the current address, so a test can check where a page sent the user. */
function LocationDisplay() {
  const { pathname, search } = useLocation();
  return <p data-testid="location">{`${pathname}${search}`}</p>;
}

interface RenderRouteOptions {
  /** The address to start at. */
  url: string;
  /** The route pattern, for pages that read parameters, such as "/indicators/:indicatorId". */
  path?: string;
}

/** Renders one page inside a router at the given address. */
export function renderRoute(page: ReactElement, { url, path = "*" }: RenderRouteOptions) {
  return render(
    <MemoryRouter initialEntries={[url]}>
      <Routes>
        <Route path={path} element={page} />
      </Routes>
      <LocationDisplay />
    </MemoryRouter>,
  );
}
