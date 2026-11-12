import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import App from "./App";
import { INDICATOR_ID } from "./test/fixtures";
import { serveEverything } from "./test/serveApp";

function renderApp(url: string) {
  return render(
    <MemoryRouter initialEntries={[url]}>
      <App />
    </MemoryRouter>,
  );
}

function navigation() {
  return within(screen.getByRole("navigation", { name: "Primary" }));
}

/** The link marked as the current page. Tests read its accessible name, which is what a screen reader says. */
function currentPage(): HTMLElement | null {
  return navigation().queryByRole("link", { current: "page" });
}

describe("App", () => {
  it("opens on the overview, with the primary navigation marking it as the current page", async () => {
    serveEverything();
    renderApp("/");

    expect(await screen.findByRole("heading", { name: "Overview", level: 1 })).toBeInTheDocument();
    expect(currentPage()).toHaveAccessibleName("Overview");
    expect(navigation().getAllByRole("link").map((link) => link.getAttribute("href"))).toEqual([
      "/",
      "/investigate",
      "/indicators",
      "/status",
    ]);
    expect(document.title).toBe("Overview · CipherForge");
  });

  it("moves between pages from the navigation, marks the current one and moves focus to the content", async () => {
    serveEverything();
    const user = userEvent.setup();
    renderApp("/");
    await screen.findByRole("heading", { name: "Overview", level: 1 });

    await user.click(navigation().getByRole("link", { name: "Investigate" }));

    expect(
      await screen.findByRole("heading", { name: "Investigate an indicator", level: 1 }),
    ).toBeInTheDocument();
    expect(currentPage()).toHaveAccessibleName("Investigate");
    expect(document.title).toBe("Investigate · CipherForge");
    expect(screen.getByRole("main")).toHaveFocus();

    await user.click(navigation().getByRole("link", { name: "Indicators" }));

    expect(await screen.findByRole("heading", { name: "Indicators", level: 1 })).toBeInTheDocument();
    expect(currentPage()).toHaveAccessibleName("Indicators");
    expect(screen.getByRole("main")).toHaveFocus();
  });

  it("keeps Indicators marked, and Overview not, while one indicator is open", async () => {
    serveEverything();
    renderApp(`/indicators/${INDICATOR_ID}`);

    expect(await screen.findByRole("heading", { name: "Indicator details" })).toBeInTheDocument();
    expect(currentPage()).toHaveAccessibleName("Indicators");
  });

  it("serves the system status page", async () => {
    serveEverything();
    renderApp("/status");

    expect(await screen.findByRole("heading", { name: "System status", level: 1 })).toBeInTheDocument();
    expect(await screen.findByText("Operational")).toBeInTheDocument();
    expect(currentPage()).toHaveAccessibleName("System status");
  });

  it("shows a not-found page for an unknown address and links back to the overview", async () => {
    serveEverything();
    const user = userEvent.setup();
    renderApp("/nowhere");

    expect(await screen.findByRole("heading", { name: "Page not found", level: 1 })).toBeInTheDocument();
    expect(currentPage()).toBeNull();
    expect(document.title).toBe("Page not found · CipherForge");

    await user.click(screen.getByRole("link", { name: "Go to the overview" }));

    expect(await screen.findByRole("heading", { name: "Overview", level: 1 })).toBeInTheDocument();
  });

  it("treats a path under an indicator as unknown rather than guessing", async () => {
    serveEverything();
    renderApp(`/indicators/${INDICATOR_ID}/extra`);

    expect(await screen.findByRole("heading", { name: "Page not found", level: 1 })).toBeInTheDocument();
  });

  it("offers a skip link that moves focus to the main content", async () => {
    serveEverything();
    const user = userEvent.setup();
    renderApp("/");
    await screen.findByRole("heading", { name: "Overview", level: 1 });

    await user.tab();
    expect(screen.getByRole("link", { name: "Skip to main content" })).toHaveFocus();
    await user.keyboard("{Enter}");

    expect(screen.getByRole("main")).toHaveFocus();
  });
});
