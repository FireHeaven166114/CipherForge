import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router";
import { afterEach, describe, expect, it } from "vitest";

import App from "../App";
import { EFFECTS_STORAGE_KEY, EffectsProvider } from "../effects/EffectsProvider";
import { makeProviders, makeStats } from "../test/fixtures";
import { serveEverything } from "../test/serveApp";

function renderApp(url = "/") {
  return render(
    <EffectsProvider>
      <MemoryRouter initialEntries={[url]}>
        <App />
      </MemoryRouter>
    </EffectsProvider>,
  );
}

async function ready(url = "/") {
  const user = userEvent.setup();
  renderApp(url);
  await screen.findByRole("heading", { level: 1 });
  return user;
}

afterEach(() => {
  window.localStorage.clear();
  delete document.documentElement.dataset.effects;
});

describe("Layout status area", () => {
  it("shows the API's state in words", async () => {
    serveEverything();
    await ready();

    expect(await screen.findByText("API ONLINE")).toBeInTheDocument();
  });

  it("keeps the top bar and the status page in agreement, with one check for both", async () => {
    const api = serveEverything();
    const healthy = api.getMockImplementation();
    let up = true;
    api.mockImplementation((input, init) =>
      !up && /^\/(health|ready)$/.test(String(input))
        ? Promise.reject(new TypeError("Failed to fetch"))
        : (healthy?.(input, init) ?? Promise.reject(new Error("No handler."))),
    );
    const checks = () => api.mock.calls.filter(([url]) => /^\/(health|ready)$/.test(String(url))).length;
    const user = await ready("/status");
    expect(await screen.findByText("API ONLINE")).toBeInTheDocument();
    expect(checks()).toBe(2);

    up = false;
    await user.click(screen.getByRole("button", { name: "Refresh" }));

    expect(await screen.findByText("API OFFLINE")).toBeInTheDocument();
    expect(screen.getByText("Down")).toBeInTheDocument();
    expect(checks()).toBe(4);
  });

  it("shows who is signed in as a role, and flags development sign-in", async () => {
    serveEverything();
    await ready();

    expect(await screen.findByText("SecurityAnalyst")).toBeInTheDocument();
    expect(screen.getByText("Dev auth")).toBeInTheDocument();
    expect(screen.queryByText("dev-user")).not.toBeInTheDocument();
  });

  it("says so when nobody is signed in", async () => {
    serveEverything({ me: null });
    await ready();

    expect(await screen.findByText("Not signed in")).toBeInTheDocument();
  });

  it("warns across every page that simulated providers produce demo data", async () => {
    serveEverything({ stats: makeStats({ providers: makeProviders(true) }) });
    await ready("/status");

    expect(await screen.findByText(/Simulated providers/)).toBeInTheDocument();
  });

  it("shows no simulation warning for real providers", async () => {
    serveEverything();
    await ready();
    await screen.findByText("API ONLINE");

    expect(screen.queryByText(/Simulated providers/)).not.toBeInTheDocument();
  });
});

describe("Command palette", () => {
  it("opens with Ctrl+K, takes focus, and jumps to the page that was picked", async () => {
    serveEverything();
    const user = await ready();

    await user.keyboard("{Control>}k{/Control}");

    const dialog = await screen.findByRole("dialog", { name: "Command palette" });
    const search = within(dialog).getByRole("combobox");
    expect(search).toHaveFocus();

    await user.type(search, "status");
    await user.click(within(dialog).getByRole("option", { name: /Go to System status/ }));

    expect(await screen.findByRole("heading", { name: "System status", level: 1 })).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(screen.getByRole("main")).toHaveFocus();
  });

  it("moves through the options with the arrow keys, wrapping at both ends, and runs the highlighted one with Enter", async () => {
    serveEverything();
    const user = await ready();

    await user.click(screen.getByRole("button", { name: "Command palette" }));
    const options = () => within(screen.getByRole("dialog")).getAllByRole("option");
    expect(options()[0]).toHaveAttribute("aria-selected", "true");

    await user.keyboard("{ArrowUp}");
    expect(options().at(-1)).toHaveAttribute("aria-selected", "true");

    // last -> first -> second -> third, which is "Go to Indicators"
    await user.keyboard("{ArrowDown}{ArrowDown}{ArrowDown}");
    expect(options()[2]).toHaveAttribute("aria-selected", "true");
    await user.keyboard("{Enter}");

    expect(await screen.findByRole("heading", { name: "Indicators", level: 1 })).toBeInTheDocument();
  });

  it("closes on Escape and gives focus back to the control that opened it", async () => {
    serveEverything();
    const user = await ready();
    const trigger = screen.getByRole("button", { name: "Command palette" });

    await user.click(trigger);
    expect(await screen.findByRole("dialog")).toBeInTheDocument();
    await user.keyboard("{Escape}");

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(trigger).toHaveFocus();
  });

  it("opens with the slash key", async () => {
    serveEverything();
    const user = await ready();

    await user.keyboard("/");

    expect(await screen.findByRole("dialog", { name: "Command palette" })).toBeInTheDocument();
  });

  it("searches stored indicators for what was typed", async () => {
    serveEverything();
    const user = await ready();

    await user.keyboard("{Control>}k{/Control}");
    await user.type(screen.getByRole("combobox"), "example.com");
    await user.click(screen.getByRole("option", { name: /Search indicators for/ }));

    expect(await screen.findByRole("heading", { name: "Indicators", level: 1 })).toBeInTheDocument();
    expect(screen.getByRole("searchbox", { name: "Search" })).toHaveValue("example.com");
  });
});

describe("Keyboard shortcuts", () => {
  it("goes to a page with G then a letter", async () => {
    serveEverything();
    const user = await ready();

    await user.keyboard("gi");
    expect(await screen.findByRole("heading", { name: "Investigate an indicator", level: 1 })).toBeInTheDocument();

    await user.keyboard("gs");
    expect(await screen.findByRole("heading", { name: "System status", level: 1 })).toBeInTheDocument();
  });

  it("leaves the keys alone while typing in a field", async () => {
    serveEverything();
    const user = await ready("/investigate");

    await user.type(screen.getByRole("textbox"), "gs/");

    expect(screen.getByRole("heading", { name: "Investigate an indicator", level: 1 })).toBeInTheDocument();
    expect(screen.getByRole("textbox")).toHaveValue("gs/");
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});

describe("Visual effects switch", () => {
  it("turns effects off and remembers the choice", async () => {
    serveEverything();
    const user = await ready();
    const toggle = screen.getByRole("button", { name: "Effects" });
    expect(toggle).toHaveAttribute("aria-pressed", "true");
    expect(document.documentElement.dataset.effects).toBe("on");

    await user.click(toggle);

    expect(toggle).toHaveAttribute("aria-pressed", "false");
    expect(document.documentElement.dataset.effects).toBe("off");
    expect(window.localStorage.getItem(EFFECTS_STORAGE_KEY)).toBe("off");
  });

  it("starts with effects off when the browser remembers that choice", async () => {
    window.localStorage.setItem(EFFECTS_STORAGE_KEY, "off");
    serveEverything();
    await ready();

    expect(screen.getByRole("button", { name: "Effects" })).toHaveAttribute("aria-pressed", "false");
    expect(document.documentElement.dataset.effects).toBe("off");
  });
});
