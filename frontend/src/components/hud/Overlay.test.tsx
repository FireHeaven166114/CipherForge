import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";

import Overlay from "./Overlay";

function mountRoot(): HTMLElement {
  const root = document.createElement("div");
  root.id = "root";
  document.body.appendChild(root);
  return root;
}

function Demo() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        Open
      </button>
      <Overlay open={open} onClose={() => setOpen(false)} label="Test dialog">
        <button type="button">First</button>
        <button type="button">Last</button>
      </Overlay>
    </>
  );
}

function Stacked() {
  const [first, setFirst] = useState(true);
  const [second, setSecond] = useState(false);
  return (
    <>
      <Overlay open={first} onClose={() => setFirst(false)} label="First dialog">
        <button type="button" onClick={() => setSecond(true)}>
          Open second
        </button>
      </Overlay>
      <Overlay open={second} onClose={() => setSecond(false)} label="Second dialog">
        <button type="button">Inside second</button>
      </Overlay>
    </>
  );
}

function WithInitialFocus() {
  const preferred = useRef<HTMLButtonElement>(null);
  return (
    <Overlay open onClose={() => undefined} label="Dialog" initialFocus={preferred}>
      <button type="button">First</button>
      <button type="button" ref={preferred}>
        Preferred
      </button>
    </Overlay>
  );
}

// A map marker is a focusable SVG element, not an HTML one.
function FromMarker() {
  const [open, setOpen] = useState(false);
  return (
    <>
      <svg role="group" aria-label="Map">
        <g role="button" tabIndex={0} aria-label="Marker" onClick={() => setOpen(true)} />
      </svg>
      <Overlay open={open} onClose={() => setOpen(false)} label="Marker details">
        <button type="button">Inside</button>
      </Overlay>
    </>
  );
}

describe("Overlay", () => {
  it("renders nothing while closed", () => {
    render(
      <Overlay open={false} onClose={() => undefined} label="Closed">
        <button type="button">Inside</button>
      </Overlay>,
    );

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(document.documentElement).not.toHaveClass("overflow-hidden");
  });

  it("moves focus in, locks the page behind it, and puts everything back on close", async () => {
    const user = userEvent.setup();
    const root = mountRoot();
    render(<Demo />, { container: root });
    const opener = screen.getByRole("button", { name: "Open" });

    await user.click(opener);

    expect(screen.getByRole("dialog", { name: "Test dialog" })).toHaveAttribute("aria-modal", "true");
    expect(screen.getByRole("button", { name: "First" })).toHaveFocus();
    expect(root).toHaveAttribute("inert");
    expect(document.documentElement).toHaveClass("overflow-hidden");

    await user.keyboard("{Escape}");

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(root).not.toHaveAttribute("inert");
    expect(document.documentElement).not.toHaveClass("overflow-hidden");
    expect(opener).toHaveFocus();
  });

  it("focuses the element it was told to focus first", () => {
    render(<WithInitialFocus />);

    expect(screen.getByRole("button", { name: "Preferred" })).toHaveFocus();
  });

  it("keeps Tab and Shift+Tab inside the dialog", async () => {
    const user = userEvent.setup();
    render(<Demo />);
    await user.click(screen.getByRole("button", { name: "Open" }));
    const first = screen.getByRole("button", { name: "First" });
    const last = screen.getByRole("button", { name: "Last" });

    last.focus();
    await user.tab();
    expect(first).toHaveFocus();

    await user.tab({ shift: true });
    expect(last).toHaveFocus();
  });

  it("closes on a press on the backdrop, but not on a press inside the dialog", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    render(
      <Overlay open onClose={onClose} label="Dialog">
        <button type="button">Inside</button>
      </Overlay>,
    );

    await user.click(screen.getByRole("button", { name: "Inside" }));
    expect(onClose).not.toHaveBeenCalled();

    await user.click(screen.getByRole("dialog").parentElement as HTMLElement);
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("leaves focus on the opener when a press on the backdrop closes it", async () => {
    const user = userEvent.setup();
    render(<Demo />);
    const opener = screen.getByRole("button", { name: "Open" });
    await user.click(opener);

    await user.click(screen.getByRole("dialog").parentElement as HTMLElement);

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
  });

  it("gives focus back to an SVG element that opened it", async () => {
    const user = userEvent.setup();
    render(<FromMarker />);
    const marker = screen.getByRole("button", { name: "Marker" });

    await user.click(marker);
    expect(screen.getByRole("dialog", { name: "Marker details" })).toBeInTheDocument();
    await user.keyboard("{Escape}");

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(marker).toHaveFocus();
  });

  it("lets Escape close only the topmost of several overlays and unlocks the page after the last", async () => {
    const user = userEvent.setup();
    const root = mountRoot();
    render(<Stacked />, { container: root });
    await user.click(screen.getByRole("button", { name: "Open second" }));
    expect(screen.getByRole("dialog", { name: "Second dialog" })).toBeInTheDocument();

    await user.keyboard("{Escape}");

    expect(screen.queryByRole("dialog", { name: "Second dialog" })).not.toBeInTheDocument();
    expect(screen.getByRole("dialog", { name: "First dialog" })).toBeInTheDocument();
    expect(root).toHaveAttribute("inert");
    expect(document.documentElement).toHaveClass("overflow-hidden");

    await user.keyboard("{Escape}");

    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(root).not.toHaveAttribute("inert");
    expect(document.documentElement).not.toHaveClass("overflow-hidden");
  });
});
