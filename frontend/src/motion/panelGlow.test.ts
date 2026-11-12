import { beforeEach, describe, expect, it, vi } from "vitest";

import { startPanelGlow } from "./panelGlow";
import { type PointerPosition, trackPointer } from "./pointer";

vi.mock("./pointer");

let report: (position: PointerPosition) => void;
let stopTracking: ReturnType<typeof vi.fn>;

function place(className: string, left: number, top: number, width = 200, height = 100): HTMLElement {
  const element = document.createElement("div");
  element.className = className;
  element.getBoundingClientRect = () =>
    ({ left, top, width, height, right: left + width, bottom: top + height, x: left, y: top }) as DOMRect;
  document.body.append(element);
  return element;
}

describe("startPanelGlow", () => {
  beforeEach(() => {
    document.body.replaceChildren();
    stopTracking = vi.fn();
    vi.mocked(trackPointer).mockImplementation((onFrame) => {
      report = onFrame;
      return stopTracking as () => void;
    });
  });

  it("lights the panels and glowing controls near the pointer and leaves far ones alone", () => {
    const panel = place("hud-panel", 0, 0);
    const link = place("cf-glow", 150, 0, 60, 30);
    const far = place("hud-panel", 0, 900);
    startPanelGlow();

    report({ x: 50.26, y: 20, inside: true });
    expect(panel).toHaveAttribute("data-lit");
    expect(panel.style.getPropertyValue("--mx")).toBe("50.3px");
    expect(panel.style.getPropertyValue("--my")).toBe("20.0px");
    expect(link).toHaveAttribute("data-lit");
    expect(link.style.getPropertyValue("--mx")).toBe("-99.7px");
    expect(far).not.toHaveAttribute("data-lit");
    expect(far.style.getPropertyValue("--mx")).toBe("");
  });

  it("reaches 140 pixels past an element's edge, and no further", () => {
    const panel = place("hud-panel", 0, 0);
    startPanelGlow();

    report({ x: 340, y: 50, inside: true });
    expect(panel).toHaveAttribute("data-lit");
    report({ x: 341, y: 50, inside: true });
    expect(panel).not.toHaveAttribute("data-lit");
  });

  it("puts every light out when the pointer leaves", () => {
    const panel = place("hud-panel", 0, 0);
    startPanelGlow();
    report({ x: 10, y: 10, inside: true });
    expect(panel).toHaveAttribute("data-lit");

    report({ x: 10, y: 10, inside: false });
    expect(panel).not.toHaveAttribute("data-lit");
  });

  it("stops following the pointer and puts the lights out when it is stopped", () => {
    const panel = place("hud-panel", 0, 0);
    const stop = startPanelGlow();
    report({ x: 10, y: 10, inside: true });

    stop();
    expect(stopTracking).toHaveBeenCalledOnce();
    expect(panel).not.toHaveAttribute("data-lit");
  });
});
