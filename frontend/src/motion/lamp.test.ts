import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createAnimatable } from "./anime";
import { createLamp } from "./lamp";

vi.mock("./anime", () => ({ createAnimatable: vi.fn() }));

type Spy = ReturnType<typeof vi.fn>;

let slider: { x: Spy; y: Spy; width: Spy; height: Spy; opacity: Spy; revert: Spy };
let remeasure: () => void;
let observed: Element[];
let disconnect: Spy;

/** jsdom does no layout, so a box is whatever the test says it is. */
function place(element: Element, left: number, top: number, width: number, height: number): void {
  element.getBoundingClientRect = () =>
    ({ left, top, width, height, right: left + width, bottom: top + height, x: left, y: top }) as DOMRect;
}

/**
 * A track with three links in a row, 100px apart and 96px wide, that starts 20px from the left of
 * the window; `active` is the index of the link of the open page, if any.
 */
function nav(active: number | null) {
  const track = document.createElement("div");
  place(track, 20, 10, 300, 48);
  const links = ["Overview", "Investigate", "Indicators"].map((name, index) => {
    const link = document.createElement("a");
    link.textContent = name;
    if (index === active) link.setAttribute("aria-current", "page");
    place(link, 20 + index * 100, 14, 96, 40);
    track.append(link);
    return link;
  });
  const lamp = document.createElement("span");
  track.append(lamp);
  return { track, links, lamp };
}

describe("createLamp", () => {
  beforeEach(() => {
    observed = [];
    disconnect = vi.fn();
    slider = { x: vi.fn(), y: vi.fn(), width: vi.fn(), height: vi.fn(), opacity: vi.fn(), revert: vi.fn() };
    vi.mocked(createAnimatable).mockImplementation(() => slider as unknown as ReturnType<typeof createAnimatable>);
    vi.stubGlobal(
      "ResizeObserver",
      class {
        constructor(callback: () => void) {
          remeasure = callback;
        }
        observe(element: Element) {
          observed.push(element);
        }
        disconnect = disconnect;
      },
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("glides onto the link of the open page", () => {
    const { track, lamp } = nav(1);
    createLamp(track, lamp).aim(true);

    expect(slider.x).toHaveBeenCalledWith(100, undefined);
    expect(slider.y).toHaveBeenCalledWith(4, undefined);
    expect(slider.width).toHaveBeenCalledWith(96, undefined);
    expect(slider.height).toHaveBeenCalledWith(40, undefined);
    expect(slider.opacity).toHaveBeenCalledWith(1, undefined);
  });

  it("jumps instead of gliding when asked to", () => {
    const { track, lamp } = nav(2);
    createLamp(track, lamp).aim(false);

    expect(slider.x).toHaveBeenCalledWith(200, 0);
    expect(slider.opacity).toHaveBeenCalledWith(1, 0);
  });

  it("keeps the fractions of a pixel, so the last of four tabs on a phone ends at the window's edge", () => {
    const { track, links, lamp } = nav(2);
    place(track, 0, 0, 390, 64);
    place(links[2] as HTMLElement, 292.5, 0, 97.5, 64);
    createLamp(track, lamp).aim(false);

    expect(slider.x).toHaveBeenCalledWith(292.5, 0);
    expect(slider.width).toHaveBeenCalledWith(97.5, 0);
  });

  it("measures from inside the track's border, where an absolutely placed lamp starts", () => {
    const { track, lamp } = nav(0);
    Object.defineProperties(track, { clientLeft: { value: 2 }, clientTop: { value: 1 } });
    createLamp(track, lamp).aim(false);

    expect(slider.x).toHaveBeenCalledWith(-2, 0);
    expect(slider.y).toHaveBeenCalledWith(3, 0);
  });

  it("goes dark when no link belongs to the open page", () => {
    const { track, lamp } = nav(null);
    createLamp(track, lamp).aim(true);

    expect(slider.opacity).toHaveBeenCalledWith(0, undefined);
    expect(slider.x).not.toHaveBeenCalled();
  });

  it("measures again, without gliding, when the track or a link changes size", () => {
    const { track, links, lamp } = nav(0);
    createLamp(track, lamp);

    expect(observed).toEqual([track, ...links]);
    remeasure();
    expect(slider.x).toHaveBeenCalledWith(0, 0);
    expect(slider.width).toHaveBeenCalledWith(96, 0);
  });

  it("stops watching and puts the lamp back on stop", () => {
    const { track, lamp } = nav(0);
    createLamp(track, lamp).stop();

    expect(disconnect).toHaveBeenCalledOnce();
    expect(slider.revert).toHaveBeenCalledOnce();
  });
});
