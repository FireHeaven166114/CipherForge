import { afterEach, beforeEach, describe, expect, it, type Mock, vi } from "vitest";

import { type PointerPosition, trackPointer } from "./pointer";

let frames: FrameRequestCallback[];
let onFrame: Mock<(position: PointerPosition) => void>;

function stubMatchMedia(matches: boolean) {
  vi.stubGlobal("matchMedia", () => ({ matches }));
}

function pointerEvent(type: string, x: number, y: number, pointerType = "mouse"): Event {
  const event = new MouseEvent(type, { clientX: x, clientY: y });
  Object.defineProperty(event, "pointerType", { value: pointerType });
  return event;
}

function move(x: number, y: number, pointerType?: string) {
  window.dispatchEvent(pointerEvent("pointermove", x, y, pointerType));
}

/** Runs the animation frames that were asked for, as the browser would. */
function runFrame() {
  for (const callback of frames.splice(0)) callback(0);
}

describe("trackPointer", () => {
  beforeEach(() => {
    frames = [];
    onFrame = vi.fn<(position: PointerPosition) => void>();
    stubMatchMedia(true);
    vi.stubGlobal("requestAnimationFrame", (callback: FrameRequestCallback) => frames.push(callback));
    vi.stubGlobal("cancelAnimationFrame", vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("reports the latest position once per frame, however many events arrived", () => {
    const stop = trackPointer(onFrame);
    move(10, 20);
    move(30, 40);
    expect(frames).toHaveLength(1);
    runFrame();
    expect(onFrame).toHaveBeenCalledOnce();
    expect(onFrame).toHaveBeenCalledWith({ x: 30, y: 40, inside: true });
    stop();
  });

  it("is skipped on a device with no hover, and without matchMedia", () => {
    stubMatchMedia(false);
    const stop = trackPointer(onFrame);
    move(1, 2);
    expect(frames).toHaveLength(0);
    stop();

    vi.stubGlobal("matchMedia", undefined);
    trackPointer(onFrame)();
    move(1, 2);
    expect(frames).toHaveLength(0);
    expect(onFrame).not.toHaveBeenCalled();
  });

  it("ignores a finger, which has no hover", () => {
    const stop = trackPointer(onFrame);
    move(5, 5, "touch");
    expect(frames).toHaveLength(0);
    move(5, 5, "pen");
    expect(frames).toHaveLength(1);
    stop();
  });

  it("reports when the pointer leaves the page or the window loses focus, but only after it was seen", () => {
    const stop = trackPointer(onFrame);
    document.documentElement.dispatchEvent(new Event("pointerleave"));
    expect(frames).toHaveLength(0);

    move(7, 9);
    runFrame();
    document.documentElement.dispatchEvent(new Event("pointerleave"));
    runFrame();
    expect(onFrame).toHaveBeenLastCalledWith({ x: 7, y: 9, inside: false });

    move(7, 9);
    runFrame();
    window.dispatchEvent(new Event("blur"));
    runFrame();
    expect(onFrame).toHaveBeenLastCalledWith({ x: 7, y: 9, inside: false });
    stop();
  });

  it("reports again when the page scrolls under a pointer that stands still", () => {
    const stop = trackPointer(onFrame);
    document.dispatchEvent(new Event("scroll", { bubbles: true }));
    expect(frames).toHaveLength(0);

    move(3, 4);
    runFrame();
    document.dispatchEvent(new Event("scroll", { bubbles: true }));
    runFrame();
    expect(onFrame).toHaveBeenCalledTimes(2);
    expect(onFrame).toHaveBeenLastCalledWith({ x: 3, y: 4, inside: true });
    stop();
  });

  it("stops listening and cancels a frame that was already asked for", () => {
    const stop = trackPointer(onFrame);
    move(1, 1);
    stop();
    expect(cancelAnimationFrame).toHaveBeenCalledWith(1);

    move(2, 2);
    document.documentElement.dispatchEvent(new Event("pointerleave"));
    expect(frames).toHaveLength(1);
    expect(onFrame).not.toHaveBeenCalled();
  });
});
