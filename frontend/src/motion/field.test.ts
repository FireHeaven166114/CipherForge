import { afterEach, describe, expect, it, vi } from "vitest";

import { createField, type Field, particleCountFor } from "./field";

type FakeContext = ReturnType<typeof fakeContext>;

function fakeContext() {
  return {
    setTransform: vi.fn(),
    clearRect: vi.fn(),
    beginPath: vi.fn(),
    moveTo: vi.fn(),
    lineTo: vi.fn(),
    stroke: vi.fn(),
    arc: vi.fn(),
    fill: vi.fn(),
    strokeStyle: "",
    fillStyle: "",
    lineWidth: 0,
    globalCompositeOperation: "source-over",
  };
}

function canvasWith(context: FakeContext | null, box: { width: number; height: number }): HTMLCanvasElement {
  const canvas = document.createElement("canvas");
  canvas.getBoundingClientRect = () => box as DOMRect;
  canvas.getContext = vi.fn(() => context) as unknown as HTMLCanvasElement["getContext"];
  return canvas;
}

/** Every dot starts in the middle and drifts straight up at 0.011 pixels per millisecond. */
function fieldOf(context: FakeContext, box: { width: number; height: number }): Field {
  const field = createField(canvasWith(context, box), () => 0.5);
  if (field === null) throw new Error("the fake canvas has a 2D context");
  field.resize();
  return field;
}

/** The x and y of the first dot's halo in the latest frame. */
function firstDot(context: FakeContext): { x: number; y: number } {
  const call = context.arc.mock.calls.at(0) as [number, number] | undefined;
  if (call === undefined) throw new Error("nothing was drawn");
  return { x: call[0], y: call[1] };
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("particleCountFor", () => {
  it("follows the area of the screen, between 18 and 72 dots", () => {
    expect(particleCountFor(1440, 1000)).toBe(60);
    expect(particleCountFor(390, 844)).toBe(18);
    expect(particleCountFor(100, 100)).toBe(18);
    expect(particleCountFor(3840, 2160)).toBe(72);
  });
});

describe("createField", () => {
  it("gives nothing back when the browser has no 2D context", () => {
    expect(createField(canvasWith(null, { width: 100, height: 100 }))).toBeNull();
  });

  it("fits the canvas to its box at no more than one and a half pixels per pixel", () => {
    vi.stubGlobal("devicePixelRatio", 3);
    const context = fakeContext();
    const canvas = canvasWith(context, { width: 1440, height: 1000 });
    createField(canvas)?.resize();

    expect(canvas.width).toBe(2160);
    expect(canvas.height).toBe(1500);
    expect(context.setTransform).toHaveBeenCalledWith(1.5, 0, 0, 1.5, 0, 0);
  });

  it("draws a halo and a core for every dot, and trims the dots when the box shrinks", () => {
    const box = { width: 1440, height: 1000 };
    const context = fakeContext();
    const field = fieldOf(context, box);

    field.draw(16);
    expect(context.arc).toHaveBeenCalledTimes(2 * 60);

    box.width = 100;
    box.height = 100;
    field.resize();
    context.arc.mockClear();
    field.draw(16);
    expect(context.arc).toHaveBeenCalledTimes(2 * 18);
  });

  it("joins dots that are close with lines, and the pointer to the ones near it", () => {
    const context = fakeContext();
    const field = fieldOf(context, { width: 100, height: 100 });

    field.draw(16);
    expect(context.stroke).toHaveBeenCalledTimes((18 * 17) / 2);

    context.stroke.mockClear();
    field.setPointer({ x: 50, y: 50, inside: true });
    field.draw(16);
    expect(context.stroke).toHaveBeenCalledTimes((18 * 17) / 2 + 18);

    context.stroke.mockClear();
    field.setPointer({ x: 650, y: 50, inside: true });
    field.draw(16);
    expect(context.stroke).toHaveBeenCalledTimes((18 * 17) / 2);
  });

  it("restores the compositing mode after each frame", () => {
    const context = fakeContext();
    fieldOf(context, { width: 100, height: 100 }).draw(16);
    expect(context.globalCompositeOperation).toBe("source-over");
  });

  it("treats a long pause as one short step, so a returning tab does not fling the dots", () => {
    const resumed = fakeContext();
    fieldOf(resumed, { width: 1440, height: 1000 }).draw(10_000);
    expect(firstDot(resumed).y).toBeCloseTo(500 - 0.011 * 64, 3);

    const frozen = fakeContext();
    fieldOf(frozen, { width: 1440, height: 1000 }).draw(-5);
    expect(firstDot(frozen).y).toBe(500);
  });

  it("brings a dot that drifts off the top back in at the bottom", () => {
    const context = fakeContext();
    const field = fieldOf(context, { width: 100, height: 100 });

    for (let frame = 0; frame < 149; frame++) field.draw(64);
    context.arc.mockClear();
    field.draw(64);

    const { y } = firstDot(context);
    expect(y).toBeGreaterThan(50);
    expect(y).toBeLessThanOrEqual(124);
  });

  it("pushes the dots near the pointer away from it", () => {
    const calm = fakeContext();
    fieldOf(calm, { width: 100, height: 100 }).draw(16);
    expect(firstDot(calm).x).toBe(50);

    const pushed = fakeContext();
    const field = fieldOf(pushed, { width: 100, height: 100 });
    field.setPointer({ x: 40, y: 50, inside: true });
    field.draw(16);
    expect(firstDot(pushed).x).toBeGreaterThan(50);
  });

  it("wipes the canvas on clear", () => {
    const context = fakeContext();
    const field = fieldOf(context, { width: 1440, height: 1000 });
    field.clear();
    expect(context.clearRect).toHaveBeenLastCalledWith(0, 0, 1440, 1000);
  });
});
