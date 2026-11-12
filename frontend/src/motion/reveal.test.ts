import { beforeEach, describe, expect, it, vi } from "vitest";

import { stagger, waapi, type WAAPIAnimation } from "./anime";
import { startReveal } from "./reveal";

vi.mock("./anime", () => ({
  stagger: vi.fn((step: number) => ({ staggered: step })),
  waapi: { animate: vi.fn() },
}));

interface Entrance {
  targets: HTMLElement[];
  options: { duration: number; ease: string; opacity: number[]; transform: string[]; onComplete: () => void };
  revert: ReturnType<typeof vi.fn>;
}

let entrances: Entrance[];
let root: HTMLElement;

function addReveal(parent: HTMLElement): HTMLElement {
  const element = document.createElement("section");
  element.setAttribute("data-reveal", "");
  parent.append(element);
  return element;
}

/** MutationObserver callbacks are delivered after the current task's microtasks. */
const settle = () => new Promise((resolve) => setTimeout(resolve, 0));

describe("startReveal", () => {
  beforeEach(() => {
    document.body.replaceChildren();
    root = document.createElement("main");
    document.body.append(root);
    entrances = [];
    vi.mocked(waapi.animate).mockImplementation((targets, options) => {
      const revert = vi.fn();
      entrances.push({
        targets: [...(targets as HTMLElement[])],
        options: options as unknown as Entrance["options"],
        revert,
      });
      return { revert } as unknown as WAAPIAnimation;
    });
  });

  it("plays what is already on the page as one wave, in page order", () => {
    const first = addReveal(root);
    const nested = addReveal(first);
    const last = addReveal(root);
    startReveal(root);

    expect(entrances).toHaveLength(1);
    expect(entrances[0]?.targets).toEqual([first, nested, last]);
    expect(entrances[0]?.options).toMatchObject({ duration: 640, ease: "outExpo", opacity: [0, 1] });
    expect(stagger).toHaveBeenCalledWith(70);
  });

  it("spreads a big wave over at most 520 ms and does not stagger a lone element", () => {
    for (let index = 0; index < 21; index++) addReveal(root);
    startReveal(root);
    expect(stagger).toHaveBeenLastCalledWith(26);

    document.body.replaceChildren();
    root = document.createElement("main");
    document.body.append(root);
    addReveal(root);
    startReveal(root);
    expect(stagger).toHaveBeenLastCalledWith(0);
  });

  it("never calls the engine with an empty list, because it would warn in the console", async () => {
    startReveal(root);
    root.append(document.createElement("div"));
    await settle();
    expect(waapi.animate).not.toHaveBeenCalled();
  });

  it("gives an element that arrives later its own wave, and never a second one", async () => {
    startReveal(root);
    const late = addReveal(root);
    await settle();
    expect(entrances).toHaveLength(1);
    expect(entrances[0]?.targets).toEqual([late]);

    // Moving it re-reports it as added, but it has had its entrance.
    root.prepend(late);
    await settle();
    expect(entrances).toHaveLength(1);
  });

  it("lets an element that was removed before its wave still have one if it comes back", async () => {
    startReveal(root);
    const gone = addReveal(root);
    gone.remove();
    await settle();
    expect(waapi.animate).not.toHaveBeenCalled();

    root.append(gone);
    await settle();
    expect(entrances).toHaveLength(1);
  });

  it("takes the animation's leftovers off an element when its entrance ends", () => {
    addReveal(root);
    const stop = startReveal(root);
    expect(entrances[0]?.revert).not.toHaveBeenCalled();

    entrances[0]?.options.onComplete();
    expect(entrances[0]?.revert).toHaveBeenCalledOnce();

    stop();
    expect(entrances[0]?.revert).toHaveBeenCalledOnce();
  });

  it("cuts a running entrance short on stop, and the element plays again on the next start", () => {
    addReveal(root);
    const stop = startReveal(root);
    expect(entrances).toHaveLength(1);

    stop();
    expect(entrances[0]?.revert).toHaveBeenCalledOnce();

    startReveal(root);
    expect(entrances).toHaveLength(2);
    expect(entrances[1]?.targets).toEqual(entrances[0]?.targets);
  });

  it("does not replay a finished entrance when the effects are switched off and on again", () => {
    addReveal(root);
    const stop = startReveal(root);
    entrances[0]?.options.onComplete();
    stop();

    startReveal(root);
    expect(entrances).toHaveLength(1);
  });

  it("stops watching the page on stop", async () => {
    const stop = startReveal(root);
    stop();
    addReveal(root);
    await settle();
    expect(waapi.animate).not.toHaveBeenCalled();
  });
});
