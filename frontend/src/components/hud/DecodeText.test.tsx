import { act, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { animate, scrambleText } from "../../motion/anime";
import DecodeText from "./DecodeText";

const state = vi.hoisted(() => ({ motion: false }));

vi.mock("../../motion/useMotion", () => ({ useMotion: () => state.motion }));
vi.mock("../../motion/anime", () => ({
  animate: vi.fn(),
  scrambleText: vi.fn((options: unknown) => ({ scramble: options })),
}));

interface Scramble {
  element: HTMLElement;
  options: { textContent: { scramble: { text: string; duration: number } }; onComplete: () => void };
  cancel: ReturnType<typeof vi.fn>;
}

let scrambles: Scramble[];

function scramblingElement(container: HTMLElement): HTMLElement {
  const element = container.querySelector<HTMLElement>('[aria-hidden="true"]');
  if (element === null) throw new Error("nothing is scrambling");
  return element;
}

describe("DecodeText", () => {
  beforeEach(() => {
    state.motion = false;
    scrambles = [];
    vi.mocked(animate).mockImplementation((element, options) => {
      const cancel = vi.fn();
      scrambles.push({
        element: element as HTMLElement,
        options: options as unknown as Scramble["options"],
        cancel,
      });
      return { cancel } as unknown as ReturnType<typeof animate>;
    });
  });

  it("is plain text when effects are off", () => {
    render(<DecodeText text="Overview" className="heading" />);

    expect(screen.getByText("Overview")).toHaveClass("heading");
    expect(animate).not.toHaveBeenCalled();
  });

  it("does not decode text that is too long to be worth it", () => {
    state.motion = true;
    render(<DecodeText text={"word ".repeat(40)} />);
    expect(animate).not.toHaveBeenCalled();
  });

  it("starts as a placeholder of the same shape, while the real text stays readable", () => {
    state.motion = true;
    const { container } = render(<DecodeText text="Investigate an indicator" className="heading" />);

    expect(screen.getByText("Investigate an indicator")).toHaveClass("sr-only");
    const element = scramblingElement(container);
    expect(element).toHaveClass("heading");
    expect(element.textContent).toBe("Investigate an indicator".replace(/\S/g, "·"));
    expect(scrambles).toHaveLength(1);
    expect(scrambles[0]?.element).toBe(element);
  });

  it("takes longer for longer text, but never less than 380 ms or more than 800 ms", () => {
    state.motion = true;
    const durations = ["Hi", "Investigate an indicator", "a".repeat(120)].map((text) => {
      render(<DecodeText text={text} />);
      const call = vi.mocked(scrambleText).mock.calls.at(-1)?.[0] as { duration: number } | undefined;
      return call?.duration;
    });
    expect(durations).toEqual([380, 672, 800]);
  });

  it("settles into the plain text once it has resolved, and does not decode it again", () => {
    state.motion = true;
    const { container, rerender } = render(<DecodeText text="System status" className="heading" />);

    act(() => {
      scrambles[0]?.options.onComplete();
    });
    expect(container.querySelector('[aria-hidden="true"]')).toBeNull();
    expect(container.querySelector(".sr-only")).toBeNull();
    expect(screen.getByText("System status")).toHaveClass("heading");

    rerender(<DecodeText text="System status" className="heading" />);
    expect(scrambles).toHaveLength(1);
  });

  it("decodes again when the text changes, and stops when it leaves the page", () => {
    state.motion = true;
    const { rerender, unmount } = render(<DecodeText text="Indicators" />);
    act(() => {
      scrambles[0]?.options.onComplete();
    });

    rerender(<DecodeText text="Indicator details" />);
    expect(scrambles).toHaveLength(2);
    expect(scrambles[1]?.options.textContent.scramble.text).toBe("Indicator details");

    unmount();
    expect(scrambles[1]?.cancel).toHaveBeenCalledOnce();
  });
});
