import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { animate } from "../../motion/anime";
import AnimatedNumber from "./AnimatedNumber";

const state = vi.hoisted(() => ({ motion: false }));

vi.mock("../../motion/useMotion", () => ({ useMotion: () => state.motion }));
vi.mock("../../motion/anime", () => ({ animate: vi.fn() }));

interface Count {
  counter: { value: number };
  options: { value: number; duration: number; onUpdate: () => void; onComplete: () => void };
  cancel: ReturnType<typeof vi.fn>;
}

let counts: Count[];

/** The visible digits: the part assistive technology is told to skip. */
function digitsIn(container: HTMLElement): HTMLElement {
  const digits = container.querySelector<HTMLElement>('[aria-hidden="true"]');
  if (digits === null) throw new Error("no visible digits");
  return digits;
}

describe("AnimatedNumber", () => {
  beforeEach(() => {
    state.motion = false;
    counts = [];
    vi.mocked(animate).mockImplementation((counter, options) => {
      const cancel = vi.fn();
      counts.push({
        counter: counter as Count["counter"],
        options: options as unknown as Count["options"],
        cancel,
      });
      return { cancel } as unknown as ReturnType<typeof animate>;
    });
  });

  it("is just the figure when effects are off", () => {
    const { container } = render(<AnimatedNumber value={12480} />);

    expect(container).toHaveTextContent(/^12,480$/);
    expect(container.querySelector(".sr-only")).toBeNull();
    expect(animate).not.toHaveBeenCalled();
  });

  it("tells assistive technology the exact figure when the drawn one is shortened", () => {
    const { container } = render(
      <AnimatedNumber value={12480} format={() => "12.5K"} spoken={(value) => value.toLocaleString("en-US")} />,
    );

    expect(digitsIn(container)).toHaveTextContent("12.5K");
    expect(screen.getByText("12,480")).toHaveClass("sr-only");
    expect(container.firstElementChild).toHaveAttribute("title", "12,480");
  });

  it("counts up with effects on, while the exact figure is there from the start", () => {
    state.motion = true;
    const { container } = render(<AnimatedNumber value={1000} />);

    expect(screen.getByText("1,000")).toHaveClass("sr-only");
    expect(digitsIn(container)).toHaveTextContent("0");
    expect(counts).toHaveLength(1);
    expect(counts[0]?.counter.value).toBe(0);
    expect(counts[0]?.options).toMatchObject({ value: 1000, duration: 900 });

    const [count] = counts;
    if (count === undefined) throw new Error("the count started");
    count.counter.value = 412.4;
    count.options.onUpdate();
    expect(digitsIn(container)).toHaveTextContent("412");

    count.options.onComplete();
    expect(digitsIn(container)).toHaveTextContent("1,000");
  });

  it("counts on from the figure on screen when the value changes", () => {
    state.motion = true;
    const { rerender } = render(<AnimatedNumber value={1000} />);
    counts[0]?.options.onComplete();

    rerender(<AnimatedNumber value={2500} />);
    expect(counts).toHaveLength(2);
    expect(counts[0]?.cancel).toHaveBeenCalledOnce();
    expect(counts[1]?.counter.value).toBe(1000);
    expect(counts[1]?.options.value).toBe(2500);
  });

  it("picks up a new formatter without restarting the count", () => {
    state.motion = true;
    const { container, rerender } = render(<AnimatedNumber value={50} />);

    rerender(<AnimatedNumber value={50} format={(value) => `${Math.round(value)} hits`} />);
    expect(counts).toHaveLength(1);

    const [count] = counts;
    if (count === undefined) throw new Error("the count started");
    count.counter.value = 7;
    count.options.onUpdate();
    expect(digitsIn(container)).toHaveTextContent("7 hits");
  });

  it("stops counting when it leaves the page", () => {
    state.motion = true;
    const { unmount } = render(<AnimatedNumber value={10} />);
    unmount();
    expect(counts[0]?.cancel).toHaveBeenCalledOnce();
  });
});
