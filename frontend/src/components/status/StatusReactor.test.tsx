import { render } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import StatusReactor from "./StatusReactor";

function corePath(container: HTMLElement): string {
  const paths = container.querySelectorAll("path");
  return paths[paths.length - 1]?.getAttribute("d") ?? "";
}

describe("StatusReactor", () => {
  it("is hidden from assistive technology, because the state is written out beside it", () => {
    const { container } = render(<StatusReactor tone="ok" />);

    expect(container.querySelector("svg")).toHaveAttribute("aria-hidden", "true");
  });

  it("draws a different mark for every state, so colour is not the only signal", () => {
    const tones = ["ok", "warn", "bad", "neutral"] as const;
    const marks = tones.map((tone) => corePath(render(<StatusReactor tone={tone} />).container));

    expect(marks.every((mark) => mark !== "")).toBe(true);
    expect(new Set(marks).size).toBe(tones.length);
  });

  it("turns the rings only when asked to", () => {
    const still = render(<StatusReactor tone="ok" />).container;
    const turning = render(<StatusReactor tone="ok" spinning />).container;

    expect(still.querySelector(".animate-orbit")).toBeNull();
    expect(turning.querySelector(".animate-orbit")).not.toBeNull();
    expect(turning.querySelector(".animate-orbit-reverse")).not.toBeNull();
  });
});
