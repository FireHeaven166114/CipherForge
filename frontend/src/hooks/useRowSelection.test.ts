import { act, renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { useRowSelection } from "./useRowSelection";

const ROWS = ["a", "b", "c", "d"];

function setup(initial: { scope: string; rows: readonly string[] } = { scope: "page=1", rows: ROWS }) {
  return renderHook((props) => useRowSelection(props.scope, props.rows), { initialProps: initial });
}

describe("useRowSelection", () => {
  it("ticks and unticks single rows", () => {
    const { result } = setup();

    act(() => result.current.set("b", true));
    act(() => result.current.set("d", true));
    expect(result.current.selected).toEqual(["b", "d"]);
    expect(result.current.overall).toBe("some");

    act(() => result.current.set("b", false));
    expect(result.current.selected).toEqual(["d"]);
  });

  it("applies a Shift-click to the run from the last row clicked, whichever way it runs", () => {
    const { result } = setup();

    act(() => result.current.set("b", true));
    act(() => result.current.set("d", true, true));
    expect(result.current.selected).toEqual(["b", "c", "d"]);

    act(() => result.current.set("c", false));
    act(() => result.current.set("a", false, true));
    // The run from "c" back to "a" is unticked, and "d" is left alone.
    expect(result.current.selected).toEqual(["d"]);
  });

  it("treats a Shift-click with nothing clicked before it as a plain click", () => {
    const { result } = setup();

    act(() => result.current.set("c", true, true));

    expect(result.current.selected).toEqual(["c"]);
  });

  it("ticks and unticks every row on screen, and clears everything", () => {
    const { result } = setup();

    act(() => result.current.setAll(true));
    expect(result.current.overall).toBe("all");
    expect(result.current.selected).toEqual(ROWS);

    act(() => result.current.setAll(false));
    expect(result.current.overall).toBe("none");

    act(() => result.current.set("a", true));
    act(() => result.current.clear());
    expect(result.current.selected).toEqual([]);
  });

  it("starts again when the scope changes, so a tick never reaches another page", () => {
    const { result, rerender } = setup();
    act(() => result.current.set("a", true));

    rerender({ scope: "page=2", rows: ["e", "f"] });
    expect(result.current.selected).toEqual([]);

    rerender({ scope: "page=1", rows: ROWS });
    expect(result.current.selected).toEqual([]);
    expect(result.current.isSelected("a")).toBe(false);
  });

  it("only counts ticked rows that are still on screen", () => {
    const { result, rerender } = setup();
    act(() => result.current.setAll(true));

    rerender({ scope: "page=1", rows: ["a", "c"] });

    expect(result.current.selected).toEqual(["a", "c"]);
    expect(result.current.overall).toBe("all");
  });

  it("forgets rows that were deleted, including the one a range would start from", () => {
    const { result } = setup();
    act(() => result.current.set("a", true));
    act(() => result.current.set("c", true));

    act(() => result.current.drop(["a", "gone"]));
    expect(result.current.selected).toEqual(["c"]);

    act(() => result.current.set("b", true));
    act(() => result.current.drop(["b"]));
    // "b" was where a Shift-click would have started, so it now behaves like a plain click.
    act(() => result.current.set("d", true, true));
    expect(result.current.selected).toEqual(["c", "d"]);
  });
});
