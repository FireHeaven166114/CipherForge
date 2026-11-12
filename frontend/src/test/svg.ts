// Testing Library types its queries for HTMLElement; an <svg> works the same at runtime.
export function svgOf(container: HTMLElement): HTMLElement {
  const svg = container.querySelector("svg");
  if (!svg) throw new Error("Expected the component to render an <svg>.");
  return svg as unknown as HTMLElement;
}
