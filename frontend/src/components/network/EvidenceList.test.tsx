import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import EvidenceList from "./EvidenceList";

describe("EvidenceList", () => {
  it("lists what the rule recorded as names and values", () => {
    render(
      <EvidenceList
        evidence={{ distinct_ports: 40, sample_ports: [22, 80, 443], total_bytes: 2048, repeated: true }}
      />,
    );

    const terms = screen.getAllByRole("term").map((term) => term.textContent);
    expect(terms).toEqual(["Distinct ports", "Sample ports", "Total bytes", "Repeated"]);
    expect(screen.getByText("40")).toBeInTheDocument();
    expect(screen.getByText("22, 80, 443")).toBeInTheDocument();
    expect(screen.getByText("2.00 KB")).toBeInTheDocument();
    expect(screen.getByText("Yes")).toBeInTheDocument();
  });

  it("shows text from the server as text, never as markup", () => {
    const hostile = '<img src="x" onerror="alert(1)"><script>alert(2)</script>';
    const { container } = render(<EvidenceList evidence={{ note: hostile }} />);

    expect(screen.getByText(hostile)).toBeInTheDocument();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
  });

  it("says so when the alert recorded no evidence", () => {
    render(<EvidenceList evidence={{}} />);
    expect(screen.getByText("This alert recorded no further evidence.")).toBeInTheDocument();
  });

  it("says when more evidence existed than could be listed", () => {
    const wide = Object.fromEntries(Array.from({ length: 70 }, (_, index) => [`field_${index}`, index]));
    render(<EvidenceList evidence={wide} />);

    expect(screen.getAllByRole("term")).toHaveLength(60);
    expect(screen.getByText("More evidence was recorded than is listed here.")).toBeInTheDocument();
  });
});
