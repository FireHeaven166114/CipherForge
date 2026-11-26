import { describe, expect, it } from "vitest";

import { flattenEvidence } from "./evidence";

function valueOf(evidence: Record<string, unknown>, key: string): string | undefined {
  return flattenEvidence(evidence).rows.find((row) => row.key === key)?.value;
}

describe("flattenEvidence", () => {
  it("lists plain values with readable labels", () => {
    const { rows, truncated } = flattenEvidence({ distinct_ports: 40, sample_ports: [1, 2, 3] });
    expect(truncated).toBe(false);
    expect(rows).toEqual([
      { key: "distinct_ports", label: "Distinct ports", value: "40" },
      { key: "sample_ports", label: "Sample ports", value: "1, 2, 3" },
    ]);
  });

  it("reads a number by its name: bytes, seconds, ports and counts", () => {
    expect(valueOf({ bytes: 5 * 1024 * 1024 }, "bytes")).toBe("5.00 MB");
    expect(valueOf({ total_bytes: 2048 }, "total_bytes")).toBe("2.00 KB");
    expect(valueOf({ window_seconds: 60 }, "window_seconds")).toBe("1 min 00 s");
    expect(valueOf({ port: 8080 }, "port")).toBe("8080");
    expect(valueOf({ new_flows: 12480 }, "new_flows")).toBe("12,480");
    expect(valueOf({ ratio: 0.456 }, "ratio")).toBe("0.46");
  });

  it("writes booleans and nothing as words", () => {
    expect(valueOf({ truncated: false }, "truncated")).toBe("No");
    expect(valueOf({ truncated: true }, "truncated")).toBe("Yes");
    expect(valueOf({ note: null }, "note")).toBe("None");
    expect(valueOf({ ports: [] }, "ports")).toBe("None");
    expect(valueOf({ detail: {} }, "detail")).toBe("None");
  });

  it("shows a timestamp in IST", () => {
    expect(valueOf({ first_seen: "2026-05-20T08:30:00Z" }, "first_seen")).toBe("20-05-2026 02:00:00 PM IST");
  });

  it("puts each small record of a list on one row", () => {
    const { rows } = flattenEvidence({
      top_targets: [
        { address: "192.0.2.10", port: 22, count: 5 },
        { address: "192.0.2.11", port: 80, count: 3 },
      ],
    });
    expect(rows).toEqual([
      { key: "top_targets.1", label: "Top targets › 1", value: "Address: 192.0.2.10, Port: 22, Count: 5" },
      { key: "top_targets.2", label: "Top targets › 2", value: "Address: 192.0.2.11, Port: 80, Count: 3" },
    ]);
  });

  it("formats the numbers inside a list's records by name", () => {
    expect(valueOf({ top_destinations: [{ address: "192.0.2.10", bytes: 1536 }] }, "top_destinations.1")).toBe(
      "Address: 192.0.2.10, Bytes: 1.50 KB",
    );
  });

  it("walks nested records into labelled rows", () => {
    const { rows } = flattenEvidence({ summary: { peers: 2, note: "seen twice" } });
    expect(rows.map((row) => [row.label, row.value])).toEqual([
      ["Summary › Peers", "2"],
      ["Summary › Note", "seen twice"],
    ]);
  });

  it("shortens a long list of plain values and says how many were left out", () => {
    const ports = Array.from({ length: 25 }, (_, index) => index + 1);
    expect(valueOf({ sample_ports: ports }, "sample_ports")).toBe(`${ports.slice(0, 20).join(", ")} and 5 more`);
  });

  it("shortens a long list of records", () => {
    const entries = Array.from({ length: 23 }, (_, index) => ({ address: `192.0.2.${index}` }));
    const { rows } = flattenEvidence({ peers: entries });
    expect(rows).toHaveLength(21);
    expect(rows.at(-1)).toMatchObject({ value: "3 more entries are not shown." });
  });

  it("says 'entry' when exactly one record was left out", () => {
    const entries = Array.from({ length: 21 }, (_, index) => ({ address: `192.0.2.${index}` }));
    const { rows } = flattenEvidence({ peers: entries });
    expect(rows.at(-1)).toMatchObject({ value: "1 more entry is not shown." });
  });

  it("stops at a depth it can show, and says so", () => {
    expect(valueOf({ a: { b: { c: { d: 1 } } } }, "a.b.c")).toBe("D: 1");
    expect(valueOf({ a: { b: { c: { d: { e: 1 } } } } }, "a.b.c")).toBe("More detail than is shown here.");
  });

  it("caps the rows and reports that it did", () => {
    const evidence = Object.fromEntries(Array.from({ length: 75 }, (_, index) => [`key_${index}`, index]));
    const { rows, truncated } = flattenEvidence(evidence);
    expect(rows).toHaveLength(60);
    expect(truncated).toBe(true);
  });

  it("cuts a very long text", () => {
    const value = valueOf({ note: "x".repeat(500) }, "note") ?? "";
    expect(value).toHaveLength(201);
    expect(value.endsWith("…")).toBe(true);
  });

  it("keeps markup as plain text", () => {
    const text = '<img src=x onerror="alert(1)">';
    expect(valueOf({ note: text }, "note")).toBe(text);
  });

  it("has no rows for no evidence", () => {
    expect(flattenEvidence({})).toEqual({ rows: [], truncated: false });
  });
});
