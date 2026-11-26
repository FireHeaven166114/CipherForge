import { describe, expect, it } from "vitest";

import { makeSessionDetail } from "../../test/networkFixtures";
import { sessionCounters } from "./counters";

function byKey(detail = makeSessionDetail()) {
  return Object.fromEntries(sessionCounters(detail).map((note) => [note.key, note]));
}

describe("sessionCounters", () => {
  it("lists every counter the session carries, each with its meaning", () => {
    const notes = sessionCounters(makeSessionDetail());
    expect(notes.map((note) => note.key)).toEqual([
      "packets_dropped",
      "non_ip_packets",
      "malformed_packets",
      "flows_evicted",
      "flows_stored",
      "flows_not_stored",
      "alerts_suppressed",
      "alerts_lost",
      "talkers_truncated",
    ]);
    for (const note of notes) expect(note.explanation).not.toBe("");
  });

  it("flags nothing for a clean session, and does not claim a zero proves nothing was lost", () => {
    const notes = byKey();
    expect(sessionCounters(makeSessionDetail()).some((note) => note.attention)).toBe(false);
    expect(notes.packets_dropped?.explanation).toContain("zero does not prove none were lost");
  });

  it("explains a drop as the monitor's own queue, not the operating system's", () => {
    const note = byKey(makeSessionDetail({ packets_dropped: 1200 })).packets_dropped;
    expect(note?.display).toBe("1,200");
    expect(note?.attention).toBe(true);
    expect(note?.explanation).toContain("bounded queue overflowed");
    expect(note?.explanation).toContain("not the operating system's drop count");
  });

  it("flags what is missing from the totals or the lists", () => {
    const notes = byKey(
      makeSessionDetail({
        malformed_packets: 3,
        flows_evicted: 7,
        flows_not_stored: 11_000,
        alerts_lost: 2,
        talkers_truncated: true,
      }),
    );
    for (const key of ["malformed_packets", "flows_evicted", "flows_not_stored", "alerts_lost", "talkers_truncated"]) {
      expect(notes[key]?.attention, key).toBe(true);
    }
    expect(notes.flows_not_stored?.display).toBe("11,000");
    expect(notes.flows_not_stored?.explanation).toContain("counted in the totals but are not in the flows table");
    expect(notes.talkers_truncated?.display).toBe("Yes");
  });

  it("only reports what is routine", () => {
    const notes = byKey(makeSessionDetail({ non_ip_packets: 9, alerts_suppressed: 4, flows_stored: 40 }));
    for (const key of ["non_ip_packets", "alerts_suppressed", "flows_stored"]) {
      expect(notes[key]?.attention, key).toBe(false);
    }
    expect(notes.non_ip_packets?.display).toBe("9");
  });
});
