import { describe, expect, it } from "vitest";
import type { DecisionEvent } from "@agent-integrity/protocol";
import { reduceDecisions } from "../../src/decisions/reduce-decisions.js";

const event = (overrides: Partial<DecisionEvent> = {}): DecisionEvent => ({
  eventId: "event-1",
  decisionId: "decision-1",
  revision: 1,
  action: "activate",
  ...overrides,
});

describe("reduceDecisions", () => {
  it("reduces active and rejected decisions independently of input order", () => {
    const events: DecisionEvent[] = [
      event({ eventId: "event-2", revision: 2, action: "reject" }),
      event(),
      event({ eventId: "event-3", decisionId: "decision-2" }),
    ];

    expect(reduceDecisions(events)).toEqual([
      { decisionId: "decision-1", revision: 2, status: "rejected" },
      { decisionId: "decision-2", revision: 1, status: "active" },
    ]);
  });

  it("records which active decision superseded the old decision", () => {
    expect(reduceDecisions([
      event(),
      event({ eventId: "event-2", decisionId: "decision-2" }),
      event({
        eventId: "event-3",
        revision: 2,
        action: "supersede",
        supersededBy: "decision-2",
      }),
    ])).toEqual([
      {
        decisionId: "decision-1",
        revision: 2,
        status: "superseded",
        supersededBy: "decision-2",
      },
      { decisionId: "decision-2", revision: 1, status: "active" },
    ]);
  });

  it.each([
    ["duplicate event IDs", [event(), event({ decisionId: "decision-2" })]],
    ["conflicting revisions", [event(), event({ eventId: "event-2", action: "reject" })]],
    ["missing first revision", [event({ revision: 2 })]],
    ["revision gaps", [event(), event({ eventId: "event-2", revision: 3, action: "reject" })]],
  ])("rejects %s", (_label, events) => {
    expect(() => reduceDecisions(events as DecisionEvent[])).toThrow();
  });

  it("rejects lifecycle events that do not follow activation", () => {
    expect(() => reduceDecisions([event({ action: "reject" })])).toThrow(/activate/u);
  });

  it("rejects malformed supersession relationships", () => {
    expect(() => reduceDecisions([
      event(),
      event({ eventId: "event-2", revision: 2, action: "supersede" }),
    ])).toThrow(/supersededBy/u);
    expect(() => reduceDecisions([
      event(),
      event({
        eventId: "event-2",
        revision: 2,
        action: "supersede",
        supersededBy: "decision-1",
      }),
    ])).toThrow(/itself/u);
  });
});
