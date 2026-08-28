import { describe, expect, it } from "vitest";
import type { DecisionEvent } from "@agent-integrity/protocol";
import { reduceDecisions } from "../../src/decisions/reduce-decisions.js";

describe("decision revival protection", () => {
  it.each(["reject", "supersede"] as const)(
    "does not allow activation after %s",
    (terminalAction) => {
      const events: DecisionEvent[] = [
        { eventId: "e1", decisionId: "old", revision: 1, action: "activate" },
        { eventId: "e2", decisionId: "new", revision: 1, action: "activate" },
        {
          eventId: "e3",
          decisionId: "old",
          revision: 2,
          action: terminalAction,
          ...(terminalAction === "supersede" ? { supersededBy: "new" } : {}),
        },
        { eventId: "e4", decisionId: "old", revision: 3, action: "activate" },
      ];

      expect(() => reduceDecisions(events)).toThrow(/terminal|revive/u);
    },
  );

  it("rejects supersession by a missing or non-active decision", () => {
    const base: DecisionEvent[] = [
      { eventId: "e1", decisionId: "old", revision: 1, action: "activate" },
      {
        eventId: "e2",
        decisionId: "old",
        revision: 2,
        action: "supersede",
        supersededBy: "missing",
      },
    ];
    expect(() => reduceDecisions(base)).toThrow(/active replacement/u);
  });
});
