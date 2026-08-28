import type { DecisionEvent, DecisionState } from "@agent-integrity/protocol";

function assertIdentifier(value: string, path: string): void {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`${path} must be a non-empty string`);
  }
}

function sortStates(states: Iterable<DecisionState>): DecisionState[] {
  return [...states].sort((left, right) =>
    left.decisionId.localeCompare(right.decisionId, "en"),
  );
}

export function reduceDecisions(events: readonly DecisionEvent[]): readonly DecisionState[] {
  const eventIds = new Set<string>();
  const byDecision = new Map<string, DecisionEvent[]>();

  for (const [index, event] of events.entries()) {
    assertIdentifier(event.eventId, `events[${index}].eventId`);
    assertIdentifier(event.decisionId, `events[${index}].decisionId`);
    if (eventIds.has(event.eventId)) {
      throw new Error(`duplicate decision event ID: ${event.eventId}`);
    }
    eventIds.add(event.eventId);
    if (!Number.isSafeInteger(event.revision) || event.revision < 1) {
      throw new Error(`events[${index}].revision must be a positive safe integer`);
    }
    if (!(["activate", "reject", "supersede"] as const).includes(event.action)) {
      throw new Error(`events[${index}].action is invalid`);
    }
    if (event.action === "supersede") {
      assertIdentifier(event.supersededBy ?? "", `events[${index}].supersededBy`);
      if (event.supersededBy === event.decisionId) {
        throw new Error(`decision ${event.decisionId} cannot supersede itself`);
      }
    } else if (event.supersededBy !== undefined) {
      throw new Error(`events[${index}].supersededBy is only valid for supersede events`);
    }
    const decisionEvents = byDecision.get(event.decisionId) ?? [];
    decisionEvents.push(event);
    byDecision.set(event.decisionId, decisionEvents);
  }

  const states = new Map<string, DecisionState>();
  for (const [decisionId, unsortedEvents] of byDecision) {
    const decisionEvents = [...unsortedEvents].sort((left, right) =>
      left.revision - right.revision || left.eventId.localeCompare(right.eventId, "en"),
    );
    let state: DecisionState | undefined;
    for (const [index, event] of decisionEvents.entries()) {
      const expectedRevision = index + 1;
      if (event.revision !== expectedRevision) {
        throw new Error(
          `decision ${decisionId} has a conflicting, duplicate, or missing revision: expected ${expectedRevision}, received ${event.revision}`,
        );
      }
      if (state === undefined) {
        if (event.action !== "activate") {
          throw new Error(`decision ${decisionId} must begin with activate`);
        }
        state = { decisionId, revision: event.revision, status: "active" };
        continue;
      }
      if (state.status !== "active") {
        throw new Error(`decision ${decisionId} has a terminal state and cannot be revived`);
      }
      if (event.action === "activate") {
        throw new Error(`decision ${decisionId} is already active and cannot be activated again`);
      }
      state = event.action === "reject"
        ? { decisionId, revision: event.revision, status: "rejected" }
        : {
            decisionId,
            revision: event.revision,
            status: "superseded",
            supersededBy: event.supersededBy!,
          };
    }
    if (state !== undefined) states.set(decisionId, state);
  }

  for (const state of states.values()) {
    if (state.status !== "superseded") continue;
    const replacement = states.get(state.supersededBy!);
    if (replacement?.status !== "active") {
      throw new Error(
        `decision ${state.decisionId} must be superseded by an active replacement decision`,
      );
    }
  }

  return sortStates(states.values());
}
