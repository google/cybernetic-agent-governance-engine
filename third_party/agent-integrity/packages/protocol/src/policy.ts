export interface IntegrityPolicy {
  readonly version: 1;
  readonly sources: {
    readonly allowedRoots: readonly string[];
  };
  readonly decisions: {
    readonly path: string;
  };
  readonly rules: {
    readonly requireEvidenceFor: readonly ("factual" | "recommendation")[];
    readonly contradictions: "review" | "block";
    readonly rejectedDecisions: "block";
    readonly responseMutation: "block";
    readonly replay: "block";
  };
}
