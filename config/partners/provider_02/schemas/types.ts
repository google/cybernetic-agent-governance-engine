// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/**
 * CAGE Governance Schema Definitions (v1)
 * 
 * TypeScript type definitions corresponding to JSON Schema URNs:
 * - urn:cage:governance:v1:step-entry
 * - urn:cage:governance:v1:attestation-bundle
 * - urn:cage:governance:v1:graph-topology
 * 
 * Generated from CAGE reference architecture Python dataclasses.
 */

/**
 * A single step in the CAGE governance DAG.
 * 
 * Maps 1:1 to a LangGraph node execution snapshot. The `parentStepIds`
 * field captures DAG edges from preceding nodes.
 */
export interface ProjectBundleStepEntry {
  /**
   * Unique identifier for this step (UUID v4)
   */
  stepId: string;

  /**
   * LangGraph node name (e.g., 'safety_check', 'governed_trader')
   */
  nodeName: string;

  /**
   * Step IDs of all parent nodes in the DAG. Empty for entry nodes.
   */
  parentStepIds: string[];

  /**
   * ISO 8601 UTC timestamp when this step was executed
   */
  timestampUtc: string;

  /**
   * Execution duration in milliseconds
   */
  durationMs: number;

  /**
   * Governance signals emitted by this node (CBF verdicts, OPA decisions, etc.).
   * Open extension point for domain-specific data.
   */
  signals: Record<string, unknown>;

  /**
   * Arbitrary node metadata (model names, token counts, etc.).
   * Open extension point.
   */
  metadata: Record<string, unknown>;

  /**
   * SHA-256 hex digest of the serialized AgentState snapshot at this node
   */
  stateHash: string;
}

/**
 * Terminal path classification for governance bundles.
 */
export type TerminalPath =
  | "happy_path"    // Successful execution, all governance gates passed
  | "nemo_block"    // Blocked by NeMo Guardrails policy violation
  | "cbf_block"     // Blocked by Control Barrier Function safety constraint
  | "loop_breaker"  // Terminated due to iteration limit
  | "unknown";      // Unclassifiable/fallback (fail-closed)

/**
 * A complete governance bundle for a single graph execution.
 * 
 * Assembled from all `ProjectBundleStepEntry` objects collected during
 * a graph run. Submitted to Provider 02's `registerProjectBundle` endpoint
 * for CER issuance.
 */
export interface AttestationBundle {
  /**
   * Unique identifier for this governance bundle (UUID v4)
   */
  bundleId: string;

  /**
   * Thread/session identifier linking multiple graph executions
   */
  threadId: string;

  /**
   * Ordered sequence of node execution steps forming the governance DAG
   */
  steps: ProjectBundleStepEntry[];

  /**
   * ISO 8601 UTC timestamp when graph execution started
   */
  startedAt: string;

  /**
   * ISO 8601 UTC timestamp when graph execution completed or terminated
   */
  completedAt: string;

  /**
   * Terminal path classification:
   * - happy_path: success
   * - nemo_block: policy violation
   * - cbf_block: safety barrier
   * - loop_breaker: iteration limit
   */
  terminalPath: TerminalPath;
}

/**
 * Domain-agnostic control graph topology.
 * 
 * Describes the structure of a LangGraph control flow without naming
 * specific actions. Used by attestation adapters for DAG construction,
 * terminal path classification, and parent-edge resolution.
 */
export interface GraphTopology {
  /**
   * All node names in the graph (unordered set)
   */
  nodes: string[];

  /**
   * Maps each node to its possible parent nodes.
   * Keys are node names, values are arrays of parent node names.
   */
  parentEdges: Record<string, string[]>;

  /**
   * The canonical success terminal node (e.g., final action executor)
   */
  terminalNode: string;

  /**
   * The node where HITL (human-in-the-loop) interrupts occur, if any
   */
  interruptNode?: string | null;

  /**
   * Nodes that trigger attestation CER emission (unordered set)
   */
  attestationNodes?: string[];
}
