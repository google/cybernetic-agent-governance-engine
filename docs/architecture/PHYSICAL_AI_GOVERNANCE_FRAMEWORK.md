# Physical AI Governance Framework

**CAGE Layer 2 Domain Plugin: Autonomous Robotics & Embodied Systems**  
*Reference Architecture Specification*

**Last Updated:** 2026-09-29

> **Activation status:** The plugin is packaged under [`src/cage_physical_ai/`](../../src/cage_physical_ai/) and registered as the `physical_ai` entry point in the `cage.plugins` group ([`pyproject.toml`](../../pyproject.toml)). It declares no `DomainConfig` (no FTRA terminal registry or OPA package), so `CAGE_DOMAIN=physical_ai` refuses to start (fail closed) until POAM-2026-077 in [`docs/POAM.md`](../POAM.md) is closed. The sections below describe what the plugin contributes when `assemble_governor()` builds a governor from it (as the test suite does).

---

## 1. Overview & Core Philosophy

As autonomous systems transition from deterministic, hardcoded robotics to embodied foundation models—Vision-Language-Action (VLA) architectures and generative agent planners—the engineering community requires a unified control model.

The **Physical AI Governance Framework** (`cage_physical_ai`) integrates runtime governance with physical robot safety. It models physical AI as an authorized domain within the Cybernetic Agent Governance Engine (CAGE), providing:
- **Declarative Barrier Functions (CBFs)** for spatial separation, kinematic velocity, and joint torque limits.
- **Multi-Critic Consensus Tiers** for authorizing safety curtain overrides and high-consequence motion plans.
- **Compliance Control Overlays** mapping physical constraints to ISO 10218, ISO/TS 15066, ISO 3691-4, OSHA 1910.212, and NIST AI RMF.
- **Non-repudiable Audit Trails** linking human operator mandates, sensor-fused state telemetry, and actuator dispatch receipts into CAGE's tamper-evident ledger.

The plugin only *names* things. It ships no Lua scripts, fence-epoch logic, KMS verification, consensus algorithm, or causal engine; each of those is a single kernel copy shared by every domain ([`plugin.py`](../../src/cage_physical_ai/plugin.py)).

---

## 2. Five-Plane Architecture Alignment

In accordance with the CAGE Five-Plane Reference Architecture:

1. **Cognitive Plane**: High-level task planners and VLA models formulate physical task plans (e.g., `dispatch_trajectory`, `actuate_joint`).
2. **Governance Plane**: The CAGE Symbolic Governor evaluates actions against domain invariants and executes multi-tier clearance checks before any actuation reaches the physical world.
3. **Execution Plane**: The FastMCP tool provider ([`PhysicalAIToolProvider`](../../src/cage_physical_ai/tools/tool_provider.py)) receives validated action dispatches. Robot actuator integrations (e.g. ROS 2, NVIDIA Isaac / Halos) are adopter-supplied; none ships in the repository.
4. **Attestation Plane**: Cryptographic receipts and consensus votes are chained into the evidence stream.
5. **Observability Plane**: Real-time telemetry (joint torques, velocities, obstacle separation distances) streams to sovereign Langfuse and ClickHouse sinks.

```
┌────────────────────────────────────────────────────────┐
│                    Cognitive Plane                     │
│           (VLA Models / Agent Task Planners)           │
└───────────────────────────┬────────────────────────────┘
                            │ Proposed Action
                            ▼
┌────────────────────────────────────────────────────────┐
│                   Governance Plane                     │
│                 (CAGE Kernel & Plugin)                 │
│                                                        │
│   Phase 1 (Consensus): PhysicalSafetyConsensusTier     │
│   Phase 2 (Bounding):  KinematicBarrierTier            │
│   Invariants:          Spatial, Velocity, Torque       │
└───────────────────────────┬────────────────────────────┘
                            │ Validated Dispatch
                            ▼
┌────────────────────────────────────────────────────────┐
│                    Execution Plane                     │
│   (FastMCP Server; adopter ROS 2 / Isaac actuators)    │
└────────────────────────────────────────────────────────┘
```

---

## 3. Declarative Barriers and Invariants

Barriers are declarative rather than procedural ([`invariants.py`](../../src/cage_physical_ai/invariants.py)). Each is a frozen dataclass naming `(invariant_id, state_key, threshold_key, gamma)`; the kernel's invariant-parametric `ControlBarrierFunction` ([`cbf_engine.py`](../../src/gateway/governance/safety/cbf_engine.py)) evaluates it atomically in Redis. The plugin builds one CBF per barrier, each with its own cost resolver from [`ground_truth.py`](../../src/cage_physical_ai/ground_truth.py):

- **`SpatialSeparationBarrier` (`CTRL_PHYS_001`)**:
  - Invariant ID: `physical_ai.spatial_separation`
  - State Key: `safety:separation_distance_mm`
  - Threshold: `domains.physical_ai.min_separation_distance_mm`
  - Algebra: \( h(S(t+1)) \ge (1 - \gamma) h(S(t)) \ge 0 \) (\( \gamma = 0.5 \))
  - Enforces minimum physical standoff distances between humans and machinery.

- **`KinematicVelocityBarrier` (`CTRL_PHYS_002`)**:
  - Invariant ID: `physical_ai.kinematic_velocity`
  - State Key: `safety:end_effector_velocity_mm_s`
  - Threshold: `domains.physical_ai.max_velocity_mm_s` (\( \gamma = 0.4 \))
  - Clamps velocity trajectories to prevent hazardous kinetic energy transfer.

- **`TorqueSaturationBarrier` (`CTRL_PHYS_003`)**:
  - Invariant ID: `physical_ai.torque_saturation`
  - State Key: `safety:joint_torque_nm`
  - Threshold: `domains.physical_ai.max_joint_torque_nm` (\( \gamma = 0.3 \))
  - Prevents motor over-torque, actuator strain, and mechanical crush hazards.

**Thresholds.** The plugin contributes the `physical_ai` threshold section. `assemble_governor()` validates `domains.physical_ai` in [`config/governance_thresholds.json`](../../config/governance_thresholds.json) against [`PhysicalAIThresholds`](../../src/cage_physical_ai/thresholds.py) and refuses startup if the section is missing or invalid. The shipped values (500 mm separation, 250 mm/s velocity, 50 N·m torque) are **reference-only**; adopters must derive real limits from a cell-specific ISO/TS 15066 risk assessment.

**Ground truth.** Each barrier sets `requires_external_ground_truth=True` and is paired by `invariant_id` with a simulated sensor provider (`SimulatedSpatialSensorProvider`, `SimulatedVelocitySensorProvider`, `SimulatedTorqueSensorProvider`) through `PluginContribution.ground_truth_providers`.

---

## 4. Governance Tiers

[`PhysicalAICagePlugin.contribute()`](../../src/cage_physical_ai/plugin.py) returns a frozen `PluginContribution` whose tiers come from `create_physical_ai_tiers()` ([`__init__.py`](../../src/cage_physical_ai/__init__.py)):

1. **`KinematicBarrierTier`** (`phase=2, order=3`, [`kinematic_barrier_tier.py`](../../src/cage_physical_ai/tiers/kinematic_barrier_tier.py)):
   - Claims every action in `PHYSICAL_AI_GOVERNED_ACTIONS` plus `move_arm` and `move_effector`.
   - Commits against the spatial, velocity, and torque CBFs in turn and rolls back earlier commits if a later barrier is violated.
   - If built without a CBF, it returns a HARD `KINEMATIC_BARRIER_UNCONFIGURED` violation (fail closed).

2. **`PhysicalSafetyConsensusTier`** (`phase=1, order=5`, [`physical_consensus_tier.py`](../../src/cage_physical_ai/tiers/physical_consensus_tier.py)):
   - Claims `PHYSICAL_AI_GOVERNED_ACTIONS` (`dispatch_trajectory`, `override_safety_curtain`, `actuate_joint`, `set_operational_mode`) and the high-stakes actions `execute_high_speed_trajectory`, `override_safety_envelope`, `disengage_e_stop`.
   - Runs the kernel `ConsensusGate`, built from a domain-injected `ConsensusContribution` whose critics come from [`critics.yaml`](../../src/cage_physical_ai/config/critics.yaml). `ESCALATE` maps to a HITL violation; any other non-approval is HARD.

The spatial CBF also fills the assembly's `safety_filter` slot, and the same consensus contribution fills the `consensus` slot.

---

## 5. Standard Compliance Overlays

Compliance controls are codified in [`US_FED_OVERLAY.json`](../../src/cage_physical_ai/config/compliance/US_FED_OVERLAY.json) and contributed through `PluginContribution.compliance_overlay_dirs`; `bootstrap_governor()` registers them at startup:
- **OSHA 1910.212**: General machine guarding.
- **ISO 10218-1/2 & ISO/TS 15066**: Collaborative industrial robot systems.
- **ISO 3691-4**: Driverless industrial trucks and AGVs.
- **ISO 21448 (SOTIF)**: Safety of the intended functionality.
- **NIST AI RMF MANAGE-2.4**: Human-AI teaming governance.
