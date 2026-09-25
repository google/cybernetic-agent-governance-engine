# Physical AI Governance Framework

**CAGE Layer 2 Domain Plugin: Autonomous Robotics & Embodied Systems**  
*Reference Architecture Specification*

---

## 1. Overview & Core Philosophy

As autonomous systems transition from deterministic, hardcoded robotics to embodied foundation models—Vision-Language-Action (VLA) architectures and generative agent planners—the engineering community requires a unified control model.

The **Physical AI Governance Framework** (`cage_physical_ai`) integrates runtime governance with physical robot safety. It models physical AI as an authorized domain within the Cybernetic Agent Governance Engine (CAGE), providing:
- **Declarative Barrier Functions (CBFs)** for spatial separation, kinematic velocity, and joint torque limits.
- **Multi-Critic Consensus Tiers** for authorizing safety curtain overrides and high-consequence motion plans.
- **Compliance Control Overlays** mapping physical constraints to ISO 10218, ISO/TS 15066, ISO 3691-4, OSHA 1910.212, and NIST AI RMF.
- **Non-repudiable Audit Trails** linking human operator mandates, sensor-fused state telemetry, and actuator dispatch receipts into CAGE's tamper-evident ledger.

---

## 2. Five-Plane Architecture Alignment

In accordance with the CAGE Five-Plane Reference Architecture:

1. **Cognitive Plane**: High-level task planners and VLA models formulate physical task plans (e.g., `dispatch_trajectory`, `actuate_joint`).
2. **Governance Plane**: The CAGE Symbolic Governor evaluates actions against domain invariants and executes multi-tier clearance checks before any actuation reaches the physical world.
3. **Execution Plane**: The FastMCP tool provider and robot actuators (e.g. ROS 2, NVIDIA Isaac / Halos) receive validated action dispatches.
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
│         (NVIDIA Halos / ROS 2 / FastMCP Server)        │
└────────────────────────────────────────────────────────┘
```

---

## 3. Declarative Barriers and Invariants

Barriers are declarative rather than procedural. The kernel compiles barrier parameters into atomic evaluation logic at runtime:

- **`SpatialSeparationBarrier` (`CTRL_PHYS_001`)**:
  - State Key: `safety:separation_distance_mm`
  - Threshold: `physical_ai.min_separation_distance_mm`
  - Algebra: \( h(S(t+1)) \ge (1 - \gamma) h(S(t)) \ge 0 \) (\( \gamma = 0.5 \))
  - Enforces minimum physical standoff distances between humans and machinery.

- **`KinematicVelocityBarrier` (`CTRL_PHYS_002`)**:
  - State Key: `safety:end_effector_velocity_mm_s`
  - Threshold: `physical_ai.max_velocity_mm_s`
  - Clamps velocity trajectories to prevent hazardous kinetic energy transfer.

- **`TorqueSaturationBarrier` (`CTRL_PHYS_003`)**:
  - State Key: `safety:joint_torque_nm`
  - Threshold: `physical_ai.max_joint_torque_nm`
  - Prevents motor over-torque, actuator strain, and mechanical crush hazards.

---

## 4. Governance Tiers

The domain plugin exports two primary governance tiers via `create_physical_ai_tiers()`:

1. **`KinematicBarrierTier`** (`phase=2, order=3`):
   - Evaluates trajectory commands (`dispatch_trajectory`, `actuate_joint`).
   - Delegates state-space evaluation to CAGE's Control Barrier Function engine.

2. **`PhysicalSafetyConsensusTier`** (`phase=1, order=5`):
   - Evaluates high-consequence operational changes (e.g., `override_safety_curtain`, `set_operational_mode`).
   - Enforces multi-model consensus prior to clearance issuance.

---

## 5. Standard Compliance Overlays

Compliance controls are codified in `src/cage_physical_ai/config/compliance/US_FED_OVERLAY.json`:
- **OSHA 1910.212**: General machine guarding.
- **ISO 10218-1/2 & ISO/TS 15066**: Collaborative industrial robot systems.
- **ISO 3691-4**: Driverless industrial trucks and AGVs.
- **ISO 21448 (SOTIF)**: Safety of the intended functionality.
- **NIST AI RMF MANAGE-2.4**: Human-AI teaming governance.
