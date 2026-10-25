# CAGE — Cybernetic Agent Governance Engine

A runtime control plane that sits between an AI agent and the things it can actually do. Every tool call, spend and actuation passes through a deterministic policy pipeline that either clears it or refuses it, and writes a signed, tamper-evident receipt either way.

CAGE is domain-agnostic infrastructure. It assumes nothing about what your agent does and does not require you to adopt a particular agent framework, model provider or cloud.

> This is not an officially supported Google product.

## The problem

Most work on making AI agents safe operates on the model: alignment, system prompts, guardrails, refusal training. All of it improves the odds that an agent decides not to do something harmful.

None of it constrains what the agent can do.

That distinction is tolerable while agents draft text. It stops being tolerable the moment an agent holds a payment credential, a database write path, or a robot arm. At that point the governing question is no longer whether the model behaves well under the inputs you anticipated. It is whether a specific action, at a specific moment, is permitted — and whether anyone can prove afterwards what was permitted and why.

Three properties follow from taking that question seriously, and none of them can be obtained from a model:

- **Determinism.** A refusal that depends on a model's judgement is not a control. The same inputs must produce the same verdict, reproducibly, and the verdict must be explicable without reference to a sampling temperature.
- **Mediation.** A control that can be bypassed is decoration. Every path to actuation must pass the same gate, and that property should be verifiable rather than asserted.
- **Evidence before the fact.** An audit log written after an action tells you what happened. A governance system must make the record a precondition of the action, so that an unrecorded action is an impossible one rather than an undetected one.

CAGE is an attempt to build those three properties as infrastructure, beneath whatever agent framework and model you happen to use.

## The thesis

An agent should execute an action only where governance and current authority both permit it, and the enforcement of that conjunction should live outside the agent.

This separates cleanly into two questions that different systems can answer. *Is this class of action permitted under policy, within budget, and reversible enough to risk?* is a governance question. *Does this particular agent hold legitimate, unexpired authority for this action right now?* is an authority question. CAGE answers the first and composes with external systems that answer the second.

The architectural consequence is that CAGE is a substrate rather than a product. It defines a contract that policy engines, authority services, attestation providers and actuators plug into, and enforces the invariants that hold across them. The value is in the contract and the conformance programme that defines compliance with it — not in any particular implementation, including this one.

## See it refuse something

```bash
git clone https://github.com/google/cybernetic-agent-governance-engine.git
cd cybernetic-agent-governance-engine
cp .env.example .env
docker compose up -d --build --wait
```

Then drive a governed action into it:

```bash
curl http://localhost:8080/health
uv run python examples/governance_demo.py --no-pause
```

You should see an `ALLOW`, then a hard `DENY` carrying control id `CTRL_OPA_005`, then a deferred action routed to human review — each emitting a verifiable receipt.

*Around three minutes on a cold Docker cache, well under a minute warm. Most of the cold time is the container build.*

**What just happened:** the denial was not a model declining to answer. The model was never consulted. A policy evaluated the action against a budget barrier and refused it before the actuation path became reachable, and the refusal is cryptographically attested.

Full walkthrough, including switching domains, in [`docs/QUICKSTART.md`](docs/QUICKSTART.md).

## Theoretical foundations

CAGE is a reference implementation of a five-plane architecture for runtime governance of production agents, described in Tallam (2026), *A Five-Plane Reference Architecture for Runtime Governance of Production AI Agents*, arXiv:2606.12320. The planes — governance, network, identity, endpoint and data — each carry enforcement rather than observation, on the principle that a control plane which only watches is a monitoring system.

Four strands of existing safety engineering do the real work:

- **Systems-Theoretic Process Analysis.** Hazards in control systems arise from unsafe interactions between components that are each behaving correctly. STPA, developed by Leveson, derives unsafe control actions from a model of the control structure rather than from a catalogue of known failures. CAGE compiles an STPA control structure into runtime checks, so the question "what could go wrong here" has a structural answer instead of a list of remembered incidents.
- **Control Barrier Functions.** For any quantity that must stay within bounds — cumulative spend, a dose, a torque, a rate — a barrier function provides a provable forward-invariance guarantee: if the system starts inside the safe set, it cannot leave it. CAGE uses discrete-time CBFs with synchronous replication fencing, following Ames et al. (2019), so bounded authority is enforced by construction rather than by a check someone remembered to write.
- **The Simplex architecture.** Sha (2001) established that an unreliable high-performance component can be made safe by a reliable simple one with authority to override it. That is precisely the relationship between a language model and a governance kernel. CAGE is the simple, verifiable component; the agent is the complex, capable, untrusted one.
- **Formal verification of mediation.** Claiming complete interception is easy; demonstrating it is not. The [`proof/`](proof/) directory contains a TLA+ model of the governance state machine and an exhaustive model check of mediation coverage, together with a trace verifier that projects runtime `GOVERNANCE_TRACE` events back onto the model. The claim and the check are both public.

From these, four correctness invariants the system is built to hold:

| Invariant | Claim |
|---|---|
| Composed Authority | Delegated tool permissions cannot expand through composition |
| Mediation Coverage | Every actuation path is intercepted — machine-verified, not asserted |
| Bounded Composite Authority | Global budget and rate bounds hold under concurrency and replication |
| Evidence Sufficiency | Immutable evidence is persisted before actuation clearance |

Full treatment in [`docs/architecture/`](docs/architecture/); the acknowledgements and theoretical lineage are in [`ACKNOWLEDGEMENTS.md`](ACKNOWLEDGEMENTS.md).

## Architecture

```text
agent → gateway → [ FTRA → STPA → pattern → CBF → OPA → consensus → causal ]
                            ↓                                        ↓
                     refuse + receipt                         clear + receipt
```

- **Kernel** — domain- and vendor-neutral enforcement. Import boundaries are enforced in CI, not by convention.
- **Domain plugins** — finance and healthcare ship complete configurations. Exactly one domain is active per process, which is what makes cross-domain isolation checkable.
- **Adapters** — partner systems plug in at four seams: normative providers, attestation providers, execution actuators and estate providers.

## Bring your own policy format

CAGE does not ask you to rewrite your policies in a CAGE-specific language. The substrate ingests several existing specifications and compiles them to the same enforcement artifacts:

| Format | Detected by | Specification |
|---|---|---|
| Microsoft ACS | `behaviorDeclarations` | [agent-control-specification](https://github.com/microsoft/agent-control-specification) |
| Linux Foundation AAIF | `governedRunLoop` | AAIF working group |
| OSCAL 1.1.x | `oscal-version` | [NIST OSCAL](https://pages.nist.gov/OSCAL/) |
| Lula validation manifest | `kind: LulaValidation` | [lula.dev](https://lula.dev/) |
| Native CAGE YAML | fallback | [`docs/SUBSTRATE_CONTRACT.md`](docs/SUBSTRATE_CONTRACT.md) |

This is deliberate. A governance substrate that invents its own policy language is a product competing for adoption. One that implements everyone else's is infrastructure.

## Conformance

The [Substrate Contract](docs/SUBSTRATE_CONTRACT.md) is the versioned interface, with explicit stability and deprecation guarantees. It is the part of CAGE other implementations are intended to be able to satisfy.

Conformance is executable rather than declarative. A trace from any engine can be checked against the same formal model:

```bash
uv run python scripts/check_trace_conformance.py
```

The verifier has no dependency on `src/`, which is the point — it can judge an implementation it knows nothing about.

## When not to use this

- **You want a model that declines politely.** CAGE refuses actions, not sentences. Use guardrails or system prompts for content behaviour.
- **Your agent takes no consequential actions.** If nothing it does moves money, changes records or touches a device, this is overhead.
- **You need a managed service.** This is infrastructure you operate.
- **You need multi-language SDKs today.** The wire protocol is HTTP and framework-neutral, but the only packaged client is Python.

## Project status

Active development, pre-1.0 on the external contract. The Substrate Contract is versioned and carries deprecation guarantees; everything under `src/` may move.

- Release notes: [`CHANGELOG.md`](CHANGELOG.md)
- Security policy and advisory history: [`SECURITY.md`](SECURITY.md)
- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md) — contributions require a [CLA](https://cla.developers.google.com/about/google-individual)
- Review ownership: [`.github/CODEOWNERS`](.github/CODEOWNERS)

## License

Apache 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
