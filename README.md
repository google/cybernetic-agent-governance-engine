# CAGE — Cybernetic Agent Governance Engine

A runtime control plane that sits between an AI agent and the things it can actually do. Every tool call, spend, and actuation passes through a deterministic policy pipeline that either clears it or refuses it — and writes a signed, tamper-evident receipt either way.

CAGE is domain-agnostic infrastructure. It makes no assumptions about what your agent does, and it does not require you to adopt a particular agent framework, model provider, or cloud.

> This is not an officially supported Google product.

## See it refuse something (~3 minutes)

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

You should see an atomic `ALLOW` and two hard refusals (`FISCAL_CAP_EXCEEDED`) under concurrent load, then a high-risk action deferred to human review with mandatory rationale, then SHA-256 tamper-evident receipt verification.

*Roughly 3 minutes on a cold Docker cache, under a minute warm. Most of the cold time is the container build, not CAGE.*

**What just happened:** the denial was not a model declining to answer. The model was never consulted. A policy evaluated the action against a budget barrier and refused it before the actuation path was reachable, and the refusal is cryptographically attested.

For the full walkthrough, including live OPA policy refusals (`CTRL_OPA_005`) and switching domains, see [`docs/QUICKSTART.md`](docs/QUICKSTART.md).

## Bring your own policy format

CAGE does not ask you to rewrite your policies in a CAGE-specific language. The substrate ingests several existing specifications and compiles them to the same enforcement artifacts:

| Format | Detected by | Spec |
|---|---|---|
| Microsoft ACS | `behaviorDeclarations` | [`agent-control-specification`](https://github.com/microsoft/agent-control-specification) |
| Linux Foundation AAIF | `governedRunLoop` | AAIF working group |
| OSCAL 1.1.x | `oscal-version` | [NIST OSCAL](https://pages.nist.gov/OSCAL/) |
| Lula validation manifest | `kind: LulaValidation` | [lula.dev](https://lula.dev/) |
| Native CAGE YAML | fallback | [`docs/SUBSTRATE_CONTRACT.md`](docs/SUBSTRATE_CONTRACT.md) |

The interface you target is the [Substrate Contract](docs/SUBSTRATE_CONTRACT.md), which carries explicit versioning and deprecation guarantees. It is the part of CAGE we intend other implementations to be able to satisfy.

## Verifiable, not just auditable

Governance claims are worth what you can check. CAGE emits a `GOVERNANCE_TRACE` event stream that can be replayed against a formal model independent of the running system:

```bash
uv run python scripts/check_trace_conformance.py
```

The verifier in [`proof/`](proof/) has no dependency on `src/`, so a trace from any engine can be checked against the same state machine. Mediation coverage is machine-verified by exhaustive model checking rather than asserted in prose.

## Architecture in one pass

```text
agent → gateway → [ FTRA → STPA → OPA → confidence → warrant → CBF → consensus → causal ]
                            ↓                                                    ↓
                     refuse + receipt                                     clear + receipt
```

- **Kernel** — domain- and vendor-neutral enforcement. Import boundaries are enforced in CI, not by convention.
- **Domain plugins** — finance and healthcare ship complete configurations. Exactly one domain is active per process.
- **Adapters** — LangGraph today, via [`packages/cage-client`](packages/cage-client/).

Deeper material lives in [`docs/architecture/`](docs/architecture/), and the formal guarantees — control barrier functions, reachability analysis, the correctness invariants — are documented in [`docs/architecture/`](docs/architecture/) with proofs under [`proof/`](proof/).

## When not to use this

Worth being direct about the boundaries:

- **You want a model that declines politely.** CAGE refuses actions, not sentences. Use guardrails or system prompts for content behaviour.
- **Your agent takes no consequential actions.** If nothing it does moves money, changes records, or touches a device, this is overhead.
- **You need a managed service.** This is infrastructure you operate.
- **You need multi-language SDKs today.** The wire protocol is HTTP and framework-neutral, but the only packaged client is Python.

## Project status

Active development, pre-1.0 on the external contract. The Substrate Contract is versioned and carries deprecation guarantees; everything under `src/` may move.

- Release notes: [`CHANGELOG.md`](CHANGELOG.md)
- Security policy and advisory history: [`SECURITY.md`](SECURITY.md)
- Contributing: [`CONTRIBUTING.md`](CONTRIBUTING.md) — contributions require a [CLA](https://cla.developers.google.com/about/google-individual)
- Review ownership: [`.github/CODEOWNERS`](.github/CODEOWNERS)

CAGE implements the five-plane reference architecture described in Tallam (2026), *A Five-Plane Reference Architecture for Runtime Governance of Production AI Agents*, arXiv:2606.12320. Full attribution in [`ACKNOWLEDGEMENTS.md`](ACKNOWLEDGEMENTS.md).

## License

Apache 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
