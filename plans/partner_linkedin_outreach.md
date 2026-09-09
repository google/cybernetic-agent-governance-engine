# Partner Outreach — LinkedIn Message (Naming Gate)

> **Purpose:** unblock Phases 1–3 of
> [`layer_inversion_remediation_plan.md`](layer_inversion_remediation_plan.md)
> by resolving the one open question in §3.1 — how each partner wants their
> brand handled in committed code.
>
> **Reference Architecture Note.** CAGE is an illustrative reference
> architecture. These messages describe a naming convention for adopters and
> partners to adapt, not a contractual commitment.

## Scope note

Send **only the naming question**. The payload-key and topology changes in
[`refactoring_vendor_communications.md`](refactoring_vendor_communications.md)
are longer-form and belong in email, not a LinkedIn DM. One question, one
decision, one reply.

---

## Generic template (~150 words)

> Hi {NAME} — quick one on the CAGE integration.
>
> We're tightening the layer boundaries in the governance kernel before the
> v4.0.0 freeze, and it surfaced a naming decision I'd rather you make than me.
>
> Today your integration is anonymised inconsistently: the package path is
> `provider_0N`, but the real name still appears in some executable symbols and
> a compliance filename. I want to make it deliberate, either way.
>
> Our default going forward:
> - **Code identifiers stay anonymised** (`provider_0N`) — keeps imports stable
>   and keeps the kernel vendor-neutral.
> - **Your real name stays in the docs** — READMEs, architecture notes, and
>   audit history. That's attribution, and we'd rather keep it.
>
> If you'd prefer the opposite — your name used consistently in committed code —
> that's equally fine, just say so.
>
> Any objection to the default? A one-line reply unblocks us.
>
> Thanks,
> {YOUR NAME}

---

## Per-partner substitution

Replace the third paragraph's specifics:

| Partner | Path | Where the real name still leaks |
|---|---|---|
| FlowSignal | `provider_01` | Kernel enum members and finding codes (`FLOWSIGNAL_HOLD`, `FLOWSIGNAL_REFUSE`), a Redis key namespace, and [`lula-validation-flowsignal.yaml`](../compliance/lula/lula-validation-flowsignal.yaml) |
| TrustLayers | `provider_02` | Historical git references and coverage reports only — code is clean |
| VERITAS | `provider_03` | Architecture and analysis documents only — code is clean |
| Veraxis (VEIP) | `provider_05` | Already correct — see the naming note in [`provider_05/README.md`](../src/integrations/provider_05/README.md:8) |
| Agent Integrity | `provider_06` | Env var prefix `CAGE_AGENT_INTEGRITY_*` and vendored docs under `third_party/` |

**FlowSignal is the only blocking one.** Theirs is the sole integration whose
name is load-bearing in kernel executable code, so Phases 1–3 cannot start until
they reply. The others are courtesy notifications and can be sent in parallel
without gating anything.

For Veraxis, replace the question with a confirmation:

> Your integration already follows the convention we're standardising on — real
> name in the README, `provider_05` in the import path. Nothing needed from you;
> flagging it so you're not surprised when the other integrations shift to match.

---

## What a reply unblocks

| Reply | Consequence |
|---|---|
| "Default is fine — anonymise the code" | Phases 1–3 proceed as drafted; complete the rename through the compliance artifacts |
| "Use our real name consistently" | Phases 1–3 shrink substantially: kernel symbols still get vendor-neutral names (the kernel must not name *any* partner), but the adapter's own emitted finding codes keep the brand, and the Lula filename stays |
| No reply within the review window | Proceed with the default and record the decision in the plan — anonymisation is the reversible choice; a partner can always ask for attribution later |

Either answer resolves the gate. The vocabulary mapping table still needs
ratifying against the CSA AARM vectors regardless — that is an internal task
and does not depend on any partner.
