# Basic Agent Example

This is the smallest complete agent-first integration. It demonstrates the boundary between an agent draft and the deterministic release decision.

## What it demonstrates

- constructing a complete envelope through `AgentIntegritySession`;
- binding the exact configured decision-registry bytes and its complete event snapshot;
- binding a response section to exact UTF-8 byte offsets and a digest, then mapping it to a claim and supporting evidence;
- calculating a deterministic `PASS`;
- releasing only the exact verified response.

## Run it

From the repository root:

```bash
npm ci
npm run build
node examples/basic-agent/index.mjs
```

Expected behavior:

- the process exits `0`;
- verification returns `PASS`;
- the release guard returns the exact response;
- findings are empty.

Read [index.mjs](index.mjs) from top to bottom. The protocol objects are intentionally explicit so you can see what a real retrieval layer and agent adapter must provide.

## Adapt it to an agent framework

1. Replace the synthetic source with records created by `collectSource` when your retrieval or file tool reads content.
2. Create each evidence anchor from the exact byte range used, not from decoded character offsets.
3. Load the policy from host-controlled configuration and pass it as `trustedPolicy`, with the trusted project root and policy-matching allowed roots, to both `verifyTrustedEnvelope` and `releaseVerifiedResponse`.
4. Replace the empty `integrity/decisions.yaml` registry with reviewed events, preserve its history in trusted storage, update its digest and snapshot, and declare the active IDs each claim depends on. The verifier cannot discover omitted semantic dependencies.
5. Ask the agent to emit structured claims, evidence references, and response sections alongside its prose.
6. Validate the structured output before adding it to the session.
7. Call the verifier after the complete response exists.
8. Return only the response from the release guard.

Do not stream the raw model draft to the user. Buffer it until verification finishes.

## Try failure cases

- Change the evidence role from supporting to contextual; the claim can no longer satisfy required support.
- Delete the claim; the response section becomes uncovered.
- Change the response after verification; the release guard refuses it.
- Reference a rejected decision; verification blocks the run.

## Experimental deployment note

This example lets the application populate every object directly. For stronger evidence completeness, source records should come from host-observed retrieval events, not solely from the model’s self-report. See [Limitations](../../docs/LIMITATIONS.md#omitted-evidence).

`PASS` confirms the deterministic envelope and trusted-byte checks. It does not determine whether the cited text actually proves the prose, whether the model omitted contrary evidence, or whether an undeclared decision dependency exists.
