# Integration Guide

This guide shows how to place Agent Integrity between an agent draft and the application code that releases the response.

## Choose an integration mode

Use the TypeScript SDK when your agent host runs on Node.js. Use the CLI when the host is written in another language or when process isolation is useful.

| Mode | Best for | Interface | Current support |
| --- | --- | --- | --- |
| TypeScript SDK | Node.js agent applications | Imported APIs | Supported |
| JSON CLI | Python, Go, Rust, shell, workflow engines | stdin/stdout | Supported |
| Browser/edge | Client-side agents | JavaScript bundle | Not supported |
| Hosted verifier | Multi-tenant services | Network API | Not included |

Agent Integrity is model-independent. OpenAI, Anthropic, Google, local-model, LangChain, Mastra, and custom agents can use it when the host can supply the protocol data. There are no provider-specific adapters in the alpha release.

## 1. Define one project policy

Humans maintain policy once rather than creating a manifest for every response.

```yaml
version: 1
sources:
  allowedRoots:
    - docs/
    - policies/
decisions:
  path: integrity/decisions.yaml
rules:
  requireEvidenceFor:
    - factual
    - recommendation
  contradictions: review
  rejectedDecisions: block
  responseMutation: block
  replay: block
```

Policy parsing uses a restricted YAML subset. Duplicate keys, aliases, custom tags, and ambiguous scalar forms are rejected. Keep the policy in source control and require normal review for changes.

Validate it:

```bash
printf '%s' "$(node -e 'process.stdout.write(JSON.stringify({policy: require("fs").readFileSync("integrity.yaml", "utf8")}))')" \
  | node packages/cli/dist/cli.js validate-policy
```

The command exits `0` for a valid policy and `1` for invalid input.

## 2. Observe sources outside the model when possible

The strongest integration records source reads in the application host or retrieval tool rather than asking the model to list sources after drafting.

For every source, capture:

- a stable source identifier;
- the allowed relative path or equivalent approved locator;
- the SHA-256 digest of its exact bytes;
- the exact excerpt or anchor used by evidence;
- whether the collector observed the read or the agent declared it.

Do not put secrets or unnecessary source content into receipts. The CLI avoids echoing content, but the envelope itself contains the response and may contain sensitive material.

Each evidence item used by trusted verification must contain `anchor.byteStart`, `anchor.byteEnd`, and the SHA-256 of that exact byte range. Offsets refer to raw file bytes, not JavaScript character positions. The host must supply `projectRoot` and `allowedRoots`; trusted verification rejects a root list that differs from policy.

Trusted context also accepts `maxSourceBytes` and `maxTotalSourceBytes`. Defaults are 16 MiB per file and 64 MiB across one verification. File size is checked before reading and again after the bounded read. Lower these limits for small-document applications.

## 3. Record decision lifecycle events

Decisions are lifecycle events with revisions in the YAML file configured by `policy.decisions.path`. A decision can be active, rejected, or superseded. A superseding event must explicitly identify its replacement. Trusted verification reads the current file inside `projectRoot`, hashes its exact bytes, requires the envelope's `decisionRegistryDigest` and complete event snapshot to match it, and validates each decision's encountered append order.

Claims list their declared decision dependencies in `decisionIds`. Use an empty list only when the host is prepared to declare no dependency. Every referenced ID must resolve to an active decision. Historical rejected or superseded decisions may remain in the current registry; they do not block claims that do not reference them. The verifier cannot infer an omitted semantic dependency, so the trusted host must assess whether the list is complete enough for the application.

The verifier does not compare the current registry with a previous run or authenticated checkpoint. Store it in trusted, access-controlled, backed-up storage if append-only history must survive across runs. A host that truncates or rewrites the registry and supplies a matching envelope and digest can erase history without detection by protocol `1-alpha`.

The verifier rejects:

- duplicate event identifiers;
- conflicting revisions;
- revision gaps;
- references to missing replacements;
- a declared claim reference treating a rejected or superseded decision as active.

Use decisions for approved product directions, policy interpretations, editorial constraints, or any durable choice that should not be silently revived after reversal.

## 4. Map the response

Split the final response UTF-8 bytes into ordered, non-overlapping sections. Record each section's inclusive `byteStart`, exclusive `byteEnd`, and SHA-256 of those exact bytes. The sections must cover the response from byte zero to its full byte length without gaps, and every section must be covered by one or more claims.

Each claim has a type such as factual, recommendation, or inference. Claims reference evidence items. Evidence has one role:

- `supporting`: can satisfy an evidence requirement;
- `contradictory`: must be disclosed according to policy;
- `contextual`: adds background but cannot prove a claim by itself.

Do not use contextual evidence as supporting evidence. When support is semantically ambiguous, route the claim to `REVIEW` rather than pretending the engine proved meaning.

## 5. Build and verify with TypeScript

```js
import { readFile } from "node:fs/promises";
import { parsePolicy, verifyTrustedEnvelope } from "@agent-integrity/core";
import {
  AgentIntegritySession,
  releaseVerifiedResponse,
} from "@agent-integrity/sdk";

const policyText = await readFile("integrity.yaml", "utf8");
const policy = parsePolicy(policyText);
const session = new AgentIntegritySession(policy, decisionRegistryDigest);

// Populate these from your retrieval/tooling layer and agent output.
session.addSource(sourceRecord);
session.addDecision(decisionEvent);
session.addEvidence(evidenceItem);
session.addClaim(claim);
session.setResponse(draft, sections);

const context = {
  projectRoot: process.cwd(),
  allowedRoots: policy.sources.allowedRoots,
  decisionRegistryPath: policy.decisions.path,
  trustedPolicy: policy,
};
const envelope = session.buildEnvelope();
const verification = await verifyTrustedEnvelope(envelope, context);
const release = await releaseVerifiedResponse({ envelope, verification, context });

switch (release.status) {
  case "PASS":
    // This is the only response string that may be sent to the user.
    return release.response;
  case "REVIEW":
    await reviewQueue.add({ findings: release.verification.findings });
    return undefined;
  case "BLOCKED":
    logger.warn({ findings: release.verification.findings });
    return undefined;
}
```

Use [the basic example](../examples/basic-agent/README.md) for concrete protocol objects that run against the current package APIs.

## 6. Prevent release bypass

The release guard only helps if it controls the application’s final output path.

- Do not stream draft tokens directly to the end user.
- Do not log draft content to a user-visible console.
- Do not retain a second code path that sends the raw model result.
- Do not convert checker exceptions into a pass.
- Do not regenerate or edit prose after verification.
- If formatting must change, apply it before verification or verify the final bytes again.

A useful application invariant is: **the network response body comes only from `release.response`.**

## Using the CLI from any language

Build the repository, then call:

```bash
node packages/cli/dist/cli.js verify --trusted-policy /absolute/project/integrity/policy.yaml --trusted-config /etc/agent-integrity/trusted-config.json < verify-request.json > verify-result.json
status=$?
```

`verify-request.json` contains only the untrusted envelope:

```json
{
  "envelope": { "protocolVersion": "1-alpha" }
}
```

The host-controlled config contains `projectRoot`, `allowedRoots`, and `decisionRegistryPath`. Recheck additionally requires `receiptStoreDirectory` and `trust` with public keys, issuer, audience, purpose, engine version, revoked key IDs, and optional timing bounds. The CLI ignores trust values in stdin, uses the host clock, recollects every file, and fails closed on disagreement.

Handle every exit code explicitly:

```bash
case "$status" in
  0) echo "PASS: release only the bound response" ;;
  2) echo "REVIEW: hold for a human" ;;
  3) echo "BLOCKED: hold and inspect findings" ;;
  *) echo "ERROR: fail closed" ;;
esac
```

Never infer success solely from valid JSON output. Check both the process exit code and the returned status.

### Python subprocess example

```python
import json
import subprocess

request = json.load(open("verify-request.json", encoding="utf-8"))
completed = subprocess.run(
    [
        "node",
        "packages/cli/dist/cli.js",
        "verify",
        "--trusted-policy",
        "/absolute/project/integrity/policy.yaml",
        "--trusted-config",
        "/etc/agent-integrity/trusted-config.json",
    ],
    input=json.dumps(request),
    text=True,
    capture_output=True,
    check=False,
)
result = json.loads(completed.stdout)

if completed.returncode == 0 and result["status"] == "PASS":
    release_exact_bound_response()
elif completed.returncode == 2:
    queue_human_review(result["findings"])
else:
    block_release(result.get("findings", []))
```

## Receipts and rechecking

Create a receipt only with `createReceipt` and the same trusted context used for verification. The function asynchronously recollects every declared source before it writes a create-once local receipt file and run-ID marker. Recheck before release when time has passed or source state may have changed.

A recheck validates:

- receipt version and self-digest;
- exact envelope digest;
- freshly recollected declared source bytes and evidence anchors;
- expiry;
- recorded outcome consistency.
- Ed25519 producer signature, trusted/revoked key state, issuer, audience, purpose, engine version, policy digest, and timestamp bounds.

Signed alpha receipts require an Ed25519 private key at issuance, an explicit trusted public-key set, and a shared `FileReceiptStore` at recheck/release. Protect private keys outside the repository and configure key IDs, issuer, audience, purpose, engine version, maximum lifetime, clock skew, revocation, and the store directory consistently. A successful recheck consumes the receipt exactly once in that local registry.

## Result handling and remediation

For `REVIEW`, show the human the findings, response, evidence mapping, and contradictions. The reviewer may approve outside the engine, request better evidence, or ask the agent to produce a new run. Do not mutate the verified envelope in place.

For `BLOCKED`, fix the specific violation and create a fresh run identifier and nonce. Do not overwrite consumed state. Every operation uses the same owner-token store lock, which is never stolen based on age. If a crash leaves it behind, stop all users and recover it only with the exact token. Output failure retains committed issuance; finish it with `completeReceiptFile`. It is not a distributed database, and backups must not restore older consumption state.

For checker errors, preserve only safe diagnostic metadata, fail closed, and investigate. Source or response contents should not be placed in general application logs.

## Experimental deployment checklist

- [ ] Project policy is reviewed and version-controlled.
- [ ] Source roots are narrow and intentional.
- [ ] Source reads are collected outside the model when feasible.
- [ ] Decision events are reviewed, stored with trusted cross-run history controls, and ordered correctly within the current snapshot.
- [ ] A trusted host checks that each claim's declared `decisionIds` does not omit a known dependency.
- [ ] Response sections cover every UTF-8 byte exactly once and their digests match.
- [ ] Every response section is mapped to at least one claim.
- [ ] Contradictions are surfaced according to policy.
- [ ] Draft response bytes never reach users before verification.
- [ ] `REVIEW`, `BLOCKED`, and errors release nothing.
- [ ] Every receipt consumer uses one protected, shared, monotonic local `FileReceiptStore`; exactly one successful consumption is enforced only inside that store, and restoring an older backup can reopen replay.
- [ ] Sensitive envelope data is excluded from logs.
- [ ] The application is tested against tampering, changed-envelope reuse, expiry, and repeated-use behavior.
- [ ] Teams understand that `PASS` does not prove truth or evidence completeness.
