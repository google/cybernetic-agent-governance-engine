# 15-Minute Trusted-Host Tutorial

This tutorial runs the complete local flow without an external model. The fake agent represents structured model output; the host owns policy, file collection, decision storage, verification, and release.

## 1. Install and verify

```bash
git clone https://github.com/SimranPabla/agent-integrity.git
cd agent-integrity
npm ci
npm run verify
```

The repository may remain private until the maintainer explicitly approves publication. The URL above is the final public location.

## 2. Inspect the trusted inputs

The runnable project is `examples/basic-agent/`:

- `docs/maintenance.md` is the approved source.
- `integrity/decisions.yaml` is the trusted decision snapshot.
- `index.mjs` is the host and fake-agent flow.

The policy allows only `docs/`, requires evidence for factual and recommendation claims, and blocks mutation and replay. In a real application, load it from host configuration rather than model output.

## 3. Follow the data flow

`index.mjs` performs these steps:

1. Create trusted context from the project root and policy.
2. Call `collectSource` to read approved bytes and calculate their digest.
3. Hash the exact evidence byte anchor used by the claim.
4. Hash the trusted decision-registry YAML.
5. Build a response with exact UTF-8 section offsets and digest.
6. Add its claim and supporting evidence link.
7. Call `verifyTrustedEnvelope`, which recollects source and registry bytes.
8. Call the release guard and print only its returned response on `PASS`.

Run it:

```bash
npm run build
node examples/basic-agent/index.mjs
```

Expected result contains:

```json
{
  "status": "PASS",
  "response": "The maintenance window begins at 09:00 UTC."
}
```

`PASS` means the supplied envelope satisfied deterministic checks and matched the trusted files at verification time. It does not mean the sentence is objectively true or that the model disclosed every relevant source or dependency.

## 4. Exercise review and blocking

```bash
node packages/cli/dist/cli.js verify --trusted-policy examples/contradictory-evidence/integrity/policy.yaml --trusted-config examples/contradictory-evidence/integrity/trusted-config.json < examples/contradictory-evidence/request.json
echo $?
node packages/cli/dist/cli.js verify --trusted-policy examples/superseded-decision/integrity/policy.yaml --trusted-config examples/superseded-decision/integrity/trusted-config.json < examples/superseded-decision/request.json
echo $?
node examples/tampered-response/index.mjs
```

Expected exit codes are `2` for the contradiction needing review and `3` for the rejected decision. The tampering example refuses changed response bytes.

## 5. Add receipts to a real host

Generate an Ed25519 key outside the model process, protect the private key, configure trusted public keys by key ID, and issue short-lived receipts for a fixed issuer, audience, and purpose. Keep the receipt store on one protected local filesystem. Release/recheck consumes the receipt exactly once; a concurrent or repeated consumer is blocked.

Never commit private keys. Keep old public keys until all intended receipts expire, unless compromised. Test rotation and recovery before using receipts operationally.

## 6. Integrate a model

Ask the model for a draft plus structured sections, claims, decision IDs, and evidence references. Validate that object strictly. The host—not the model—must collect sources, load policy/decisions, calculate byte digests, verify, create/consume receipts, and release the final bytes.

Do not stream the draft. Route `REVIEW` to a human queue and treat `BLOCKED` as a failed release.
