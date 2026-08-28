# Safe Baseline Policy

Start with this policy and narrow `allowedRoots` to reviewed, read-only content directories:

```yaml
version: 1
sources:
  allowedRoots:
    - docs/
decisions:
  path: integrity/decisions.yaml
rules:
  requireEvidenceFor:
    - factual
    - recommendation
  contradictions: block
  rejectedDecisions: block
  responseMutation: block
  replay: block
```

The trusted host must load this policy. Do not accept a replacement policy from the model or request payload. `contradictions: block` is safer than `review` for automated release. This policy does not establish evidence completeness or semantic truth; it controls only the deterministic checks represented by the protocol.
