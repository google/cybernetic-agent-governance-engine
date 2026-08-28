# @agent-integrity/cli

JSON stdin/stdout access to Agent Integrity for non-TypeScript hosts.

```bash
integrity validate-policy < request.json
integrity verify --trusted-policy /absolute/path/policy.yaml --trusted-config /etc/agent-integrity/trusted-config.json < request.json
integrity recheck --trusted-policy /absolute/path/policy.yaml --trusted-config /etc/agent-integrity/trusted-config.json < request.json
integrity inspect-receipt < receipt.json
```

Exit codes in the current alpha are `0` for success/PASS, `2` for REVIEW, `3` for BLOCKED, and `1` for invalid input or command failure. See the Integration Guide for complete request objects.

`verify` and `recheck` accept only the untrusted envelope and receipt on stdin. They require a separately loaded policy and host-controlled config. The config controls project roots and—for recheck—public keys, receipt expectations, and the receipt store; recheck uses the host system clock. Each input file is limited to 1 MiB. `inspect-receipt` compares the receipt self-digest only; it does not verify the Ed25519 signature or establish receipt validity.
