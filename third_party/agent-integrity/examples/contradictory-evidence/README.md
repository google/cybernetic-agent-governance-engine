# Contradictory Evidence Example

This CLI example contains contradictory evidence in the submitted envelope but does not disclose that contradiction in the response. The configured policy routes the result to `REVIEW`.

## Run it

```bash
npm run build
node packages/cli/dist/cli.js verify --trusted-policy examples/contradictory-evidence/integrity/policy.yaml --trusted-config examples/contradictory-evidence/integrity/trusted-config.json < examples/contradictory-evidence/request.json
echo $?
```

Expected:

- JSON output reports `REVIEW`;
- process exit code is `2`;
- findings identify the undisclosed contradiction;
- source and response content are not echoed by the CLI;
- the application must hold the response for a human.

## Why it is not automatically blocked

Contradiction can require judgment. The sample policy chooses `REVIEW` so a person can inspect the claim, supporting evidence, contradictory evidence, and disclosure. A stricter policy can block the same condition.

## Try it

Copy `request.json`, then change the response disclosure metadata so the contradiction is explicitly addressed. Run verification again and compare the findings. Next, remove the contradictory item entirely and note the limitation: the engine cannot know a source was omitted unless another collector observed it.

This example proves handling of **included** contradictions only. Read [Omitted evidence](../../docs/LIMITATIONS.md#omitted-evidence).

## Safe remediation

The expected finding code is `claim.contradiction_undisclosed`. The safe repair is to explain the contradiction in the response, set the contradictory link's `disclosed` field to `true`, regenerate the exact response-section digest, and verify again.

Do not delete the contradictory evidence, relabel it as supporting, or weaken the trusted policy merely to obtain `PASS`. The verifier cannot detect evidence the host never supplies.
