# Superseded Decision Example

This example shows lifecycle validation inside one current decision-registry snapshot. The envelope declares that its claim depends on an older decision that has been replaced.

## Run it

```bash
npm run build
node packages/cli/dist/cli.js verify --trusted-policy examples/superseded-decision/integrity/policy.yaml --trusted-config examples/superseded-decision/integrity/trusted-config.json < examples/superseded-decision/request.json
echo $?
```

Expected:

- JSON output reports `BLOCKED`;
- process exit code is `3`;
- findings identify the superseded decision;
- no response content is emitted by the CLI.

## What to inspect

Open `integrity/decisions.yaml` and follow the decision revisions in order. `request.json` contains the same current snapshot and its exact registry digest. The claim's `decisionIds` points to `old`, whose latest state is superseded, so that declared reference blocks. This example does not prove the registry was preserved from an earlier run or that every semantic dependency was declared.

## Try it

- Point the claim at the active replacement and rerun.
- Add a duplicate revision and observe structural rejection.
- Add a revision gap and observe fail-closed behavior.
- Change the replacement identifier to a missing decision.

Decision validation proves lifecycle consistency, not whether the replacement decision is strategically correct.

## Safe remediation

The expected finding code is `decision.superseded`. Update the claim to the reviewed active replacement and retain the complete lifecycle in the trusted registry snapshot. Historical prose may describe the old decision, but a current claim must not rely on it as active authority.

Do not omit a real decision dependency, erase registry history, or relabel an inactive decision without a reviewed event. The engine cannot infer undeclared semantic dependencies.
