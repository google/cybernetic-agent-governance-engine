# Provider 06 Agent Integrity Conformance Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove whether a realistic CAGE governed-response artifact is compatible with the unchanged Agent Integrity `1-alpha` envelope by invoking the real vendored verifier CLI from CAGE tests.

**Architecture:** Add a deterministic fixture project and a bounded Python subprocess harness under CAGE tests. The tests invoke the vendored Node.js CLI with separately trusted policy/config files, exercise seven required verdict and mutation scenarios, and publish a result artifact. Production Provider 06 code and Agent Integrity schemas remain unchanged.

**Tech Stack:** Python 3.10–3.12, pytest via `uv`, Node.js 22+, npm 10+, vendored TypeScript Agent Integrity CLI, JSON, YAML, SHA-256.

**Approved design:** `docs/architecture/provider_06_agent_integrity_conformance_design.md`

---

## 1. Summary of Changes

This plan specifies the implementation steps to execute the Provider 06 Agent
Integrity conformance experiment defined in
[`CONFORMANCE_DESIGN.md`](CONFORMANCE_DESIGN.md).

The change adds:
- `tests/integrations/provider_06/support/provider_06_agent_integrity_cli.py` — subprocess wrapper and lock.
- `tests/integrations/provider_06/fixtures/project/docs/source.md` — trusted source bytes.
- `tests/integrations/provider_06/fixtures/project/integrity/decisions.yaml` — trusted decision registry.
- `tests/integrations/provider_06/fixtures/project/integrity/policy.yaml` — trusted policy.
- `tests/integrations/provider_06/fixtures/project/integrity/trusted-config.json` — trusted host configuration template.
- `tests/integrations/provider_06/fixtures/project/request-pass.json` — PASS request.
- `tests/integrations/provider_06/fixtures/project/request-review.json` — REVIEW request.
- `tests/integrations/provider_06/fixtures/project/request-blocked.json` — BLOCKED request.
- `docs/partners/provider_06/CONFORMANCE_RESULT.md` — observed experiment result.
- `tests/integrations/provider_06/artifacts/provider_06_agent_integrity_conformance_result.json` — scenario table evidence.
- `tests/integrations/provider_06/test_provider_06_agent_integrity_conformance.py` — pytest suite.

Modify only if required by actual repository test discovery:

- `tests/support/__init__.py` — export nothing; create only if Python package discovery requires it.

Must remain byte-identical:

- `src/integrations/provider_06/adapter.py`
- `src/integrations/provider_06/mock_endpoint.py`
- `third_party/agent-integrity/schemas/integrity-envelope.schema.json`
- `third_party/agent-integrity/schemas/integrity-receipt.schema.json`

## Chunk 1: Freeze compatibility inputs

### Task 1: Record the exact base and protocol hashes

- [ ] **Step 1: Verify branch and clean scope**

Run:

```bash
git status --short --branch --untracked-files=all
git rev-parse HEAD
```

Expected: branch `spike/provider-06-conformance`, base `94e9d717be22bafcf6307efd9434fdb04754ac6a`, and only the approved design/plan documents dirty before implementation begins.

- [ ] **Step 2: Record immutable baseline hashes**

Run:

```bash
sha256sum \
  src/integrations/provider_06/adapter.py \
  src/integrations/provider_06/mock_endpoint.py \
  third_party/agent-integrity/schemas/integrity-envelope.schema.json \
  third_party/agent-integrity/schemas/integrity-receipt.schema.json
```

Expected: four hashes recorded before implementation for diagnostic reporting. The
enforcement test will compare branch bytes directly with `94e9d717...`, so changing
an expected constant cannot hide a protected-file modification.

- [ ] **Step 3: Verify toolchain**

Run:

```bash
uv --version
node --version
npm --version
```

Expected: `uv` available, Node.js major version at least 22, and npm major version at least 10.

- [ ] **Step 4: Commit approved documentation**

```bash
git add \
  docs/architecture/provider_06_agent_integrity_conformance_design.md \
  plans/provider_06_agent_integrity_conformance_implementation_plan.md
git diff --cached --name-only
git commit -m "docs(governance): define provider 06 conformance experiment"
```

Expected: exactly the design and plan are committed.

### Task 2: Create the deterministic fixture project

**Files:** all paths under `tests/fixtures/provider_06_conformance/project/`.

- [ ] **Step 1: Derive the fixture from the public protocol**

Use `third_party/agent-integrity/packages/core/tests/support/valid-envelope.ts` and
`third_party/agent-integrity/packages/cli/tests/cli.test.ts` as implementation
references. Do not copy private keys or temporary paths.

- [ ] **Step 2: Add trusted source and decision bytes**

Create a short source document and a version-1 decision registry whose content
supports one realistic CAGE governance-response claim. Keep timestamps and IDs
fixed.

- [ ] **Step 3: Add trusted policy and config template**

The policy must allow only the fixture's `docs/` root and must reference
`integrity/decisions.yaml`. The committed config must use a documented placeholder
for `projectRoot`; the Python test replaces it with the temporary copied project
root before invoking the CLI.

- [ ] **Step 4: Add PASS, REVIEW, and BLOCKED request JSON**

Each file must contain exactly one top-level `envelope` object and conform to the
vendored schema. Use byte offsets, lengths, and SHA-256 values computed from the
committed UTF-8 bytes. Do not include CAGE-only action keys.

- [ ] **Step 5: Validate fixture JSON and schema compatibility**

Run:

```bash
uv run python - <<'PY'
import json
from pathlib import Path
import jsonschema

root = Path("tests/fixtures/provider_06_conformance/project")
schema = json.loads(Path("third_party/agent-integrity/schemas/integrity-envelope.schema.json").read_text())
for path in sorted(root.glob("request-*.json")):
    request = json.loads(path.read_text())
    assert set(request) == {"envelope"}
    jsonschema.validate(request["envelope"], schema)
    print(path)
PY
```

Expected: all three request paths print with no exception.

- [ ] **Step 6: Scan fixtures for secrets and private keys**

Run:

```bash
if rg -n --hidden \
  'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY|-----BEGIN PRIVATE KEY-----|pk-lf-[A-Za-z0-9_-]+|sk-[A-Za-z0-9_-]+|hf_[A-Za-z0-9]+' \
  tests/fixtures/provider_06_conformance; then
  echo "credential or private-key material detected" >&2
  exit 1
fi
```

Expected: no matches except clearly non-secret explanatory prose; investigate every match.

- [ ] **Step 7: Commit fixtures**

```bash
git add tests/fixtures/provider_06_conformance
git diff --cached --name-only
git commit -m "test(tests): add provider 06 conformance fixtures"
```

Expected: only fixture paths are committed.

## Chunk 2: Build the executable conformance proof

### Task 3: Write the failing harness tests

**Files:**

- Create: `tests/test_provider_06_agent_integrity_conformance.py`
- Create later: `tests/support/provider_06_agent_integrity_cli.py`

- [ ] **Step 1: Add test markers and imports**

Use:

```python
pytestmark = [pytest.mark.unit, pytest.mark.local]
```

Import only the future support helper, standard-library paths/copy tools, and pytest.

- [ ] **Step 2: Write tests for the seven frozen scenarios**

Use exact test names:

```text
test_valid_fixture_returns_pass
test_ambiguous_support_returns_review
test_blocked_fixture_returns_blocked
test_response_mutation_never_passes
test_source_mutation_never_passes
test_missing_source_never_passes
test_invalid_trusted_config_never_passes
```

Each mutation test must copy the fixture tree to `tmp_path` and mutate only the copy.

- [ ] **Step 3: Add boundary tests**

Add tests that:

- assert the request envelopes contain none of `amount`, `symbol`, `magnitude`, or `context`;
- compare each protected file byte-for-byte with
  `git show 94e9d717be22bafcf6307efd9434fdb04754ac6a:<path>`;
- inspect the complete `origin/main...HEAD` diff plus repository entry-point/plugin
  configuration and assert no Provider 06 domain-plugin implementation or
  `cage.plugins` registration was introduced.

- [ ] **Step 4: Run the tests to prove RED**

Run:

```bash
uv run pytest tests/test_provider_06_agent_integrity_conformance.py -v --no-cov -p no:langsmith -p no:langsmith_plugin
```

Expected: collection/import failure because
`tests.support.provider_06_agent_integrity_cli` does not exist.

### Task 4: Implement the bounded CLI harness

**File:** `tests/support/provider_06_agent_integrity_cli.py`

- [ ] **Step 1: Add the Apache-2.0 Python header**

Use the exact repository header from `AGENTS.md`.

- [ ] **Step 2: Define a closed result type**

Create a frozen dataclass containing only:

```python
returncode: int
stdout: dict[str, object]
stderr: str
```

- [ ] **Step 3: Implement runtime validation**

Resolve `node` and `npm`, run `node --version`, and reject versions below major 22
with a clear test-setup error. Build the CLI from the tracked vendored lockfile in a
session-scoped setup helper; do not assume ignored `dist/` files exist.

- [ ] **Step 4: Implement one bounded verify call**

Use `subprocess.run` with:

- explicit argument array;
- `cwd` set to `third_party/agent-integrity`;
- JSON request serialized to stdin;
- `text=True` and UTF-8-compatible capture;
- `capture_output=True`;
- timeout no greater than 30 seconds per verification;
- no shell;
- no inherited configuration paths beyond the explicit test arguments.

Enforce bounded captured output. Parse stdout as exactly one JSON value plus
optional surrounding whitespace (for example with `json.JSONDecoder.raw_decode`),
require that value to be an object, and reject trailing non-whitespace content.
Sanitize and truncate stderr before adding it to any assertion failure.

- [ ] **Step 5: Add a fixture-copy/config helper**

Copy the committed fixture project to `tmp_path`, replace only the config's
`projectRoot` with the absolute temporary path, and return all exact paths needed by
the verify invocation.

- [ ] **Step 6: Add clean-clone session setup using locked dependencies**

Implement a pytest session fixture or helper that runs these commands once with an
explicit working directory and bounded timeout:

```bash
cd third_party/agent-integrity
npm ci
npm run build
```

Expected: build succeeds and `packages/cli/dist/cli.js` exists. Do not commit
`node_modules/` or build artifacts unless they are already tracked.

- [ ] **Step 7: Run focused tests to GREEN**

```bash
uv run pytest tests/test_provider_06_agent_integrity_conformance.py -v --no-cov -p no:langsmith -p no:langsmith_plugin
```

Expected: all conformance and boundary tests pass.

- [ ] **Step 8: Commit harness and tests**

```bash
git add \
  tests/support/provider_06_agent_integrity_cli.py \
  tests/test_provider_06_agent_integrity_conformance.py
git diff --cached --name-only
git commit -m "test(tests): run agent integrity cli conformance"
```

Expected: exactly the helper and test file are committed.

## Chunk 3: Publish bounded results and prove repository health

### Task 5: Record the experiment result

**Files:**

- `tests/artifacts/provider_06_agent_integrity_conformance_result.json`
- `docs/architecture/provider_06_agent_integrity_conformance_result.md`

- [ ] **Step 1: Capture versions and hashes**

Record:

- CAGE base and final branch SHA;
- Agent Integrity package and protocol versions;
- Node, npm, uv, Python, and pytest versions;
- protected schema/runtime hashes before and after.

- [ ] **Step 2: Generate the machine-readable evidence artifact**

Add a deterministic test or script path that writes only scenario name, expected
and actual exit/status, and finding codes to the JSON artifact. It must never write
response content, source bytes, trusted paths, or credentials.

- [ ] **Step 3: Record all scenario outcomes in prose**

For each required scenario, record input fixture, expected exit/status, actual
exit/status, finding codes, and pass/fail. Include failures; do not rewrite the
threshold after observing results.

- [ ] **Step 4: Check prose against the JSON evidence**

Add a test that loads both artifacts and proves every scenario row in the prose
result matches the machine-readable evidence.

- [ ] **Step 5: State the bounded verdict**

Use exactly one verdict: `PASS`, `FAIL`, or `INCONCLUSIVE`, applying the approved
thresholds. State the predetermined next action and list unsupported claims.

- [ ] **Step 6: Commit the result**

```bash
git add \
  tests/artifacts/provider_06_agent_integrity_conformance_result.json \
  docs/architecture/provider_06_agent_integrity_conformance_result.md
git diff --cached --name-only
git commit -m "docs(governance): record provider 06 conformance result"
```

### Task 6: Run repository verification

- [ ] **Step 1: Run focused Provider 06 tests**

```bash
uv run pytest \
  tests/test_provider_06_agent_integrity_conformance.py \
  tests/test_provider_06_receipts.py \
  -v --no-cov -p no:langsmith -p no:langsmith_plugin
```

Expected: PASS.

- [ ] **Step 2: Run the canonical local/unit suite**

```bash
uv run pytest tests/ -m "local or unit" -n auto --dist loadscope --no-cov -p no:langsmith -p no:langsmith_plugin --tb=short
```

Expected: PASS with no new marker, import-boundary, or test-order failure.

- [ ] **Step 3: Run architecture and hygiene gates**

```bash
uv run python scripts/check_import_boundaries.py --verbose
git diff origin/main...HEAD --check
git status --short --branch --untracked-files=all
```

Expected: import boundaries pass, no whitespace errors, and no unowned files.

- [ ] **Step 4: Prove clean-clone reproducibility**

Create a temporary detached worktree at branch HEAD, prove its path and SHA, then
run the focused conformance suite without pre-existing `node_modules/` or `dist/`.
Remove only that exact temporary worktree after recording the result.

- [ ] **Step 5: Recheck protected bytes and hashes**

Repeat Task 1's `sha256sum` command.

Expected: all four protected hashes match the recorded baseline exactly.

- [ ] **Step 6: Review commits and scope**

```bash
git log --oneline origin/main..HEAD
git diff --name-status origin/main...HEAD
```

Expected: only design, plan, fixture, harness, test, and result files are changed.

### Task 7: Prepare the pull request without opening it

- [ ] **Step 1: Draft the PR title**

Use:

```text
test(governance): prove provider 06 envelope conformance
```

This satisfies CAGE Conventional Commit title rules and accurately describes a
test-only compatibility proof.

- [ ] **Step 2: Draft the PR body**

Include:

- decision being informed;
- ownership/trust boundary;
- exact files and tests added;
- machine-generated result table and matching prose summary;
- protected files confirmed unchanged;
- explicit exclusions;
- PASS/FAIL/INCONCLUSIVE result and next action;
- Google CLA and CI requirements.

- [ ] **Step 3: Stop for review**

Do not push or open the external PR until the user approves the reviewed code,
evidence, title, and body. Opening the PR is a separate externally visible action.

## Final completion gate

This plan is complete only when:

- all seven required scenarios pass their frozen expectations;
- production Provider 06 files and Agent Integrity schemas are byte-identical;
- the result document reports the bounded compatibility verdict honestly;
- the result JSON and prose document agree exactly;
- the focused suite passes from a clean detached worktree without prebuilt ignored artifacts;
- focused and canonical CAGE tests pass;
- repository architecture/hygiene gates pass;
- the worktree contains no unrelated changes;
- independent specification and code-quality/security reviews approve the branch;
- the user explicitly approves opening the external PR.
