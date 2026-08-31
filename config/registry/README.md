# config/registry — GEAP Agent Registry Artifacts

> **GCP Adaptation:** The files in this directory are generated for and consumed
> by the GEAP Agent Registry (Vertex AI Agent Engine). They are part of an
> optional GCP-specific deployment path. Cloud-agnostic deployments (AWS, Azure,
> on-premises) do not use these files — they use `config/agent_catalog.json`
> directly.

---

## Files

### `generated_tool_authorizations.json`

**What it is:** A machine-generated JSON manifest that maps each STPA-derived
control action (tool) to its authorization policy — which roles may invoke it,
which UCAs constrain it, and what approval thresholds apply.

**How it is generated:**

```bash
uv run python -m src.gateway.governance.stpa_compiler compile \
  --targets registry \
  --registry-out config/registry/generated_tool_authorizations.json
```

The compiler reads `config/stpa_control_structure.yaml` and calls
[`generate_registry_manifest()`](../../src/gateway/governance/stpa_compiler.py)
to produce this file. **Do not edit it manually** — edit the YAML and
re-run the compiler.

**Schema version:** `1.0.0`

---

## JSON Schema

```json
{
  "_generated_by": "CAGE stpa_compiler",
  "_source": "config/stpa_control_structure.yaml",
  "_generated_at": "<ISO-8601 UTC timestamp>",
  "_schema_version": "1.0.0",
  "tool_authorizations": [
    {
      "tool_name": "execute_trade",
      "allowed_roles": ["trader", "senior"],
      "denied_roles": ["junior"],
      "uca_refs": ["UCA-1", "UCA-2"],
      "hazard_refs": ["H-1", "H-2"],
      "requires_approval_above_usd": 10000
    }
  ]
}
```

### Field descriptions

| Field | Type | Description |
|---|---|---|
| `_generated_by` | string | Always `"CAGE stpa_compiler"` |
| `_source` | string | Source YAML file path |
| `_generated_at` | string | ISO-8601 UTC generation timestamp |
| `_schema_version` | string | Schema version for forward compatibility |
| `tool_authorizations` | array | One entry per unique control action |
| `tool_authorizations[].tool_name` | string | The control action / tool name |
| `tool_authorizations[].allowed_roles` | string[] | RBAC roles permitted to invoke this tool |
| `tool_authorizations[].denied_roles` | string[] | RBAC roles explicitly denied |
| `tool_authorizations[].uca_refs` | string[] | UCA IDs that constrain this tool |
| `tool_authorizations[].hazard_refs` | string[] | Hazard IDs referenced by those UCAs |
| `tool_authorizations[].requires_approval_above_usd` | number | (optional) Manual review threshold in USD |

---

## How to push to the GEAP Agent Registry (GCP only)

After generating the manifest, push it to the GEAP Agent Registry using the
[`AgentRegistryAdapter`](../../src/gateway/governance/ingress/agent_registry_adapter.py):

```python
import asyncio
import json
from src.gateway.governance.ingress.agent_registry_adapter import AgentRegistryAdapter


async def push():
    adapter = AgentRegistryAdapter()
    with open("config/registry/generated_tool_authorizations.json") as f:
        manifest = json.load(f)
    await adapter.push_tool_authorizations(manifest)


asyncio.run(push())
```

**Prerequisites:**
- `CAGE_AGENT_REGISTRY_PROJECT` must be set to your GCP project ID.
- Application Default Credentials must be configured (`gcloud auth application-default login`).
- The GEAP Agent Registry resource must exist at the configured location.

> **Note:** The exact REST API endpoint for pushing tool authorizations must be
> verified against the live GEAP API at deployment time. See the `push_tool_authorizations()`
> docstring in `agent_registry_adapter.py` for details.

---

## CI/CD integration

The `.github/workflows/policy_compile.yml` workflow automatically generates
this manifest on every push that modifies `config/stpa_control_structure.yaml`.
The generated file is committed back to the repository as a CI artifact.

The workflow also validates the manifest JSON structure:

```yaml
- name: Validate registry manifest JSON
  run: |
    python -c "
    import json, sys
    with open('config/registry/generated_tool_authorizations.json') as f:
        manifest = json.load(f)
    assert 'tool_authorizations' in manifest, 'Missing tool_authorizations key'
    assert '_schema_version' in manifest, 'Missing _schema_version key'
    print(f'Registry manifest OK: {len(manifest[\"tool_authorizations\"])} tool entries')
    "
```

---

## Cloud-agnostic deployments

If `CAGE_AGENT_REGISTRY_PROJECT` is **not** set, the
[`AgentRegistryAdapter`](../../src/gateway/governance/ingress/agent_registry_adapter.py)
is a complete no-op. The gateway uses `config/agent_catalog.json` directly
via OPA's `data.agent_catalog_data` document. No changes to cloud-agnostic
deployments are required.

The `AgentRegistryDaemon` (wired into the gateway lifespan) logs a debug
message and exits immediately when unconfigured:

```
AgentRegistryDaemon: CAGE_AGENT_REGISTRY_PROJECT not set —
no-op (cloud-agnostic deployment uses config/agent_catalog.json directly).
```

---

## Related files

| File | Purpose |
|---|---|
| `config/agent_catalog.json` | Static agent catalog — cloud-agnostic fallback |
| `config/opa/agent_catalog.rego` | OPA policy reading `data.agent_catalog_data.agents` |
| `config/stpa_control_structure.yaml` | Source of truth for tool authorization rules |
| `src/gateway/governance/ingress/agent_registry_adapter.py` | GCP adapter + daemon |
| `src/gateway/governance/stpa_compiler.py` | Compiler that generates this manifest |
