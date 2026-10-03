# Measurement Provenance — In-Cluster GKE Benchmark Run

| Field | Value |
|---|---|
| Generated | 2026-10-03T21:25:21Z |
| Git SHA | 3902db4b |
| Environment | staging (keyring cage-signing-staging) |
| Image tag | 3902db4b |
| Benchmark image | gcr.io/laah-cybernetics/gateway@sha256:67374d925fa003ef9f737d180e7ddfd5186f67b46e6e0323007785706ad12148 |
| Pod | cage-paper-benchmark-gdn62 |
| Namespace | governance-stack |
| Job | cage-paper-benchmark |
| Redis | Throwaway `benchmark-redis` (deployment/k8s/benchmark-redis.yaml): 1 primary + 1 replica, no persistence, `gcr.io/laah-cybernetics/redis@sha256:41a05f1df0e41913c765714bcc4e2b7b61bad98686c3f8577fb5370306bd1efe` |
| Replication wait | `CAGE_REDIS_WAIT_REPLICAS=1` |
| OPA | gcr.io/laah-cybernetics/opa@sha256:bd9909283897aaf8e4409efb6fcb049f08fe6466f32467545157b66a39f4879f |
| Consensus backend | vllm-reasoning `deepseek-ai/DeepSeek-R1-Distill-Llama-8B` (gcr.io/laah-cybernetics/vllm-streamer@sha256:12e2a7f6320d54d5f098d28bc20f8104676c4e2058cc69436587912151b738e3) |
| Latency mode | over_the_wire_in_cluster |
| Scope | full (`measure_paper_metrics.py --unmocked`) |
| Reconciliation Redis | DB 1 of the same throwaway Redis (step 2 leaves CBF state in DB 0) |
| Output Directory | docs/paper/measurements/2026-10-03-3902db4b |

## Run Artifacts
- `cage_paper_metrics.json`
- `cage_paper_metrics.txt`
- `cage_reconciliation_metrics.json`
- `cage_reconciliation_metrics.txt`

## Deployment Under Test

| Component | Image | Notes |
|---|---|---|
| gateway | `gcr.io/laah-cybernetics/gateway@sha256:67374d925fa003ef9f737d180e7ddfd5186f67b46e6e0323007785706ad12148` (tag `3902db4b`) | Cloud Build, rolled out with `kubectl set image` (`deploy_all.sh` unusable: empty local Terraform state for `infra/targets/gcp-gke`) |
| governed-financial-advisor | `gcr.io/laah-cybernetics/governed-financial-advisor@sha256:a77dbe8560b742ece6ab0ac74f8cd24c37ad5be4251a4953a4c5b10d88d021f1` (tag `3902db4b`) | Same commit as the gateway |
| vLLM | `vllm-inference` and `vllm-reasoning` scaled 0 → 1 for the run, then back to 0 | |

## Notes

- **Superseded by `../2026-10-03-55096730/`.** This run checked #387.
- **Deflection 26/26 (100 %).** The PII-003 leak is fixed.
- **Benign FPR 10/20 (50.0 %).** The NeMo judge got the text, then failed with `Expected an LLMModel instance, got VLLMLLM` (12 × `LLM_JUDGE_FAILED`). The runtime injects the unwrapped LangChain model, and NeMo 0.23's `llm_call()` rejects it. Fixed in #388. The 4 trade refusals are unchanged; see POAM-2026-094.
