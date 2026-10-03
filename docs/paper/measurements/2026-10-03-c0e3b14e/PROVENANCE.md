# Measurement Provenance — In-Cluster GKE Benchmark Run

| Field | Value |
|---|---|
| Generated | 2026-10-03T17:44:45Z |
| Git SHA | c0e3b14e |
| Environment | staging (keyring cage-signing-staging) |
| Image tag | 353065c7 |
| Benchmark image | gcr.io/laah-cybernetics/gateway@sha256:d289507624f5a236105afdcec19cfb00c99624397a936ff72458c14e5a5bfa9e |
| Pod | cage-paper-benchmark-fvjnr |
| Namespace | governance-stack |
| Job | cage-paper-benchmark |
| Redis | Throwaway `benchmark-redis` (deployment/k8s/benchmark-redis.yaml): 1 primary + 1 replica, no persistence, `gcr.io/laah-cybernetics/redis@sha256:41a05f1df0e41913c765714bcc4e2b7b61bad98686c3f8577fb5370306bd1efe` |
| Replication wait | `CAGE_REDIS_WAIT_REPLICAS=1` |
| OPA | gcr.io/laah-cybernetics/opa@sha256:bd9909283897aaf8e4409efb6fcb049f08fe6466f32467545157b66a39f4879f |
| Consensus backend | vllm-reasoning `deepseek-ai/DeepSeek-R1-Distill-Llama-8B` (gcr.io/laah-cybernetics/vllm-streamer@sha256:12e2a7f6320d54d5f098d28bc20f8104676c4e2058cc69436587912151b738e3) |
| Latency mode | over_the_wire_in_cluster |
| Scope | latency (`measure_paper_metrics.py --unmocked --latency-only`); adversarial deflection and benign FPR not measured |
| Reconciliation Redis | DB 1 of the same throwaway Redis (step 2 leaves CBF state in DB 0) |
| Output Directory | docs/paper/measurements/2026-10-03-c0e3b14e |

## Run Artifacts
- `cage_paper_metrics.json`
- `cage_paper_metrics.txt`
- `cage_reconciliation_metrics.json`
- `cage_reconciliation_metrics.txt`

## Notes

- **Image vs. HEAD.** The benchmark image was built at `353065c7`. `git diff 353065c7 c0e3b14e -- src config` is empty, so the governor code that ran is the code at HEAD. The measurement scripts are mounted from HEAD through the `benchmark-scripts` ConfigMap.
- **Table 2b path.** The real governor ALLOWs the $10 junior USD trade without HITL. The `govern (FULL, sealed)` row therefore times the gateway's single committing `govern()` pass (KMS-signed seal included), and `revalidate_post_hitl` does not apply. Per-tier rows come from the same `govern()` calls.
- **Consensus not exercised.** A $10 trade is below the consensus threshold, so Tier 5 short-circuits (P50 0.03 ms) and no vLLM critic was called. vllm-reasoning was scaled to 1 for the run and back to 0 afterwards.
- **OPA.** P50 is 22.9 ms here. An earlier attempt the same day (`ea176822`, not committed: its artifacts were never harvested) measured 54.0 ms against the same OPA digest. The cause of the difference was not investigated. Read Tier 3b as network-sensitive.
- **Deflection and benign FPR not measured.** The deployed advisor is about 26 days stale and its inference backend (`vllm-inference`) was at 0 replicas, so this run uses `BENCHMARK_SCOPE=latency`. The earlier 100%/100% numbers were HTTP 401 responses: the harness sent no bearer token. They are not reported.
- **Reconciliation (Tables 3, 4, §6.5).** Ran against DB 1 of the same throwaway Redis, signed with Cloud KMS (`evidence_grade: True`, 20/20 ticks succeeded). §6.5 reproduces the POAM-023 threat model in cluster: (a) self-reported inflated state is SAFE, (b) the reconciler detects the discrepancy, refuses to publish and advances the fence epoch, and (c) a KMS-signed $8,000 snapshot makes the CBF reject the $10,000 trade.
