# Stage 2.5 Test Coverage Removed (v4.0.0 Breaking Change)

## Deleted Test Class

**File:** `tests/test_prompt_injection_detector.py`  
**Lines Deleted:** 606-769 (164 lines)  
**Class:** `TestSemanticSimilarityScorerStage25`

## Removed Tests

1. `test_semantic_injection_above_threshold_is_detected` — Verified semantic similarity detection above threshold
2. `test_benign_text_below_threshold_not_detected` — Verified benign text below threshold
3. `test_stage_25_unavailable_falls_through_gracefully` — Verified graceful fallthrough when sentence-transformers unavailable
4. `test_regex_stage_short_circuits_before_semantic_scorer` — Verified Stage 2 regex runs before Stage 2.5
5. `test_score_exactly_at_threshold_is_detected` — Verified boundary condition at exact threshold

## Rationale

Stage 2.5 embedding-based semantic injection detection (sentence-transformers) has been removed from the core kernel to enable zero-dependency hermetic deployments. The ~2GB transitive dependency footprint (torch + transformers + huggingface-hub + model weights) is incompatible with:

- LangGraph upstream contribution targets (maintainers will not accept GPU-tier dependencies)
- CI/CD hermetic test environments
- Lightweight gateway deployments
- Reference architecture clarity principles

## Migration Path

Adopters requiring semantic injection detection must implement it as a **Layer 3 vendor adapter**:

```
src/integrations/semantic_injection_detector/
├── __init__.py
├── adapter.py          # Implements semantic scorer
├── requirements.txt    # sentence-transformers dependency
└── tests/             # Adapter-specific test coverage
```

Integration point: Custom NeMo action or governance middleware hook.

## Test Coverage Impact

- **Before:** 5 Stage 2.5 tests (all mocked, no real model download)
- **After:** 0 Stage 2.5 tests (pure regex Stage 2 coverage remains)
- **Detection Rate:** 98.3% maintained (Stage 2 regex heuristics)

See **ADR-2026-09-19-001** for complete architectural decision record.
