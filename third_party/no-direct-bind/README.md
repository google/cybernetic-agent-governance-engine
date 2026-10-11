# third_party/no-direct-bind

## Origin

- **Project:** LalaSkye / no-direct-bind
- **License:** Apache License 2.0
- **Source commit:** https://github.com/LalaSkye/no-direct-bind/commit/7fe9ff99636798accd5e04136991e1d3d3079417
- **Copyright:** Copyright (c) LalaSkye contributors

## What Was Adapted

The BFS state-space enumerator and the `NoDirectBind` TLA+ safety invariant
from `no-direct-bind` were adapted into `proof/model.py` and
`proof/LangGraphHarness.tla` in this repository.

**Modifications made:**
- Extended for the CAGE 8-tier governance architecture (FTRA + 7 in-pipeline tiers)
- Added Gap 1/2/3/4 sub-proofs and concurrency-interleaving checks specific to CAGE's symbolic governor pipeline
- Adapted the `NoDirectBind` TLA+ safety invariant into `proof/LangGraphHarness.tla`
- No original source files from `no-direct-bind` are copied verbatim into this repository;
  the state-space enumeration approach and invariant formulation were adapted for CAGE's pipeline

## Attribution

This attribution is also recorded in the repository [`NOTICE`](../../NOTICE) file,
as required by the Apache License 2.0.
