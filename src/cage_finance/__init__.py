# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""CAGE Finance Plugin — Domain governance tiers and tool provider."""

# ---------------------------------------------------------------------------
# Canonical action surface (domain plugin's single source of truth)
# ---------------------------------------------------------------------------
# Every action name the cage_finance plugin presents to the FTRA classifier
# MUST appear here. The FTRA staleness gate (scripts/check_ftra_registry_staleness.py)
# and the corresponding conformance tests compare this set against the terminal
# registry to detect entries that are stale in either direction (Issue #107 —
# Mayur Agnihotri, https://github.com/google/cybernetic-agent-governance-engine/issues/107):
#
#   REGISTERED_ACTIONS - registry → actions live in domain but unclassified
#                                   (will silently default to IRREVERSIBLE_TERMINAL)
#   registry - REGISTERED_ACTIONS → registry has entries for actions that no
#                                   longer exist in the domain plugin
#
# Keep this set in sync with:
#   - src/cage_finance/tiers/*/handles() implementations
#   - config/opa/trade_policy.rego action name bindings
#   - config/ftra/terminal_registry.json terminals block
REGISTERED_ACTIONS: frozenset[str] = frozenset(
    {
        "execute_trade",  # IRREVERSIBLE_TERMINAL — classified by all 4 tiers
        "execute_trade_bounded",  # EXTERNALLY_REVERSIBLE — bounding_tier
        "release_wire",  # EXTERNALLY_REVERSIBLE — wire transfer
        "write_db",  # IRREVERSIBLE_TERMINAL — database write
        "check_balance",  # READ_ONLY — balance query
        "prompt_injection_check",  # READ_ONLY — safety pre-screen
    }
)
