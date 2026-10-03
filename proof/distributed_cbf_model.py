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

"""Distributed CBF fence-epoch model with a lagging Redis replica.

Exhaustive BFS over the admission protocol that
``src/gateway/governance/safety/cbf_engine.py`` runs for N gateway processes
sharing one Redis primary that asynchronously replicates to one replica.
``proof/DistributedCBF.tla`` is a line-for-line transliteration; TLC on
``proof/DistributedCBF*.cfg`` must report the same distinct-state counts
(pinned in :data:`EXPECTED_STATE_COUNTS` and by
``tests/test_distributed_cbf_proof.py``).

Runtime correspondence (one model agent = one gateway process):

==================  =========================================================
Model action        Runtime
==================  =========================================================
``read``            ``_check_fence_epoch``: reject when the live epoch is
                    below the in-process ``_last_seen_epoch``; otherwise raise
                    ``_last_seen_epoch`` and keep the read scalar + epoch.
``write``           ``LUA_ATOMIC_CBF``: CAS on ``safety:fence_epoch``, barrier
                    on the *read* scalar (ARGV[5]), ``SET`` the new state,
                    ``INCR`` the epoch, ledger the debit. Python then assigns
                    ``_last_seen_epoch = new_epoch``.
``write_reject``    CAS mismatch (``Fence epoch regression``) — no effect.
``commit``          Actuation. Not fenced again. Under strict replication it
                    runs only after ``WAIT N`` acknowledged the debit.
``rollback``        ``LUA_ROLLBACK`` by ``debit_id``: reconciled mode removes
                    the ledger entry if the primary holds it; a missing entry
                    takes ``ROLLED_BACK_SETTLED`` and restores the magnitude to
                    the state key, which only the self-reported barrier reads.
                    ``INCR``\\ s the epoch; Python assigns ``_last_seen_epoch``.
``replicate``       Asynchronous primary → replica copy.
``stale_failover``  Replica promoted: balance, epoch, HWM and ledger regress.
                    In-process ``_last_seen_epoch`` is untouched. Under strict
                    replication a debit the replica lacks cannot be actuated
                    (its ``WAIT`` fails); the process rolls it back.
``agent_restart``   Process restart: ``_last_seen_epoch`` re-seeded from the
                    (possibly stale) primary's ``max(epoch, hwm)``.
==================  =========================================================

``safety:fence_epoch_hwm`` lives in the same Redis instance as the epoch and
regresses with it, so it adds nothing beyond ``fence_epoch`` here.

Safety property:
    SP-1  spent + actuatable in-flight debits ≤ InitialPool (no double
          spend; ``spent`` is the broker side effect and never regresses).
    SP-2  available + spent + actuatable in-flight debits ≤ InitialPool (no
          over-credit; the leading indicator of a later SP-1 violation).
    SP-4  the fence epoch decreases only at a stale failover (transition
          property).

Usage:
    uv run python proof/distributed_cbf_model.py
"""

from __future__ import annotations

import sys
from collections import deque
from dataclasses import dataclass
from typing import NamedTuple

# ---------------------------------------------------------------------------
# Bounds (must match proof/DistributedCBF*.cfg)
# ---------------------------------------------------------------------------

INITIAL_POOL = 2
RESERVE_AMOUNT = 1
MAX_AGENT_RESERVE = 1
MAX_FENCE_EPOCH = 4
MAX_STALE_FAILOVERS = 1


@dataclass(frozen=True)
class Config:
    """One model configuration (one ``.cfg`` file)."""

    n_agents: int
    sync_replication: bool = True
    reconciled: bool = True
    fenced: bool = True
    allow_restart: bool = True
    max_stale_failovers: int = MAX_STALE_FAILOVERS


class State(NamedTuple):
    """Mirrors the TLA+ VARIABLES, in the same order."""

    available_balance: int
    fence_epoch: int
    rep_balance: int
    rep_epoch: int
    agent_reserves: tuple[int, ...]
    ledger: tuple[int, ...]
    rep_ledger: tuple[int, ...]
    agent_epochs: tuple[int, ...]
    read_balance: tuple[int, ...]
    read_epoch: tuple[int, ...]
    spent: int
    stale_failovers: int


def initial_state(cfg: Config) -> State:
    zeros = (0,) * cfg.n_agents
    return State(
        available_balance=INITIAL_POOL,
        fence_epoch=1,
        rep_balance=INITIAL_POOL,
        rep_epoch=1,
        agent_reserves=zeros,
        ledger=zeros,
        rep_ledger=zeros,
        agent_epochs=(1,) * cfg.n_agents,  # seeded from Redis at startup
        read_balance=zeros,
        read_epoch=zeros,
        spent=0,
        stale_failovers=0,
    )


def _set(t: tuple[int, ...], i: int, v: int) -> tuple[int, ...]:
    return (*t[:i], v, *t[i + 1 :])


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


def read(s: State, a: int, cfg: Config) -> State | None:
    if s.read_epoch[a] != 0 or s.agent_reserves[a] >= MAX_AGENT_RESERVE:
        return None
    if s.available_balance < RESERVE_AMOUNT:
        return None
    if cfg.fenced and s.agent_epochs[a] > s.fence_epoch:
        return None  # CBF_EPOCH_REGRESSION_DETECTED
    return s._replace(
        agent_epochs=_set(s.agent_epochs, a, max(s.agent_epochs[a], s.fence_epoch)),
        read_balance=_set(s.read_balance, a, s.available_balance),
        read_epoch=_set(s.read_epoch, a, s.fence_epoch),
    )


def write(s: State, a: int, cfg: Config) -> State | None:
    if s.read_epoch[a] == 0 or s.fence_epoch >= MAX_FENCE_EPOCH:
        return None
    if cfg.fenced and s.fence_epoch != s.read_epoch[a]:
        return None
    # Reconciled mode nets the live outstanding total inside the script and
    # refuses a replaced snapshot, so the barrier sees the live balance.
    # Self-reported mode evaluates the scalar Python read (ARGV[5]).
    basis = s.available_balance if cfg.reconciled else s.read_balance[a]
    if basis < RESERVE_AMOUNT:
        return None
    new_epoch = s.fence_epoch + 1
    return s._replace(
        available_balance=basis - RESERVE_AMOUNT,
        fence_epoch=new_epoch,
        agent_reserves=_set(s.agent_reserves, a, s.agent_reserves[a] + RESERVE_AMOUNT),
        ledger=_set(s.ledger, a, s.ledger[a] + RESERVE_AMOUNT),
        agent_epochs=_set(s.agent_epochs, a, new_epoch),
        read_balance=_set(s.read_balance, a, 0),
        read_epoch=_set(s.read_epoch, a, 0),
    )


def write_reject(s: State, a: int, cfg: Config) -> State | None:
    if s.read_epoch[a] == 0:
        return None
    cas_ok = (not cfg.fenced) or s.fence_epoch == s.read_epoch[a]
    basis = s.available_balance if cfg.reconciled else s.read_balance[a]
    if cas_ok and s.fence_epoch < MAX_FENCE_EPOCH and basis >= RESERVE_AMOUNT:
        return None
    return s._replace(
        read_balance=_set(s.read_balance, a, 0),
        read_epoch=_set(s.read_epoch, a, 0),
    )


def commit(s: State, a: int, cfg: Config) -> State | None:
    if s.agent_reserves[a] == 0:
        return None
    if cfg.sync_replication and s.rep_ledger[a] != s.agent_reserves[a]:
        return None  # WAIT N has not acknowledged the debit
    return s._replace(
        spent=s.spent + s.agent_reserves[a],
        agent_reserves=_set(s.agent_reserves, a, 0),
        ledger=_set(s.ledger, a, 0),
        rep_ledger=_set(s.rep_ledger, a, 0),
    )


def rollback(s: State, a: int, cfg: Config) -> State | None:
    if s.agent_reserves[a] == 0 or s.read_epoch[a] != 0:
        return None
    if s.fence_epoch >= MAX_FENCE_EPOCH:
        return None
    # LUA_ROLLBACK: a ledgered debit is removed from cbf:debits:total; a
    # debit the primary lacks (lost in a failover) takes the
    # ROLLED_BACK_SETTLED branch and restores the magnitude to the state key.
    # The reconciled barrier nets the total, not the state key.
    restore = s.ledger[a] if cfg.reconciled else s.agent_reserves[a]
    new_epoch = s.fence_epoch + 1
    return s._replace(
        available_balance=s.available_balance + restore,
        fence_epoch=new_epoch,
        agent_reserves=_set(s.agent_reserves, a, 0),
        ledger=_set(s.ledger, a, 0),
        rep_ledger=_set(s.rep_ledger, a, 0),
        agent_epochs=_set(s.agent_epochs, a, new_epoch),
    )


def agent_restart(s: State, a: int, cfg: Config) -> State | None:
    if not cfg.allow_restart:
        return None
    if s.agent_reserves[a] != 0 or s.read_epoch[a] != 0:
        return None
    if s.agent_epochs[a] == s.fence_epoch:
        return None
    return s._replace(agent_epochs=_set(s.agent_epochs, a, s.fence_epoch))


def _replica_current(s: State) -> bool:
    return (
        s.rep_balance == s.available_balance
        and s.rep_epoch == s.fence_epoch
        and s.rep_ledger == s.ledger
    )


def replicate(s: State, cfg: Config) -> State | None:
    if _replica_current(s):
        return None
    return s._replace(rep_balance=s.available_balance, rep_epoch=s.fence_epoch, rep_ledger=s.ledger)


def stale_failover(s: State, cfg: Config) -> State | None:
    if s.stale_failovers >= cfg.max_stale_failovers or _replica_current(s):
        return None
    return s._replace(
        available_balance=s.rep_balance,
        fence_epoch=s.rep_epoch,
        ledger=s.rep_ledger,
        stale_failovers=s.stale_failovers + 1,
    )


_AGENT_ACTIONS = (read, write, write_reject, commit, rollback, agent_restart)
_GLOBAL_ACTIONS = (replicate, stale_failover)


def successors(s: State, cfg: Config) -> list[tuple[str, State]]:
    out: list[tuple[str, State]] = []
    for a in range(cfg.n_agents):
        for act in _AGENT_ACTIONS:
            nxt = act(s, a, cfg)
            if nxt is not None:
                out.append((f"{act.__name__}(a{a})", nxt))
    for act in _GLOBAL_ACTIONS:
        nxt = act(s, cfg)
        if nxt is not None:
            out.append((act.__name__, nxt))
    return out


# ---------------------------------------------------------------------------
# Invariants
# ---------------------------------------------------------------------------


def actuatable(s: State, a: int, cfg: Config) -> int:
    """An admitted debit that can still reach the broker. Under strict
    replication a debit the primary no longer holds can only be rolled back
    (its WAIT failed or will fail)."""
    if cfg.sync_replication and s.ledger[a] != s.agent_reserves[a]:
        return 0
    return s.agent_reserves[a]


def sp1_no_double_spend(s: State, cfg: Config) -> bool:
    return s.spent + sum(actuatable(s, a, cfg) for a in range(cfg.n_agents)) <= INITIAL_POOL


def sp2_no_overcommit(s: State, cfg: Config) -> bool:
    """Admissible balance never exceeds what the pool can still fund."""
    committed = s.spent + sum(actuatable(s, a, cfg) for a in range(cfg.n_agents))
    return s.available_balance + committed <= INITIAL_POOL


def sp4_epoch_monotonic(before: State, after: State) -> bool:
    return after.fence_epoch >= before.fence_epoch or after.stale_failovers > before.stale_failovers


@dataclass(frozen=True)
class Result:
    states: int
    sp1_holds: bool
    sp2_holds: bool
    sp4_holds: bool
    counterexample: tuple[str, ...]  # shortest trace to an SP-1 violation


def check(cfg: Config) -> Result:
    """BFS: distinct states, invariant verdicts, shortest SP-1 counterexample."""
    start = initial_state(cfg)
    parent: dict[State, tuple[State, str] | None] = {start: None}
    queue: deque[State] = deque([start])
    first_violation: State | None = None
    sp2_ok = True
    sp4_ok = True
    while queue:
        s = queue.popleft()
        if first_violation is None and not sp1_no_double_spend(s, cfg):
            first_violation = s
        if not sp2_no_overcommit(s, cfg):
            sp2_ok = False
        for label, nxt in successors(s, cfg):
            if not sp4_epoch_monotonic(s, nxt):
                sp4_ok = False
            if nxt not in parent:
                parent[nxt] = (s, label)
                queue.append(nxt)
    trace: list[str] = []
    cur = first_violation
    while cur is not None and parent[cur] is not None:
        prev, label = parent[cur]  # type: ignore[misc]
        trace.append(label)
        cur = prev
    return Result(len(parent), first_violation is None, sp2_ok, sp4_ok, tuple(reversed(trace)))


# ---------------------------------------------------------------------------
# Claims (pinned by tests/test_distributed_cbf_proof.py)
# ---------------------------------------------------------------------------

#: Named configurations; each has a matching ``proof/<name>.cfg`` (N = 2).
CONFIGS: dict[str, Config] = {
    # Shipped staging/prod posture: CAGE_CBF_STRICT_MODE (reconciled) and
    # CAGE_STRICT_REPLICATION with CAGE_REDIS_WAIT_REPLICAS=1.
    "DistributedCBF": Config(2),
    # Negative control: no WAIT N. Neither the fence epoch nor the
    # in-process _last_seen_epoch prevents the double spend.
    "DistributedCBF_nosync": Config(2, sync_replication=False),
    # Residual: self-reported scalar (non-strict, dev only; dev runs no
    # replica). Fence-epoch ABA across a stale failover.
    "DistributedCBF_selfreported": Config(2, reconciled=False),
    # In reconciled mode SP-1 does not depend on the fence-epoch CAS: the
    # script evaluates the barrier on the live netted balance.
    "DistributedCBF_unfenced": Config(2, fenced=False),
}

#: (config name, N) -> (distinct states, SP-1 holds, SP-2 holds). TLC on the
#: matching cfg (N = 2, ``-continue``) reports the same count and verdicts.
EXPECTED_STATE_COUNTS: dict[tuple[str, int], tuple[int, bool, bool]] = {
    ("DistributedCBF", 1): (107, True, True),
    ("DistributedCBF", 2): (1945, True, True),
    ("DistributedCBF", 3): (27809, True, True),
    ("DistributedCBF_nosync", 1): (244, False, False),
    ("DistributedCBF_nosync", 2): (4232, False, False),
    ("DistributedCBF_nosync", 3): (56435, False, False),
    ("DistributedCBF_selfreported", 1): (98, True, False),
    ("DistributedCBF_selfreported", 2): (1933, False, False),
    ("DistributedCBF_selfreported", 3): (28924, False, False),
    ("DistributedCBF_unfenced", 1): (110, True, True),
    ("DistributedCBF_unfenced", 2): (2536, True, True),
    ("DistributedCBF_unfenced", 3): (51302, True, True),
}


def config_for(name: str, n: int) -> Config:
    base = CONFIGS[name]
    return Config(
        n,
        sync_replication=base.sync_replication,
        reconciled=base.reconciled,
        fenced=base.fenced,
        allow_restart=base.allow_restart,
        max_stale_failovers=base.max_stale_failovers,
    )


def main() -> int:
    ok = True
    for name in CONFIGS:
        for n in (1, 2, 3):
            r = check(config_for(name, n))
            exp = EXPECTED_STATE_COUNTS.get((name, n))
            got = (r.states, r.sp1_holds, r.sp2_holds)
            mark = "" if exp == got else "  <-- MISMATCH"
            ok &= mark == "" and r.sp4_holds
            print(
                f"[{name} N={n}] states={r.states} "
                f"SP-1={'holds' if r.sp1_holds else 'VIOLATED'} "
                f"SP-2={'holds' if r.sp2_holds else 'VIOLATED'} SP-4={r.sp4_holds}{mark}"
            )
            if r.counterexample:
                print("    shortest counterexample:", " -> ".join(r.counterexample))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
