--------------------------- MODULE DistributedCBF ---------------------------
(* Copyright 2026 Google LLC

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       https://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

   --------------------------------------------------------------------------
   Distributed CBF admission under a lagging Redis replica
   --------------------------------------------------------------------------

   Line-for-line transliteration of proof/distributed_cbf_model.py, which
   documents the correspondence to src/gateway/governance/safety/cbf_engine.py
   action by action. TLC on the DistributedCBF*.cfg files must report the
   distinct-state counts pinned in tests/test_distributed_cbf_proof.py.

   One agent = one gateway process. Redis is one primary that replicates
   asynchronously to one replica; StaleFailover promotes the replica.

   Results (N = 2, see the cfg files):
   - DistributedCBF.cfg              Reconciled, SyncReplication: SP-1 holds.
   - DistributedCBF_nosync.cfg       no WAIT N: SP-1 violated. The fence
     epoch and the in-process _last_seen_epoch do not prevent it: another
     process whose last_seen is at or below the regressed epoch spends the
     restored balance.
   - DistributedCBF_selfreported.cfg self-reported scalar (non-strict, dev
     only): SP-1 violated through a fence-epoch ABA — a read in flight
     across the failover passes the CAS once the epoch climbs back.
*)

EXTENDS Naturals, FiniteSets

CONSTANTS
    AgentIDs,           \* gateway processes
    InitialPool,        \* initial balance
    ReserveAmount,      \* cost of one admitted action
    MaxAgentReserve,    \* in-flight debits per process (state bound)
    MaxFenceEpoch,      \* epoch bound (state bound)
    MaxStaleFailovers,  \* failover bound (state bound)
    SyncReplication,    \* WAIT N + strict rollback before actuation
    Reconciled,         \* script nets the live ledger (strict mode)
    Fenced,             \* fence-epoch CAS and last_seen regression check
    AllowRestart        \* processes may restart and re-seed last_seen

VARIABLES
    available_balance,  \* primary: barrier scalar net of in-flight debits
    fence_epoch,        \* primary: safety:fence_epoch (HWM regresses with it)
    rep_balance,        \* replica copy of available_balance
    rep_epoch,          \* replica copy of fence_epoch
    agent_reserves,     \* per process: admitted, not yet actuated
    ledger,             \* primary: cbf:debits (rollback-able amount)
    rep_ledger,         \* replica copy of ledger
    agent_epochs,       \* per process: _last_seen_epoch (in memory)
    read_balance,       \* per process: scalar read before the script
    read_epoch,         \* per process: epoch read (0 = no read in flight)
    spent,              \* actuated at the broker; never regresses
    stale_failovers

vars == <<available_balance, fence_epoch, rep_balance, rep_epoch,
          agent_reserves, ledger, rep_ledger, agent_epochs,
          read_balance, read_epoch, spent, stale_failovers>>

RECURSIVE SumOver(_, _)
SumOver(f, S) == IF S = {} THEN 0
                 ELSE LET a == CHOOSE x \in S : TRUE
                      IN f[a] + SumOver(f, S \ {a})

Max(x, y) == IF x >= y THEN x ELSE y

-----------------------------------------------------------------------------

Init ==
    /\ available_balance = InitialPool
    /\ fence_epoch = 1
    /\ rep_balance = InitialPool
    /\ rep_epoch = 1
    /\ agent_reserves = [a \in AgentIDs |-> 0]
    /\ ledger = [a \in AgentIDs |-> 0]
    /\ rep_ledger = [a \in AgentIDs |-> 0]
    /\ agent_epochs = [a \in AgentIDs |-> 1]     \* seeded at startup
    /\ read_balance = [a \in AgentIDs |-> 0]
    /\ read_epoch = [a \in AgentIDs |-> 0]
    /\ spent = 0
    /\ stale_failovers = 0

Basis(a) == IF Reconciled THEN available_balance ELSE read_balance[a]

(* _check_fence_epoch + state read. *)
Read(a) ==
    /\ read_epoch[a] = 0
    /\ agent_reserves[a] < MaxAgentReserve
    /\ available_balance >= ReserveAmount
    /\ ~(Fenced /\ agent_epochs[a] > fence_epoch)
    /\ agent_epochs' = [agent_epochs EXCEPT ![a] = Max(@, fence_epoch)]
    /\ read_balance' = [read_balance EXCEPT ![a] = available_balance]
    /\ read_epoch' = [read_epoch EXCEPT ![a] = fence_epoch]
    /\ UNCHANGED <<available_balance, fence_epoch, rep_balance, rep_epoch,
                   agent_reserves, ledger, rep_ledger, spent, stale_failovers>>

(* LUA_ATOMIC_CBF success: CAS, barrier, SET, INCR, ledger the debit. *)
Write(a) ==
    /\ read_epoch[a] # 0
    /\ fence_epoch < MaxFenceEpoch
    /\ ~(Fenced /\ fence_epoch # read_epoch[a])
    /\ Basis(a) >= ReserveAmount
    /\ available_balance' = Basis(a) - ReserveAmount
    /\ fence_epoch' = fence_epoch + 1
    /\ agent_reserves' = [agent_reserves EXCEPT ![a] = @ + ReserveAmount]
    /\ ledger' = [ledger EXCEPT ![a] = @ + ReserveAmount]
    /\ agent_epochs' = [agent_epochs EXCEPT ![a] = fence_epoch + 1]
    /\ read_balance' = [read_balance EXCEPT ![a] = 0]
    /\ read_epoch' = [read_epoch EXCEPT ![a] = 0]
    /\ UNCHANGED <<rep_balance, rep_epoch, rep_ledger, spent, stale_failovers>>

(* LUA_ATOMIC_CBF refusal (CAS mismatch, barrier, or epoch bound). *)
WriteReject(a) ==
    /\ read_epoch[a] # 0
    /\ ~( /\ (~Fenced \/ fence_epoch = read_epoch[a])
          /\ fence_epoch < MaxFenceEpoch
          /\ Basis(a) >= ReserveAmount )
    /\ read_balance' = [read_balance EXCEPT ![a] = 0]
    /\ read_epoch' = [read_epoch EXCEPT ![a] = 0]
    /\ UNCHANGED <<available_balance, fence_epoch, rep_balance, rep_epoch,
                   agent_reserves, ledger, rep_ledger, agent_epochs,
                   spent, stale_failovers>>

(* Actuation: not re-fenced; under SyncReplication only after WAIT N. *)
Commit(a) ==
    /\ agent_reserves[a] > 0
    /\ ~(SyncReplication /\ rep_ledger[a] # agent_reserves[a])
    /\ spent' = spent + agent_reserves[a]
    /\ agent_reserves' = [agent_reserves EXCEPT ![a] = 0]
    /\ ledger' = [ledger EXCEPT ![a] = 0]
    /\ rep_ledger' = [rep_ledger EXCEPT ![a] = 0]
    /\ UNCHANGED <<available_balance, fence_epoch, rep_balance, rep_epoch,
                   agent_epochs, read_balance, read_epoch, stale_failovers>>

(* LUA_ROLLBACK by debit_id. Reconciled: removes the ledger entry if the
   primary holds it. A missing entry takes ROLLED_BACK_SETTLED and restores
   the magnitude to the state key, which only the self-reported barrier
   reads. *)
Rollback(a) ==
    /\ agent_reserves[a] > 0
    /\ read_epoch[a] = 0
    /\ fence_epoch < MaxFenceEpoch
    /\ available_balance' = available_balance
                            + (IF Reconciled THEN ledger[a] ELSE agent_reserves[a])
    /\ fence_epoch' = fence_epoch + 1
    /\ agent_reserves' = [agent_reserves EXCEPT ![a] = 0]
    /\ ledger' = [ledger EXCEPT ![a] = 0]
    /\ rep_ledger' = [rep_ledger EXCEPT ![a] = 0]
    /\ agent_epochs' = [agent_epochs EXCEPT ![a] = fence_epoch + 1]
    /\ UNCHANGED <<rep_balance, rep_epoch, read_balance, read_epoch,
                   spent, stale_failovers>>

(* Process restart: _last_seen_epoch re-seeded from the primary. *)
AgentRestart(a) ==
    /\ AllowRestart
    /\ agent_reserves[a] = 0
    /\ read_epoch[a] = 0
    /\ agent_epochs[a] # fence_epoch
    /\ agent_epochs' = [agent_epochs EXCEPT ![a] = fence_epoch]
    /\ UNCHANGED <<available_balance, fence_epoch, rep_balance, rep_epoch,
                   agent_reserves, ledger, rep_ledger, read_balance,
                   read_epoch, spent, stale_failovers>>

ReplicaCurrent ==
    /\ rep_balance = available_balance
    /\ rep_epoch = fence_epoch
    /\ rep_ledger = ledger

Replicate ==
    /\ ~ReplicaCurrent
    /\ rep_balance' = available_balance
    /\ rep_epoch' = fence_epoch
    /\ rep_ledger' = ledger
    /\ UNCHANGED <<available_balance, fence_epoch, agent_reserves, ledger,
                   agent_epochs, read_balance, read_epoch, spent,
                   stale_failovers>>

(* Replica promoted: balance, epoch, HWM and ledger regress; last_seen does
   not. Under SyncReplication a debit the replica lacks cannot be actuated
   (Commit waits for it on the replica); the process rolls it back. *)
StaleFailover ==
    /\ stale_failovers < MaxStaleFailovers
    /\ ~ReplicaCurrent
    /\ available_balance' = rep_balance
    /\ fence_epoch' = rep_epoch
    /\ ledger' = rep_ledger
    /\ stale_failovers' = stale_failovers + 1
    /\ UNCHANGED <<rep_balance, rep_epoch, rep_ledger, agent_reserves,
                   agent_epochs, read_balance, read_epoch, spent>>

Next ==
    \/ \E a \in AgentIDs :
          \/ Read(a) \/ Write(a) \/ WriteReject(a)
          \/ Commit(a) \/ Rollback(a) \/ AgentRestart(a)
    \/ Replicate
    \/ StaleFailover

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------

TypeOK ==
    /\ available_balance \in Nat
    /\ rep_balance \in Nat
    /\ spent \in Nat
    /\ fence_epoch \in 1..MaxFenceEpoch
    /\ rep_epoch \in 1..MaxFenceEpoch
    /\ agent_reserves \in [AgentIDs -> 0..MaxAgentReserve]
    /\ agent_epochs \in [AgentIDs -> 1..MaxFenceEpoch]
    /\ read_epoch \in [AgentIDs -> 0..MaxFenceEpoch]
    /\ stale_failovers \in 0..MaxStaleFailovers

(* An admitted debit that can still reach the broker: under SyncReplication
   one the primary no longer holds can only be rolled back. *)
Actuatable == [a \in AgentIDs |->
                 IF SyncReplication /\ ledger[a] # agent_reserves[a]
                 THEN 0 ELSE agent_reserves[a]]

(* SP-1: no double spend. Actuated spend plus actuatable in-flight debits
   never exceed the pool. *)
SP1_NoDoubleSpend == spent + SumOver(Actuatable, AgentIDs) <= InitialPool

(* SP-2: no over-credit. Admissible balance never exceeds what the pool can
   still fund — the leading indicator of a later SP-1 violation. *)
SP2_NoOvercommit ==
    available_balance + spent + SumOver(Actuatable, AgentIDs) <= InitialPool

(* SP-4: the fence epoch decreases only at a stale failover. *)
SP4_FenceEpochMonotonic ==
    [][fence_epoch' >= fence_epoch \/ stale_failovers' > stale_failovers]_vars

=============================================================================
