# LKMP v2.0 (`branch: v2.0`) — Multi-Process Set Live Migration Handoff & Architecture Plan

## 0. Deeper Prompt Rewrite (`METODA`: Deeper, Not Bigger)

### (1) What a top systems/kernel engineer would do here that wasn't explicitly asked for
A naive implementation of "moving a couple pointed processes at once (`--pids p1,p2,p3`)" simply loops over `MigrationOrchestrator(pid)` or `GangMigrationCoordinator`. On a real Linux kernel with CRIU, that fails or corrupts state for three fundamental reasons:
1. **Overlapping Subtrees (Forest Redundancy)**: If `p2` is already a child/descendant of `p1`, dumping both `p1` and `p2` checkpoints `p2` twice and fails on restore with `EEXIST` (`Can't fork for <pid>: File exists`). We must first compute the **Minimal Disjoint Process Forest** $F = \{R_1, \dots, R_m\}$ by walking `/proc/<pid>/task/*/children` and `/proc/*/stat` (`ppid`, `pgid`, `sid`, `starttime`) and absorbing any descendant $p_j \in T(p_i)$ into its ancestor root $R_i$.
2. **Set-Closure of Kernel Resources (`INTRA_TREE` vs. `INTER_TREE_CLOSED` vs. `EXTERNAL_UNCLOSED_PEER`)**: When two pointed sibling trees $T(R_1)$ and $T(R_2)$ communicate over an unnamed pipe (`pipe:[ino]`), UNIX domain socket (`socket:[ino]`), or `/dev/shm` segment, single-process preflight falsely classifies that pipe as an *external leaked pipe*. Evaluated across the union $\bigcup_{i} T(R_i)$, both endpoints lie inside the migration set (`INTER_TREE_CLOSED`). Conversely, if $T(R_1)$ holds a pipe whose other endpoint is in an unmigrated host process $q \notin \bigcup T(R_i)$, the analyzer must flag $q$ (`EXTERNAL_UNCLOSED_PEER`) and support automatic dependency closure (`--auto-include-coupled`).
3. **Simultaneous Atomic Co-Freeze Barrier (Consistent Cut)**: Freezing and dumping $R_1$ while $R_2$ is still running allows $R_2$ to mutate shared files or send IPC messages after $R_1$'s checkpoint, violating Chandy-Lamport / Podman cut consistency. All disjoint roots $R_1, \dots, R_m$ must pass through a **Lockstep Co-Freeze Barrier** (simultaneous `SIGSTOP` / `cgroup.freeze` with `starttime` PID-reuse verification across $\bigcup T(R_i)$) **before** the first final `criu dump` or frozen volume snapshot begins.

### (2) Rawest material to start from
- Raw Linux `/proc` kernel tables: `/proc/<pid>/stat` (fields `pid`, `ppid`, `pgrp`, `session`, and field 22 `starttime`), `/proc/<pid>/task/*/children`, `/proc/<pid>/fd/*` symlink targets (`pipe:[ino]`, `socket:[ino]`), `/proc/net/unix`, `/proc/net/tcp`, and `/proc/<pid>/ns/*`.
- Real CRIU 4.2.1 (`GitID: f192861`) mechanics on Linux `7.0.0-42-generic` (`ai-father`): `pstree.img` process-tree hierarchies, `--leave-stopped` ptrace seizure lifecycles, and PID namespace isolation (`unshare --mount --pid --fork --mount-proc`).

### (3) Specific methods and tools
- **Graph / Forest Reduction (`ProcessSetAnalyzer` in `lkmp/process_set.py`)**: DFS subtree expansion + set-closure classification over `/proc/[0-9]*/fd` inode bipartite graphs.
- **7-Stage Lockstep Barrier Pipeline (`SetMigrationOrchestrator`)**:
  `PREFLIGHT_AND_CLOSURE` -> `ONLINE_PRE_COPY` -> `CO_FREEZE_BARRIER` -> `FINAL_DUMP_AND_SNAPSHOT` -> `TRANSFER_AND_SET_MERKLE_ATTEST` -> `RESTORE_STOPPED_BARRIER` -> `IRREVOCABLE_SET_COMMIT_OR_ROLLBACK` backed by `.set.wal.jsonl` (`os.fsync`).
- **Remote Hardware Verification (`ai-father`)**: Real CRIU 4.2.1 multi-tree dump & detached restore on Ubuntu 24.04 / Linux 7.0 via SSH.

### (4) Objective external oracle proving correctness
1. **`sudo criu dump` & `sudo criu restore` (CRIU 4.2.1 on `ai-father`, Linux `7.0.0-42-generic`)** checkpointing and restoring a pointed multi-process forest (`Scenario D` in `scripts/linux_criu_e2e.py`) with `0` exit codes and verified post-restore `state.log` progression across all trees.
2. **13-Scenario Stateful Acceptance Matrix (`./bin/lkmp acceptance`)** proving `co_freeze_barrier_achieved == True`, contiguous sequence numbers, `0` lost/duplicated writes, and `max_concurrent_writers == 1`.

### Rewritten Prompt (Self-Directed Mandate for Worker Threads)
> *"On branch `v2.0` of `/Users/pawel/_DEV/LK_MP`, design and implement **LKMP v2.0 Multi-Process Set Live Migration (`2.0.0`)**. Build `lkmp/process_set.py` (`ProcessSetAnalyzer` + `SetMigrationOrchestrator`), extend `lkmp/models.py`, `lkmp/config.py`, `lkmp/agent.py`, `lkmp/telemetry.py`, and `lkmp/cli.py` (`lkmp migrate --pids ...`, `lkmp migrate-set`, `lkmp portability --pids ...`, `lkmp recover --set-journal ...`) to: (1) reduce arbitrary pointed PID lists into a minimal disjoint process forest (absorbing descendant PIDs so no process is dumped twice); (2) build the `/proc/<pid>/fd` kernel coupling graph classifying pipes/sockets into `INTRA_TREE`, `INTER_TREE_CLOSED`, and `EXTERNAL_UNCLOSED_PEER` with `--auto-include-coupled` closure expansion; (3) enforce a Simultaneous Lockstep Co-Freeze Barrier across all disjoint trees before final CRIU dump and frozen volume snapshot; (4) hold all restored trees in `--leave-stopped` state on Destination B until a single fsynced `COMMITTED` record in `.set.wal.jsonl`, killing all Source A trees before resuming Destination B trees. Verify via TDD unit tests (`tests/test_v2_process_set.py`), Scenario 13 in `lkmp acceptance`, and Scenario D in `scripts/linux_criu_e2e.py` on remote Linux 7.0 host `ai-father` with real CRIU 4.2.1."*

---

## 1–2. Analysis of Materials & Current Repository State
- **Repository**: `git@github.com:xsub/LKMP.git`
- **Branches**:
  - `main` (`525ecda`): LKMP v1.x (single-process `MigrationOrchestrator`, sequential `GangMigrationCoordinator`, 4-state `PortabilityReport`, mandatory `.wal.jsonl`, Podman-style frozen snapshot, Same-Host CoW fast path, 78 unit tests, 12 acceptance scenarios, 4/4 real CRIU 4.2.1 scenarios on `ai-father`).
  - `v2.0` (active development branch): Dedicated branch for **LKMP v2.0 Multi-Process Set Live Migration**.
- **Gap Identified in v1.x `GangMigrationCoordinator` (`lkmp/gang.py`)**:
  - `GangMigrationCoordinator` executes `orch.execute_prepare_phase()` sequentially one member at a time (Member 1 freezes, dumps, transfers, and restores while Member 2 is still running unfrozen on Host A), does not normalize overlapping parent/child PIDs, and does not analyze cross-process `/proc/<pid>/fd` pipe/socket closure.

---

## 3. LKMP v2.0 MVP Scope
1. **Forest Reduction (`ProcessSetAnalyzer.normalize_process_forest`)**: Deduplicates pointed PIDs into disjoint root trees (`root_pids`, `absorbed_pids`, `all_pids`, `shared_anchor_pid`).
2. **Coupling Closure Graph (`ProcessSetAnalyzer.analyze_coupling_closure` & `expand_coupled_closure`)**: Classifies shared pipes/sockets/files into `INTRA_TREE`, `INTER_TREE_CLOSED`, and `EXTERNAL_UNCLOSED_PEER`, plus `--auto-include-coupled`.
3. **Lockstep `SetMigrationOrchestrator` (`lkmp/process_set.py`)**:
   - Simultaneous `freeze_process_set` Co-Freeze Barrier on `lkmp-agent` with `starttime` PID-reuse protection.
   - Composite `set_merkle_root` attestation across all disjoint root checkpoints.
   - Stopped-Readiness Barrier + `.set.wal.jsonl` crash recovery (`recover_from_journal`).
4. **CLI v2.0 (`lkmp migrate-set`, `--pids`, `--auto-include-coupled`, `--set-journal`)** + ASCII telemetry tables.
5. **Verification**: `tests/test_v2_process_set.py`, Scenario 13 in `lkmp acceptance`, and Scenario D in `scripts/linux_criu_e2e.py` executed on `ai-father` (CRIU 4.2.1).

---

## 4. Nice-to-Haves Marked as `TODO` (v2.1 Backlog)
- `TODO(v2.1-nice-to-have)`: Automatic CRIU `--inherit-fd` proxy pipe splicing for `INTER_TREE_CLOSED` unnamed pipes when sibling roots do not share a common non-init anchor process.
- `TODO(v2.1-nice-to-have)`: eBPF `sockmap` / `sk_msg` cross-host UNIX domain socket bridge when only a subset of coupled local services is migrated.
- `TODO(v2.1-nice-to-have)`: Shared SysV IPC (`ipcs` / `shmget`) namespace extraction across disjoint root processes in different IPC namespaces.
- `TODO(v2.1-nice-to-have)`: Parallel multi-stream `criu page-server` multiplexing on a single mTLS port for >10 disjoint process trees.

---

## 5. Active Worker Thread Tree & Model Optimization Schedule

To keep the main thread clean and optimize cost/latency:
- **Worker Thread 1 (`5567f404-e7e1-4fd5-8e52-4d7f5cb1181b`, Model: `flash`)**:
  - Role: `Process Set Topology and Orchestrator Builder`
  - Scope: `lkmp/__init__.py` (`2.0.0`), `lkmp/models.py`, `lkmp/process_set.py`.
- **Worker Thread 2 (`906c6a61-40ad-41e4-ad7d-68856765920d`, Model: `flash`)**:
  - Role: `Agent Set Freeze and CLI v2 Builder`
  - Scope: `lkmp/config.py`, `lkmp/agent.py`, `lkmp/telemetry.py`, `lkmp/cli.py`.
- **Worker Thread 3 (`c04932ea-282e-4aa6-a821-81e5adb2d76f`, Model: `flash`)**:
  - Role: `Multi-Process Set Acceptance and TDD Suite Builder`
  - Scope: `tests/test_v2_process_set.py`, `lkmp/acceptance.py` (Scenario 13), `tests/test_acceptance_suite.py`, `scripts/linux_criu_e2e.py` (Scenario D).
  - Status: **COMPLETED** (11/11 in `tests/test_v2_process_set.py`, 16/16 in `tests/test_acceptance_suite.py`, 13/13 acceptance matrix scenarios passing, Scenario D added to `scripts/linux_criu_e2e.py`).
- **Skill Created**: `.agents/skills/lkmp-v2-multi-process-migration/SKILL.md`

---

## 6. Implementation Summary for Worker 3 Deliverables
- **`tests/test_v2_process_set.py`**:
  - 11 comprehensive TDD tests passing in 0.049s.
  - Covers forest normalization, coupling closure analysis (`INTRA_TREE`, `INTER_TREE_CLOSED`, `EXTERNAL_UNCLOSED_PEER`), `--auto-include-coupled` expansion, 7-phase lockstep cutover, stopped-barrier rollback, WAL recovery, RPC handlers, CLI parsing, and telemetry.
- **`lkmp/acceptance.py`**:
  - Added Scenario 13 (`13. Pointed Multi-Process Set Lockstep Cutover (v2.0 --pids)`).
  - Harness upgraded with multi-workload support, co-freeze tracking, and longest-prefix socket mapping.
  - Matrix validation: 13/13 scenarios passing.
- **`tests/test_acceptance_suite.py`**:
  - Added `test_scenario_13_pointed_process_set` and updated matrix assertions (16/16 tests passing).
- **`scripts/linux_criu_e2e.py`**:
  - Implemented Scenario D (`run_scenario_d_multi_process_set`) with CRIU 4.2.1 co-freeze & restore testing. All 5 scenarios verified with `--json`.

---

## 7. Worker 4 Deliverables: Remote CRIU v2 Verifier & Branch Publisher

- **Role**: `Remote CRIU v2 Verifier and Branch Publisher`
- **Scope**: Verification on Linux 7.0 + CRIU 4.2.1 (`ai-father`), documentation updates, and git publication.
- **Remote Host Verification Results (`pawel@ai-father`, Linux `7.0.0-42-generic` x86_64, CRIU `4.2.1 GitID: f192861`)**:
  - **Unit + TDD Suite**: `96/96 PASS` in 8.022s (`python3 -m unittest discover -s tests -p 'test_*.py'`).
    - `tests/test_v2_process_set.py`: 11/11 tests passing (forest normalization, coupling closure analysis, auto-include coupled expansion, 7 lockstep phase barriers, stopped-barrier rollback, WAL recovery, agent RPCs, CLI parsing, telemetry).
    - `tests/test_acceptance_suite.py`: 16/16 tests passing.
  - **Acceptance Suite Matrix (`./bin/lkmp acceptance`)**: `13/13 PASS` (`0` failed, 100% TCP preservation, 0 lost/duplicated writes, max concurrent writers = 1, `co_freeze_barrier_achieved == True`).
  - **Real CRIU 4.2.1 E2E Suite (`sudo python3 scripts/linux_criu_e2e.py`)**: `5/5 PASS` (`0` failed, exit code 0).
    - Scenario 1 (CRIU CLI Flags): `PASS`
    - Scenario 2 (Scenario A COLD Dump & Detached Restore): `PASS`
    - Scenario 3 (Scenario B PRE_COPY Page-Server Streaming): `PASS`
    - Scenario 4 (Scenario C LAZY Supervised Popen & Demand-Paging): `PASS`
    - Scenario 5 (Scenario D Multi-Process Set Co-Freeze & Restore): `PASS` (PID 20841 absorbed into root 20840, simultaneous co-freeze barrier across 6 processes in 0.02ms, dual-tree CRIU dump & detached restore, continuous `state.log` record progression).
- **Documentation**:
  - Updated `README.md` to showcase LKMP v2.0 (`2.0.0`) architecture, `ProcessSetAnalyzer`, `SetMigrationOrchestrator`, new CLI commands (`lkmp migrate-set`, `--pids`, `--auto-include-coupled`, `--set-journal`), and verified test metrics.
- **Git Branch Status**:
  - Branch: `v2.0`
  - Committed and pushed to `origin/v2.0`.
