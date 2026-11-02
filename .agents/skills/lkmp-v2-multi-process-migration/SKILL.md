---
name: lkmp-v2-multi-process-migration
description: >-
  Runbook and engineering workflow for LKMP v2.0 Multi-Process Set Live Migration
  (forest normalization, kernel resource closure, lockstep co-freeze barrier,
  and real CRIU 4.2.1 verification on remote Linux host ai-father).
---

# LKMP v2.0 Multi-Process Set Live Migration Skill

Use this skill whenever developing, debugging, or verifying **LKMP v2.0** multi-process set live migration (`lkmp migrate --pids ...`, `lkmp migrate-set`, `lkmp portability --pids ...`, and `lkmp/process_set.py`).

## 1. Core Kernel & CRIU Invariants for Pointed Process Sets

When a user points to a set of processes $P = \{p_1, p_2, \dots, p_k\}$ to migrate together from Source Host A to Destination Host B:

1. **Minimal Disjoint Process Forest Reduction (`normalize_process_forest`)**:
   - Expand each $p_i \in P$ into its full descendant tree $T(p_i)$ using `/proc/<pid>/task/*/children` and `/proc/*/stat` (`ppid`, `pgid`, `sid`, `starttime`).
   - If $p_j \in T(p_i)$ ($i \neq j$), prune $p_j$ from the root list and record it under $R_i = p_i$. Never dump or restore overlapping subtrees twice.
2. **Kernel Coupling & Closure Graph (`analyze_process_set_closure`)**:
   - Inspect `/proc/<pid>/fd` link targets (`pipe:[ino]`, `socket:[ino]`, `/dev/shm/*`, writable files) across $\bigcup T(R_i)$ and peer processes on Host A:
     - `INTRA_TREE`: Both endpoints reside inside the same root tree $T(R_i)$ -> natively preserved by `criu dump -t R_i`.
     - `INTER_TREE_CLOSED`: Endpoints span $T(R_i)$ and $T(R_j)$ ($i \neq j$) inside the pointed set -> closed within the migration set; requires lockstep co-freeze and coordinated restore.
     - `EXTERNAL_UNCLOSED_PEER`: One endpoint is inside $\bigcup T(R_i)$ and the other is held by an unmigrated host PID $q \notin \bigcup T(R_i)$ -> report `q` (`peer_pid`, `peer_comm`, `resource`) and support `--auto-include-coupled` to close the set automatically.
3. **Lockstep Phase Barriers (`SetMigrationOrchestrator`)**:
   - Never run sequential full migrations member-by-member when migrating a pointed set on the same host.
   - Execute phases in lockstep across all disjoint roots $R_1, \dots, R_m$:
     1. `PREFLIGHT_AND_CLOSURE`
     2. `PRE_COPY` (online iterative pre-dump for all $R_i$)
     3. `CO_FREEZE_BARRIER` (quiesce -> network lock -> simultaneous stop/freeze of all $\bigcup T(R_i)$ with `starttime` verification **before** any final dump starts)
     4. `FINAL_DUMP_AND_SNAPSHOT` (dump all $R_i$ while frozen + single consistent frozen volume/CoW snapshot)
     5. `TRANSFER_AND_ATTEST` (transfer images + composite `set_merkle_root` in `set_manifest.sig.json`)
     6. `RESTORE_STOPPED_BARRIER` (restore all $R_i$ on Destination B with `--leave-stopped` and verify all $R'_i$ stopped while Source A remains frozen)
     7. `COMMIT_OR_ROLLBACK` (single durable `COMMITTED` decision in `.set.wal.jsonl`, kill all Source A trees first, then simultaneously `SIGCONT` all Destination B trees).

## 2. Remote Linux 7.0 + CRIU 4.2.1 Verification Workflow (`ai-father`)

Never run heavy VM or multi-process stress suites on the local macOS machine. Always sync to `ai-father` (`Linux 7.0.0-42-generic x86_64`, CRIU `4.2.1 GitID: f192861`):

```bash
# 1. Sync current branch workspace to ai-father
rsync -az --delete --exclude=.git --exclude=__pycache__ /Users/pawel/_DEV/LK_MP/ ai-father:/tmp/LK_MP/

# 2. Run unit, portability, recovery, and v2.0 process-set tests on ai-father
ssh ai-father "cd /tmp/LK_MP && python3 -m unittest discover -s tests -p 'test_*.py' -v"

# 3. Run acceptance matrix on ai-father
ssh ai-father "cd /tmp/LK_MP && ./bin/lkmp acceptance"

# 4. Run real CRIU 4.2.1 single + multi-process set E2E verification on ai-father
ssh ai-father sudo python3 /tmp/LK_MP/scripts/linux_criu_e2e.py
```

## 3. Handoff Hygiene (`HANDOFF.md`)

Always keep `/Users/pawel/_DEV/LK_MP/HANDOFF.md` updated with:
- Current branch (`v2.0`) and HEAD commit hash,
- Completed v2.0 modules and test status (`unittest`, `lkmp acceptance`, `linux_criu_e2e.py` on `ai-father`),
- Explicit `TODO (Nice-to-Haves)` backlog for future workers/models.
