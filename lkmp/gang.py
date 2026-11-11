"""Distributed Two-Phase Commit (2PC) Gang Migration Coordinator for coupled workloads."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from lkmp.agent import AgentClient, config_to_dict
from lkmp.config import MigrationConfig
from lkmp.journal import (
    DEFAULT_JOURNAL_DIR,
    MigrationJournal,
    open_migration_journal,
    validate_safe_identifier,
)
from lkmp.models import MigrationResult, MigrationState
from lkmp.orchestrator import MigrationOrchestrator


@dataclass
class GangMigrationResult:
    """Outcome of a coordinated gang migration across multiple coupled processes."""

    gang_id: str
    all_committed: bool
    atomic_rollback_triggered: bool
    member_results: List[MigrationResult] = field(default_factory=list)
    partial_commit_error: bool = False
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        members_list = []
        for mr in self.member_results:
            d = {
                "migration_id": mr.migration_id,
                "success": mr.success,
                "final_state": mr.final_state.value if hasattr(mr.final_state, "value") else str(mr.final_state),
                "restored_pid": mr.restored_pid,
                "freeze_downtime_ms": mr.freeze_downtime_ms,
                "total_duration_ms": mr.total_duration_ms,
                "rolled_back": mr.rolled_back,
                "error_message": mr.error_message,
                "state_history": [
                    s.value if hasattr(s, "value") else str(s) for s in mr.state_history
                ],
            }
            members_list.append(d)
        return {
            "gang_id": self.gang_id,
            "all_committed": self.all_committed,
            "atomic_rollback_triggered": self.atomic_rollback_triggered,
            "partial_commit_error": self.partial_commit_error,
            "error_message": self.error_message,
            "total_duration_ms": round(sum(m.total_duration_ms for m in self.member_results), 2),
            "member_results": members_list,
        }


class GangMigrationCoordinator:
    """
    Coordinates atomic migration of a coupled group of processes (e.g., MPI ranks or
    co-located microservices) using a true Two-Phase Commit (2PC) protocol:
    - Phase 1 (Prepare & Verify): Every member executes `execute_prepare_phase(keep_stopped_on_prepare=True)`
      keeping the restored process stopped and network-fenced on Destination B while keeping its frozen
      source process on Host A alive (`--leave-stopped`). NO source process is killed during Phase 1.
    - Phase 2 (Global Decision):
      * If ALL members reached `VERIFY` and passed stopped verification, fsyncs `COMMITTED` to `GangJournal`,
        fences/kills all processes on Source A first, then switches over and resumes on Destination B.
      * If ANY member failed in Phase 1, fsyncs `ABORTING` to `GangJournal` and rolls back all prepared members
        so every member's original process on Host A resumes via `SIGCONT` with zero data loss.
    """

    def __init__(
        self,
        gang_id: str,
        members: List[Tuple[MigrationConfig, AgentClient, AgentClient]],
        journal_dir: Optional[str | Path] = None,
        require_persistent_journal: bool = True,
    ) -> None:
        self.gang_id = validate_safe_identifier(gang_id, "gang_id")
        j_dir = (
            journal_dir
            or (members[0][0].journal_dir if members else None)
            or DEFAULT_JOURNAL_DIR
        )
        self.member_ids = [f"{self.gang_id}-m{idx}" for idx in range(1, len(members) + 1)]
        self.journal = open_migration_journal(
            j_dir,
            f"{self.gang_id}.gang",
            extra_ids=self.member_ids,
            member_ids=self.member_ids,
            require_persistent=require_persistent_journal,
        )

        self.orchestrators: List[MigrationOrchestrator] = [
            MigrationOrchestrator(
                config=cfg,
                source_client=src,
                dest_client=dst,
                migration_id=f"{self.gang_id}-m{idx}",
                journal_dir=self.journal.journal_dir,
                gang_id=self.gang_id,
                require_persistent_journal=require_persistent_journal,
            )
            for idx, (cfg, src, dst) in enumerate(members, start=1)
        ]

    def execute(self) -> GangMigrationResult:
        """Alias for `execute_atomic()`."""
        return self.execute_atomic()

    def execute_atomic(self) -> GangMigrationResult:
        """
        Execute 2PC gang migration across all members.
        """
        member_configs = [config_to_dict(o.config) for o in self.orchestrators]

        # 0. Durable Gang & Member WAL Initialization Barrier (before any host RPC):
        #    Write GangJournal INIT first (so any member WAL created next can always consult
        #    GangJournal), initialize every member WAL on disk, then record PREFLIGHT on
        #    GangJournal so any missing member WAL from PREFLIGHT onwards is provably file loss.
        self.journal.append(
            state=MigrationState.INIT,
            commit_decision="PREPARING",
            note="Initializing member WALs",
            member_ids=self.member_ids,
            member_configs=member_configs,
        )
        for orch in self.orchestrators:
            orch._transition(MigrationState.INIT, commit_decision="PREPARING")
        self.journal.append(
            state=MigrationState.PREFLIGHT,
            commit_decision="PREPARING",
            note="All member WALs initialized; starting preflight barrier",
            member_ids=self.member_ids,
            member_configs=member_configs,
        )

        # 1. Global Preflight Barrier: all members must pass preflight before any member freezes
        for orch in self.orchestrators:
            report = orch.run_preflight()
            if not report.compatible:
                self.journal.append(
                    state=MigrationState.ABORTED,
                    commit_decision="ABORTING",
                    note="Preflight failed",
                    member_ids=self.member_ids,
                    member_configs=member_configs,
                )
                results: List[MigrationResult] = []
                for o in self.orchestrators:
                    o._transition(MigrationState.ABORTED, commit_decision="ABORTING")
                    results.append(
                        MigrationResult(
                            migration_id=o.migration_id,
                            success=False,
                            final_state=MigrationState.ABORTED,
                            error_message=f"Gang preflight barrier aborted by {orch.migration_id}",
                            state_history=list(o.state_history),
                        )
                    )
                return GangMigrationResult(
                    gang_id=self.gang_id,
                    all_committed=False,
                    atomic_rollback_triggered=False,
                    member_results=results,
                )

        # Reset state history before Phase 1 prepare execution
        for orch in self.orchestrators:
            orch.state = MigrationState.INIT
            orch.state_history = [MigrationState.INIT]

        self.journal.append(
            state=MigrationState.PREPARE,
            commit_decision="PREPARING",
            member_ids=self.member_ids,
            member_configs=member_configs,
        )

        # 2. Phase 1 (Prepare & Verify): stops at VERIFY with keep_stopped_on_prepare=True
        # Process on B stays stopped and network-fenced; source process on A is alive and frozen
        prepared_orchestrators: List[MigrationOrchestrator] = []
        failed_result: MigrationResult | None = None

        for orch in self.orchestrators:
            res = orch.execute_prepare_phase(keep_stopped_on_prepare=True)
            if not res.success or res.final_state != MigrationState.VERIFY:
                failed_result = res
                break
            prepared_orchestrators.append(orch)

        # 3. Phase 2a (Global Abort / Rollback): If any member failed Phase 1, roll back all prepared members
        if failed_result is not None:
            self.journal.append(state=MigrationState.ABORTED, commit_decision="ABORTING", note="Phase 1 prepare failure")
            rolled_back_results: List[MigrationResult] = []
            for orch in prepared_orchestrators:
                rb_res = orch.rollback("Rolled back by 2PC Gang Coordinator due to peer failure")
                rolled_back_results.append(rb_res)
            rolled_back_results.append(failed_result)

            all_rolled_back = bool(rolled_back_results) and all(
                r.rolled_back for r in rolled_back_results
            )
            if all_rolled_back:
                self.journal.append(state=MigrationState.ROLLBACK, commit_decision="ROLLED_BACK")
                err_msg = None
            else:
                failed_rb_ids = [
                    r.migration_id for r in rolled_back_results if not r.rolled_back
                ]
                err_msg = (
                    f"Incomplete gang rollback: members {failed_rb_ids} did not confirm rolled_back=True"
                )
                self.journal.append(
                    state=MigrationState.ROLLBACK,
                    commit_decision="ABORTING",
                    note=err_msg,
                )
            return GangMigrationResult(
                gang_id=self.gang_id,
                all_committed=False,
                atomic_rollback_triggered=all_rolled_back,
                member_results=rolled_back_results,
                error_message=err_msg,
            )

        # 4. Phase 2b (Global Commit): All members prepared and verified stopped on B
        # Step 1: Write and fsync COMMITTED to GangJournal and each member's WAL
        self.journal.append(state=MigrationState.COMMIT, commit_decision="COMMITTED")
        for orch in prepared_orchestrators:
            orch._transition(MigrationState.COMMIT, commit_decision="COMMITTED")

        try:
            # Step 2: Fence/Kill Source A first so no source process can ever run concurrently with B
            for orch in prepared_orchestrators:
                orch.source.call(
                    "commit_source",
                    migration_id=orch.migration_id,
                    config_dict=config_to_dict(orch.config),
                )

            # Step 3: Resume and verify on Destination B, then finalize commit
            committed_results: List[MigrationResult] = []
            for orch in prepared_orchestrators:
                orch.complete_switchover_and_verify()
                committed_results.append(orch.commit())

            return GangMigrationResult(
                gang_id=self.gang_id,
                all_committed=True,
                atomic_rollback_triggered=False,
                member_results=committed_results,
            )
        except Exception as exc:
            # Step 4: Honest Mid-Commit Failure: do NOT claim atomic_rollback_triggered=True!
            return GangMigrationResult(
                gang_id=self.gang_id,
                all_committed=False,
                atomic_rollback_triggered=False,
                partial_commit_error=True,
                error_message=f"Mid-commit failure after irrevocable decision: {exc}",
            )

    @classmethod
    def recover_from_journal(
        cls,
        gang_journal_path: str | Path,
        members: List[Tuple[MigrationConfig, AgentClient, AgentClient]],
    ) -> GangMigrationResult:
        """
        Recover an interrupted gang migration from its fsynced GangJournal.
        If COMMITTED was recorded, roll forward all members to Destination B.
        If not committed, roll back all members to Source A.
        """
        path = Path(gang_journal_path)
        journal = MigrationJournal.load(path)
        gang_id = journal.migration_id
        if gang_id.endswith(".gang"):
            gang_id = gang_id[:-5]

        expected_member_ids = journal.expected_member_ids
        if not expected_member_ids:
            raise ValueError(
                f"Gang journal {path} is missing authoritative member_ids manifest; "
                "refusing partial gang recovery"
            )
        if len(members) != len(expected_member_ids):
            raise ValueError(
                f"Gang recovery member count mismatch for {gang_id!r}: gang WAL requires "
                f"{len(expected_member_ids)} members ({expected_member_ids}), got {len(members)}"
            )

        only_unstarted_init = (
            len(journal.entries) == 1
            and journal.entries[0].state == MigrationState.INIT.value
            and journal.entries[0].commit_decision == "PREPARING"
        )
        loaded_member_journals: Dict[str, Optional[MigrationJournal]] = {}
        seen_uncreated_init_member = False
        for mid in expected_member_ids:
            mem_wal_path = path.parent / f"{mid}.wal.jsonl"
            if not mem_wal_path.exists():
                if only_unstarted_init:
                    seen_uncreated_init_member = True
                    loaded_member_journals[mid] = None
                    continue
                raise FileNotFoundError(
                    f"Cannot recover gang {gang_id!r}: required member WAL is missing at "
                    f"{mem_wal_path} (expected full gang {expected_member_ids})"
                )
            if seen_uncreated_init_member:
                raise FileNotFoundError(
                    f"Cannot recover gang {gang_id!r}: non-contiguous member WAL missing before "
                    f"{mem_wal_path} (expected full gang {expected_member_ids})"
                )
            loaded_member_journals[mid] = MigrationJournal.load(mem_wal_path)

        committed_decision = journal.has_committed_decision
        results: List[MigrationResult] = []
        coordinator = cls(gang_id=gang_id, members=members, journal_dir=path.parent)
        if [o.migration_id for o in coordinator.orchestrators] != expected_member_ids:
            raise ValueError(
                f"Gang recovery member identifier mismatch for {gang_id!r}: "
                f"expected {expected_member_ids}"
            )

        if committed_decision:
            for orch in coordinator.orchestrators:
                mem_journal = loaded_member_journals[orch.migration_id]
                assert mem_journal is not None
                for entry in reversed(mem_journal.entries):
                    if entry.restored_pid is not None:
                        orch._restored_pid = entry.restored_pid
                        orch._restored_starttime = entry.restored_starttime
                        break

                try:
                    verify_kwargs: Dict[str, object] = {
                        "restored_pid": orch._restored_pid,
                        "health_check_cmd": None,
                        "migration_id": orch.migration_id,
                    }
                    if orch._restored_starttime is not None:
                        verify_kwargs["expected_restored_starttime"] = orch._restored_starttime
                    try:
                        pre_verify = orch.dest.call("verify_process", **verify_kwargs)
                    except TypeError:
                        verify_kwargs.pop("expected_restored_starttime", None)
                        pre_verify = orch.dest.call("verify_process", **verify_kwargs)

                    if not pre_verify.get("healthy"):
                        raise RuntimeError(
                            "Refusing roll-forward commit_source: "
                            f"{pre_verify.get('reason')}"
                        )
                    orch.source.call(
                        "commit_source",
                        migration_id=orch.migration_id,
                        config_dict=config_to_dict(orch.config),
                    )
                    already_switched_over = any(
                        e.state == MigrationState.SWITCHOVER.value and e.commit_decision == "COMMITTED"
                        for e in mem_journal.entries
                    )
                    if not already_switched_over:
                        orch.complete_switchover_and_verify()
                    res = orch.commit()
                    results.append(res)
                except Exception as exc:
                    results.append(
                        MigrationResult(
                            migration_id=orch.migration_id,
                            success=False,
                            final_state=MigrationState.ABORTED,
                            error_message=f"Roll-forward recovery failed: {exc}",
                        )
                    )
            all_ok = bool(results) and all(r.success for r in results)
            err_summary = (
                "; ".join(r.error_message for r in results if not r.success and r.error_message)
                if not all_ok
                else None
            )
            return GangMigrationResult(
                gang_id=gang_id,
                all_committed=all_ok,
                atomic_rollback_triggered=False,
                member_results=results,
                partial_commit_error=not all_ok,
                error_message=err_summary,
            )
        else:
            for orch in coordinator.orchestrators:
                mem_journal = loaded_member_journals[orch.migration_id]
                if mem_journal is not None and not mem_journal.has_rolled_back_decision:
                    for entry in reversed(mem_journal.entries):
                        if entry.restored_pid is not None:
                            orch._restored_pid = entry.restored_pid
                            orch._restored_starttime = entry.restored_starttime
                            break
                res = orch.rollback("Gang recovery: aborting uncommitted gang migration")
                results.append(res)
            all_rolled_back = bool(results) and all(r.rolled_back for r in results)
            if all_rolled_back:
                coordinator.journal.append(
                    state=MigrationState.ROLLBACK,
                    commit_decision="ROLLED_BACK",
                )
                err_msg = None
            else:
                failed_rb_ids = [r.migration_id for r in results if not r.rolled_back]
                err_msg = (
                    f"Incomplete gang recovery rollback: members {failed_rb_ids} did not confirm rolled_back=True"
                )
                coordinator.journal.append(
                    state=MigrationState.ROLLBACK,
                    commit_decision="ABORTING",
                    note=err_msg,
                )
            return GangMigrationResult(
                gang_id=gang_id,
                all_committed=False,
                atomic_rollback_triggered=all_rolled_back,
                member_results=results,
                error_message=err_msg,
            )
