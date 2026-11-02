"""Distributed Two-Phase Commit (2PC) Gang Migration Coordinator for coupled workloads."""

from __future__ import annotations

import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from lkmp.agent import AgentClient, config_to_dict
from lkmp.config import MigrationConfig
from lkmp.journal import MigrationJournal, validate_safe_identifier
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
    ) -> None:
        self.gang_id = validate_safe_identifier(gang_id, "gang_id")
        j_dir = journal_dir or (members[0][0].journal_dir if members else None) or "/var/lib/lkmp/journals"
        try:
            Path(j_dir).mkdir(parents=True, exist_ok=True)
            self.journal = MigrationJournal(j_dir, f"{self.gang_id}.gang")
        except OSError:
            fallback = Path(tempfile.gettempdir()) / "lkmp-journals"
            fallback.mkdir(parents=True, exist_ok=True)
            self.journal = MigrationJournal(fallback, f"{self.gang_id}.gang")

        self.orchestrators: List[MigrationOrchestrator] = [
            MigrationOrchestrator(
                config=cfg,
                source_client=src,
                dest_client=dst,
                migration_id=f"{self.gang_id}-m{idx}",
                journal_dir=self.journal.journal_dir,
            )
            for idx, (cfg, src, dst) in enumerate(members, start=1)
        ]

    def execute_atomic(self) -> GangMigrationResult:
        """
        Execute 2PC gang migration across all members.
        """
        # 1. Global Preflight Barrier: all members must pass preflight before any member freezes
        for orch in self.orchestrators:
            report = orch.run_preflight()
            if not report.compatible:
                self.journal.append(state=MigrationState.ABORTED, commit_decision="ABORTING", note="Preflight failed")
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

        self.journal.append(state=MigrationState.PREPARE, commit_decision="PREPARING")

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
            self.journal.append(state=MigrationState.ROLLBACK, commit_decision="ROLLED_BACK")
            return GangMigrationResult(
                gang_id=self.gang_id,
                all_committed=False,
                atomic_rollback_triggered=True,
                member_results=rolled_back_results,
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

        committed_decision = journal.has_committed_decision
        results: List[MigrationResult] = []
        coordinator = cls(gang_id=gang_id, members=members, journal_dir=path.parent)

        if committed_decision:
            for orch in coordinator.orchestrators:
                if orch._restored_pid is None and orch.journal and orch.journal.path.exists():
                    try:
                        mem_journal = MigrationJournal.load(orch.journal.path)
                        for entry in reversed(mem_journal.entries):
                            if entry.restored_pid:
                                orch._restored_pid = entry.restored_pid
                                break
                    except Exception:
                        pass

                try:
                    orch.source.call(
                        "commit_source",
                        migration_id=orch.migration_id,
                        config_dict=config_to_dict(orch.config),
                    )
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
            all_ok = all(r.success for r in results)
            return GangMigrationResult(
                gang_id=gang_id,
                all_committed=all_ok,
                atomic_rollback_triggered=False,
                member_results=results,
                partial_commit_error=not all_ok,
            )
        else:
            for orch in coordinator.orchestrators:
                res = orch.rollback("Gang recovery: aborting uncommitted gang migration")
                results.append(res)
            return GangMigrationResult(
                gang_id=gang_id,
                all_committed=False,
                atomic_rollback_triggered=True,
                member_results=results,
            )
