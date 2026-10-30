"""Distributed Two-Phase Commit (2PC) Gang Migration Coordinator for coupled workloads."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

from lkmp.agent import AgentClient, config_to_dict
from lkmp.config import MigrationConfig
from lkmp.models import MigrationResult, MigrationState
from lkmp.orchestrator import MigrationOrchestrator


@dataclass
class GangMigrationResult:
    """Outcome of a coordinated gang migration across multiple coupled processes."""

    gang_id: str
    all_committed: bool
    atomic_rollback_triggered: bool
    member_results: List[MigrationResult] = field(default_factory=list)


class GangMigrationCoordinator:
    """
    Coordinates atomic migration of a coupled group of processes (e.g., MPI ranks or
    co-located microservices) using a Two-Phase Commit (2PC) barrier so either all
    processes commit on Destination B or all roll back to Source A (preventing split-brain).
    """

    def __init__(
        self,
        gang_id: str,
        members: List[Tuple[MigrationConfig, AgentClient, AgentClient]],
    ) -> None:
        self.gang_id = gang_id
        self.orchestrators: List[MigrationOrchestrator] = [
            MigrationOrchestrator(
                config=cfg,
                source_client=src,
                dest_client=dst,
                migration_id=f"{gang_id}-m{idx}",
            )
            for idx, (cfg, src, dst) in enumerate(members, start=1)
        ]

    def execute_atomic(self) -> GangMigrationResult:
        """
        Execute gang migration with a global preflight barrier and a 2PC commit/rollback barrier.
        """
        # 1. Global Preflight Barrier: all members must pass preflight before any member freezes
        for orch in self.orchestrators:
            report = orch.run_preflight()
            if not report.compatible:
                results: List[MigrationResult] = []
                for o in self.orchestrators:
                    o._transition(MigrationState.ABORTED)
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

        # 2. Execute migration for each member, deferring source destruction until all succeed
        saved_wipe_flags = [o.config.wipe_images_on_commit for o in self.orchestrators]
        for o in self.orchestrators:
            o.config.wipe_images_on_commit = False

        member_results: List[MigrationResult] = []
        any_failed = False

        for orch in self.orchestrators:
            res = orch.execute()
            member_results.append(res)
            if not res.success:
                any_failed = True
                break

        # 3. 2PC Barrier: If any member failed, roll back ALL previously succeeded members to Source A
        if any_failed:
            rolled_back_results: List[MigrationResult] = []
            for idx, res in enumerate(member_results):
                orch = self.orchestrators[idx]
                if res.success:
                    cfg_dict = config_to_dict(orch.config)
                    orch.dest.call(
                        "rollback_dest",
                        migration_id=orch.migration_id,
                        restored_pid=res.restored_pid,
                        config_dict=cfg_dict,
                    )
                    orch.source.call(
                        "rollback_source",
                        migration_id=orch.migration_id,
                        source_host=orch.source.host,
                        config_dict=cfg_dict,
                    )
                    orch._transition(MigrationState.ROLLBACK)
                    res.success = False
                    res.rolled_back = True
                    res.final_state = MigrationState.ROLLBACK
                    res.restored_pid = None
                    res.error_message = "Rolled back by 2PC Gang Coordinator due to peer failure"
                    res.state_history = list(orch.state_history)
                rolled_back_results.append(res)

            return GangMigrationResult(
                gang_id=self.gang_id,
                all_committed=False,
                atomic_rollback_triggered=True,
                member_results=rolled_back_results,
            )

        # 4. All members succeeded: wipe checkpoint images if configured
        for idx, orch in enumerate(self.orchestrators):
            orch.config.wipe_images_on_commit = saved_wipe_flags[idx]
            if orch.config.wipe_images_on_commit:
                orch.dest.call(
                    "cleanup_dest",
                    migration_id=orch.migration_id,
                    wipe_images=True,
                )

        return GangMigrationResult(
            gang_id=self.gang_id,
            all_committed=True,
            atomic_rollback_triggered=False,
            member_results=member_results,
        )
