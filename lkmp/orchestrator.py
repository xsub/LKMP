"""Migration Controller & State Machine (Section 3.3 & 3.4)."""

from __future__ import annotations

import time
import uuid
from typing import Dict, List, Optional

from lkmp.agent import AgentClient, config_to_dict
from lkmp.config import FilesystemMode, MigrationConfig, MigrationStrategy
from lkmp.convergence import PreCopyConvergenceTracker
from lkmp.models import (
    FileArtifact,
    HostCapabilities,
    MigrationResult,
    MigrationState,
    PreCopyIterationStats,
    PreflightReport,
    ProcessSnapshotInfo,
)
from lkmp.preflight import evaluate_compatibility


class MigrationOrchestrator:
    """Drives the end-to-end live migration state machine between Source A and Destination B."""

    def __init__(
        self,
        config: MigrationConfig,
        source_client: AgentClient,
        dest_client: AgentClient,
        migration_id: Optional[str] = None,
    ) -> None:
        self.config = config
        self.source = source_client
        self.dest = dest_client
        self.migration_id = migration_id or f"mig-{uuid.uuid4().hex[:8]}"
        self.state = MigrationState.INIT
        self.state_history: List[MigrationState] = [MigrationState.INIT]

    def _transition(self, next_state: MigrationState) -> None:
        self.state = next_state
        self.state_history.append(next_state)

    def run_preflight(self) -> PreflightReport:
        """Execute Phase 1 (Preflight) without modifying either host."""
        self._transition(MigrationState.PREFLIGHT)

        src_caps_raw = self.source.call("get_capabilities")
        dst_caps_raw = self.dest.call("get_capabilities")
        src_caps = HostCapabilities.from_dict(src_caps_raw)
        dst_caps = HostCapabilities.from_dict(dst_caps_raw)

        snap_raw = self.source.call(
            "inspect_process",
            pid=self.config.pid,
            ghost_limit_bytes=self.config.ghost_limit_bytes,
        )
        snapshot = ProcessSnapshotInfo.from_dict(snap_raw)

        file_paths = [f.path for f in snapshot.files if not f.is_deleted]
        dst_files_raw = self.dest.call("stat_files", paths=file_paths)
        dst_files: Dict[str, FileArtifact] = {
            path: FileArtifact.from_dict(meta) for path, meta in dst_files_raw.items()
        }

        report = evaluate_compatibility(
            config=self.config,
            source_caps=src_caps,
            dest_caps=dst_caps,
            snapshot=snapshot,
            dest_files=dst_files,
        )

        # Auto-apply safe flag recommendations discovered during preflight
        for flag in report.required_criu_flags:
            if flag == "--ext-unix-sk":
                self.config.ext_unix_sk = True
            elif flag.startswith("--ghost-limit "):
                try:
                    self.config.ghost_limit_bytes = int(flag.split()[1])
                except (IndexError, ValueError):
                    pass

        return report

    def execute(self) -> MigrationResult:
        """Run the complete migration state machine with automatic rollback on failure."""
        t_start = time.monotonic()
        precopy_stats: List[PreCopyIterationStats] = []
        restored_pid: Optional[int] = None
        freeze_start: Optional[float] = None
        freeze_downtime_ms: float = 0.0

        # Phase 1: Preflight
        try:
            report = self.run_preflight()
        except Exception as exc:
            self._transition(MigrationState.ABORTED)
            return MigrationResult(
                migration_id=self.migration_id,
                success=False,
                final_state=self.state,
                total_duration_ms=round((time.monotonic() - t_start) * 1000.0, 2),
                error_message=f"Preflight error: {exc}",
                state_history=list(self.state_history),
            )

        if not report.compatible:
            self._transition(MigrationState.ABORTED)
            reasons = "; ".join(f"{b.identifier}: {b.reason}" for b in report.blockers)
            return MigrationResult(
                migration_id=self.migration_id,
                success=False,
                final_state=self.state,
                total_duration_ms=round((time.monotonic() - t_start) * 1000.0, 2),
                error_message=f"Preflight failed: {reasons}",
                state_history=list(self.state_history),
            )

        cfg_dict = config_to_dict(self.config)
        prev_round: Optional[str] = None

        try:
            # Phase 2: Prepare
            self._transition(MigrationState.PREPARE)
            self.source.call("prepare_migration", migration_id=self.migration_id)
            self.dest.call("prepare_migration", migration_id=self.migration_id)

            if self.config.fs_mode == FilesystemMode.RSYNC:
                self.source.call(
                    "pre_sync_fs",
                    config_dict=cfg_dict,
                    dest_host=self.dest.host,
                )

            # Phase 3: Iterative Pre-Copy (if PRE_COPY or HYBRID)
            if self.config.strategy in (MigrationStrategy.PRE_COPY, MigrationStrategy.HYBRID):
                tracker = PreCopyConvergenceTracker(
                    bandwidth_mbps=self.config.estimated_bandwidth_mbps,
                    target_downtime_ms=self.config.target_downtime_ms,
                    min_shrink_ratio=self.config.min_shrink_ratio,
                    max_iterations=self.config.max_precopy_iterations,
                )
                for iteration in range(1, self.config.max_precopy_iterations + 1):
                    self._transition(MigrationState.PRE_COPY)
                    round_name = str(iteration)
                    self.dest.call(
                        "start_page_server",
                        migration_id=self.migration_id,
                        round_name=round_name,
                        prev_round_name=prev_round,
                        config_dict=cfg_dict,
                    )
                    predump_res = self.source.call(
                        "run_pre_dump",
                        migration_id=self.migration_id,
                        round_name=round_name,
                        prev_round_name=prev_round,
                        dest_host=self.dest.host,
                        config_dict=cfg_dict,
                    )
                    prev_round = round_name
                    dirty_bytes = int(predump_res["dirty_bytes"])
                    duration_ms = float(predump_res["duration_ms"])

                    decision = tracker.evaluate(iteration=iteration, dirty_bytes=dirty_bytes)
                    precopy_stats.append(
                        PreCopyIterationStats(
                            iteration=iteration,
                            dirty_bytes=dirty_bytes,
                            duration_ms=duration_ms,
                            converged=decision.converged,
                            stop_reason=decision.reason if decision.should_stop else None,
                        )
                    )
                    if decision.should_stop:
                        break

            # Phase 4: Freeze & Final Dump (Downtime begins)
            self._transition(MigrationState.FREEZE)
            freeze_start = time.monotonic()

            if self.config.strategy == MigrationStrategy.PRE_COPY:
                self.dest.call(
                    "start_page_server",
                    migration_id=self.migration_id,
                    round_name="final",
                    prev_round_name=prev_round,
                    config_dict=cfg_dict,
                )

            self._transition(MigrationState.FINAL_DUMP)
            self.source.call(
                "freeze_and_final_dump",
                migration_id=self.migration_id,
                prev_round_name=prev_round,
                dest_host=self.dest.host,
                config_dict=cfg_dict,
            )

            # Phase 5: Transfer metadata & final filesystem delta
            self._transition(MigrationState.TRANSFER)
            self.source.call(
                "transfer_final_state",
                migration_id=self.migration_id,
                dest_host=self.dest.host,
                config_dict=cfg_dict,
            )

            # Phase 6: Restore on Destination B (remains stopped until Switchover)
            self._transition(MigrationState.RESTORE)
            restore_res = self.dest.call(
                "restore_process",
                migration_id=self.migration_id,
                source_host=self.source.host,
                config_dict=cfg_dict,
            )
            restored_pid = int(restore_res["restored_pid"])

            # Phase 7: Switchover (move IP, unlock network on B, resume process on B)
            self._transition(MigrationState.SWITCHOVER)
            self.source.call("release_ip", config_dict=cfg_dict)
            self.dest.call(
                "claim_ip_and_resume",
                restored_pid=restored_pid,
                target_host=self.dest.host,
                config_dict=cfg_dict,
            )
            freeze_downtime_ms = (time.monotonic() - freeze_start) * 1000.0

            # Phase 8: Verify -> Commit
            self._transition(MigrationState.VERIFY)
            verify_res = self.dest.call(
                "verify_process",
                restored_pid=restored_pid,
                health_check_cmd=self.config.health_check_cmd,
                timeout_sec=self.config.health_check_timeout_sec,
            )
            if not verify_res.get("healthy"):
                raise RuntimeError(
                    f"Destination verification failed: {verify_res.get('reason')}"
                )

            self._transition(MigrationState.COMMIT)
            self.source.call(
                "commit_source",
                migration_id=self.migration_id,
                config_dict=cfg_dict,
            )
            if self.config.strategy not in (MigrationStrategy.LAZY, MigrationStrategy.HYBRID):
                self.dest.call(
                    "cleanup_dest",
                    migration_id=self.migration_id,
                    wipe_images=self.config.wipe_images_on_commit,
                )

            return MigrationResult(
                migration_id=self.migration_id,
                success=True,
                final_state=self.state,
                restored_pid=restored_pid,
                total_duration_ms=round((time.monotonic() - t_start) * 1000.0, 2),
                freeze_downtime_ms=round(freeze_downtime_ms, 2),
                precopy_iterations=precopy_stats,
                rolled_back=False,
                state_history=list(self.state_history),
            )

        except Exception as exc:
            # Deterministic rollback: kill partial restore on B, restore IP & resume frozen process on A
            self._transition(MigrationState.ROLLBACK)
            try:
                self.dest.call(
                    "rollback_dest",
                    migration_id=self.migration_id,
                    restored_pid=restored_pid,
                    config_dict=cfg_dict,
                )
            except Exception:
                pass
            try:
                self.source.call(
                    "rollback_source",
                    migration_id=self.migration_id,
                    source_host=self.source.host,
                    config_dict=cfg_dict,
                )
            except Exception:
                pass

            if freeze_start is not None and freeze_downtime_ms == 0.0:
                freeze_downtime_ms = (time.monotonic() - freeze_start) * 1000.0

            return MigrationResult(
                migration_id=self.migration_id,
                success=False,
                final_state=self.state,
                restored_pid=None,
                total_duration_ms=round((time.monotonic() - t_start) * 1000.0, 2),
                freeze_downtime_ms=round(freeze_downtime_ms, 2),
                precopy_iterations=precopy_stats,
                rolled_back=True,
                error_message=str(exc),
                state_history=list(self.state_history),
            )
