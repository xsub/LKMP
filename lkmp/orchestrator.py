"""Migration Controller, 2PC Prepare/Commit Engine & WAL Crash Recovery."""

from __future__ import annotations

import os
import tempfile
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from lkmp.agent import AgentClient, config_from_dict, config_to_dict
from lkmp.attestation import generate_ephemeral_key_hex
from lkmp.config import FilesystemMode, IpMobilityMode, MigrationConfig, MigrationStrategy
from lkmp.convergence import PreCopyConvergenceTracker
from lkmp.fs_sync import is_same_host_or_shared_storage
from lkmp.journal import MigrationJournal, open_migration_journal, validate_safe_identifier
from lkmp.models import (
    FileArtifact,
    HostCapabilities,
    MigrationResult,
    MigrationState,
    PreCopyIterationStats,
    PreflightReport,
    ProcessSnapshotInfo,
    ResourceClassification,
    ResourceFinding,
)
from lkmp.pagemap import select_optimal_strategy
from lkmp.preflight import evaluate_compatibility
from lkmp.telemetry import PrometheusMetricsCollector

try:
    from lkmp.models import PortabilityReport, PortabilityStatus
except ImportError:
    from dataclasses import asdict, dataclass, field
    from enum import Enum

    class PortabilityStatus(str, Enum):
        BLOCKED = "BLOCKED"
        PREPARE = "PREPARE"
        UNKNOWN = "UNKNOWN"
        VERIFIED = "VERIFIED"

    @dataclass
    class PortabilityReport:
        compatible: bool
        overall_status: PortabilityStatus
        same_host_fast_path_available: bool = False
        check_only_passed: Optional[bool] = None
        trial_restore_passed: Optional[bool] = None
        findings: List[ResourceFinding] = field(default_factory=list)
        required_criu_flags: List[str] = field(default_factory=list)
        estimated_cold_downtime_ms: float = 0.0
        estimated_live_downtime_ms: float = 0.0

        def to_dict(self) -> Dict[str, Any]:
            st = self.overall_status.value if hasattr(self.overall_status, "value") else str(self.overall_status)
            return {
                "status": st,
                "overall_status": st,
                "compatible": self.compatible,
                "same_host_fast_path_available": self.same_host_fast_path_available,
                "check_only_passed": self.check_only_passed,
                "trial_restore_passed": self.trial_restore_passed,
                "findings": [f.to_dict() for f in self.findings],
                "required_criu_flags": self.required_criu_flags,
                "estimated_cold_downtime_ms": self.estimated_cold_downtime_ms,
                "estimated_live_downtime_ms": self.estimated_live_downtime_ms,
            }

try:
    from lkmp.preflight import evaluate_portability
except ImportError:
    evaluate_portability = None


class MigrationOrchestrator:
    """Drives the end-to-end live migration state machine between Source A and Destination B."""

    def __init__(
        self,
        config: MigrationConfig,
        source_client: AgentClient,
        dest_client: AgentClient,
        migration_id: Optional[str] = None,
        metrics: Optional[PrometheusMetricsCollector] = None,
        journal_dir: Optional[str | Path] = None,
    ) -> None:
        self.config = config
        self.source = source_client
        self.dest = dest_client
        self.migration_id = validate_safe_identifier(
            migration_id or f"mig-{uuid.uuid4().hex[:8]}",
            "migration_id",
        )
        self.metrics = metrics
        self.state = MigrationState.INIT
        self.state_history: List[MigrationState] = [MigrationState.INIT]
        j_dir = journal_dir if journal_dir is not None else getattr(self.config, "journal_dir", None)
        self.journal: Optional[MigrationJournal] = None
        if j_dir:
            self.journal = open_migration_journal(j_dir, self.migration_id)

        # Ensure an ephemeral per-migration attestation key is set if not already provided
        if (
            self.config.verify_attestation
            and not self.config.attestation_key_hex
            and not os.environ.get("LKMP_ATTESTATION_KEY")
        ):
            self.config.attestation_key_hex = generate_ephemeral_key_hex()

        self._t_start: float = 0.0
        self._freeze_downtime_ms: float = 0.0
        self._precopy_stats: List[PreCopyIterationStats] = []
        self._restored_pid: Optional[int] = None
        self._dest_has_userfaultfd: bool = False

    def _transition(
        self,
        next_state: MigrationState,
        commit_decision: str = "PREPARING",
        note: Optional[str] = None,
    ) -> None:
        self.state = next_state
        self.state_history.append(next_state)
        if self.journal is not None:
            cfg_dict = (
                config_to_dict(self.config)
                if len(self.journal.entries) == 0
                else None
            )
            self.journal.append(
                state=next_state,
                commit_decision=commit_decision,
                restored_pid=self._restored_pid,
                config_dict=cfg_dict,
                note=note,
            )

    def run_preflight(self) -> PreflightReport:
        """Execute Phase 1 (Preflight) without modifying either host."""
        self._transition(MigrationState.PREFLIGHT, commit_decision="PREPARING")

        src_caps_raw = self.source.call("get_capabilities")
        dst_caps_raw = self.dest.call("get_capabilities")
        src_caps = HostCapabilities.from_dict(src_caps_raw)
        dst_caps = HostCapabilities.from_dict(dst_caps_raw)
        self._dest_has_userfaultfd = dst_caps.has_userfaultfd

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

        if self.config.strategy == MigrationStrategy.AUTO:
            chosen_strategy, _reason = select_optimal_strategy(
                rss_bytes=snapshot.rss_bytes,
                dirty_rate_bytes_per_sec=snapshot.dirty_rate_bytes_per_sec,
                bandwidth_mbps=self.config.estimated_bandwidth_mbps,
                has_userfaultfd=dst_caps.has_userfaultfd,
            )
            self.config.strategy = chosen_strategy

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

    def assess_portability(
        self,
        run_check_only: Optional[bool] = None,
        run_trial_restore: Optional[bool] = None,
    ) -> PortabilityReport:
        """
        Assess process live migration portability, CRIU compatibility, and host readiness:
        1. Calls get_capabilities, inspect_process (passing active_sample_ms), and stat_files.
        2. If run_check_only (or config.check_only): calls run_check_only on Source A.
        3. If run_trial_restore (or config.trial_restore): executes non-destructive trial restore
           on Destination B (--leave-stopped + network locked) and rolls back cleanly to Source A.
        4. Calls evaluate_portability and sets same_host_fast_path_available.
        """
        do_check_only = run_check_only if run_check_only is not None else self.config.check_only
        do_trial_restore = run_trial_restore if run_trial_restore is not None else self.config.trial_restore

        src_caps_raw = self.source.call("get_capabilities")
        dst_caps_raw = self.dest.call("get_capabilities")
        src_caps = HostCapabilities.from_dict(src_caps_raw)
        dst_caps = HostCapabilities.from_dict(dst_caps_raw)
        self._dest_has_userfaultfd = dst_caps.has_userfaultfd

        snap_raw = self.source.call(
            "inspect_process",
            pid=self.config.pid,
            ghost_limit_bytes=self.config.ghost_limit_bytes,
            active_sample_ms=getattr(self.config, "active_sample_ms", 0),
        )
        snapshot = ProcessSnapshotInfo.from_dict(snap_raw)

        file_paths = [f.path for f in snapshot.files if not f.is_deleted]
        dst_files_raw = self.dest.call("stat_files", paths=file_paths)
        dst_files: Dict[str, FileArtifact] = {
            path: FileArtifact.from_dict(meta) for path, meta in dst_files_raw.items()
        }

        # Check preliminary compatibility
        pre_rep = evaluate_compatibility(
            config=self.config,
            source_caps=src_caps,
            dest_caps=dst_caps,
            snapshot=snapshot,
            dest_files=dst_files,
        )
        has_blockers = not pre_rep.compatible or bool(pre_rep.blockers)

        check_only_passed: Optional[bool] = None
        if do_check_only and not has_blockers:
            try:
                chk_res = self.source.call(
                    "run_check_only",
                    migration_id=self.migration_id,
                    config_dict=config_to_dict(self.config),
                )
                check_only_passed = bool(chk_res.get("check_only_ok", True))
            except Exception:
                check_only_passed = False

        trial_restore_passed: Optional[bool] = None
        if do_trial_restore and not has_blockers and (check_only_passed is not False):
            orig_ip_mobility = self.config.ip_mobility
            orig_tcp_est = self.config.tcp_established
            has_net_sockets = any(
                getattr(f, "resource_type", "") == "socket" and "TCP" in str(getattr(f, "identifier", "")).upper()
                for f in getattr(snapshot, "findings", [])
            )
            try:
                self.config.ip_mobility = IpMobilityMode.NONE
                if not self.config.workload_ip and not has_net_sockets:
                    self.config.tcp_established = False
                prep_res = self.execute_prepare_phase(keep_stopped_on_prepare=True)
                rb_res = self.rollback("Completed isolated trial restore verification")
                trial_restore_passed = bool(prep_res.success and rb_res.rolled_back)
            except Exception:
                trial_restore_passed = False
                try:
                    self.rollback("Completed isolated trial restore verification")
                except Exception:
                    pass
            finally:
                self.config.ip_mobility = orig_ip_mobility
                self.config.tcp_established = orig_tcp_est

        # Evaluate final portability state
        report = None
        if evaluate_portability is not None:
            try:
                res = evaluate_portability(
                    snapshot_or_report=snapshot,
                    dirty_rate_actively_sampled=bool(getattr(self.config, "active_sample_ms", 0) > 0),
                    trial_restore_passed=bool(trial_restore_passed),
                    config=self.config,
                    source_caps=src_caps,
                    dest_caps=dst_caps,
                )
                if isinstance(res, PortabilityReport):
                    report = res
                else:
                    st_val = getattr(res, "value", str(res)).upper()
                    compatible = (st_val != "BLOCKED")
                    report = PortabilityReport(
                        compatible=compatible,
                        overall_status=res,
                        check_only_passed=check_only_passed,
                        trial_restore_passed=trial_restore_passed,
                        findings=snapshot.findings,
                        required_criu_flags=pre_rep.required_criu_flags,
                        estimated_cold_downtime_ms=pre_rep.estimated_cold_downtime_ms,
                        estimated_live_downtime_ms=pre_rep.estimated_live_downtime_ms,
                    )
            except TypeError:
                try:
                    report = evaluate_portability(
                        config=self.config,
                        source_caps=src_caps,
                        dest_caps=dst_caps,
                        snapshot=snapshot,
                        dest_files=dst_files,
                        check_only_passed=check_only_passed,
                        trial_restore_passed=trial_restore_passed,
                    )
                except Exception:
                    pass

        if report is None:
            if has_blockers:
                status = PortabilityStatus.BLOCKED
            elif pre_rep.required_criu_flags:
                status = PortabilityStatus.PREPARE
            elif trial_restore_passed:
                status = PortabilityStatus.VERIFIED
            else:
                status = PortabilityStatus.UNKNOWN
            report = PortabilityReport(
                compatible=not has_blockers,
                overall_status=status,
                check_only_passed=check_only_passed,
                trial_restore_passed=trial_restore_passed,
                findings=snapshot.findings,
                required_criu_flags=pre_rep.required_criu_flags,
                estimated_cold_downtime_ms=pre_rep.estimated_cold_downtime_ms,
                estimated_live_downtime_ms=pre_rep.estimated_live_downtime_ms,
            )

        src_host_id = getattr(src_caps, "host_id", None)
        dst_host_id = getattr(dst_caps, "host_id", None)
        same_host = bool(
            (src_host_id is not None and src_host_id == dst_host_id)
            or (self.source.host == self.dest.host)
        )
        report.same_host_fast_path_available = same_host
        return report

    def execute_prepare_phase(self, keep_stopped_on_prepare: bool = False) -> MigrationResult:
        """
        Execute Phases 1 through 8 (`PREFLIGHT` -> ... -> `VERIFY`), stopping at `VERIFY`
        while keeping the frozen source process on Host A intact (`--leave-stopped`).
        When keep_stopped_on_prepare is True (used by 2PC gang migration), Destination B
        is kept stopped (--leave-stopped) and network-fenced, verified via verify_restored_stopped.
        """
        self._t_start = time.monotonic()
        self._precopy_stats = []
        self._restored_pid = None
        freeze_start: Optional[float] = None
        self._freeze_downtime_ms = 0.0

        # Phase 1: Preflight
        try:
            report = self.run_preflight()
        except Exception as exc:
            self._transition(MigrationState.ABORTED, commit_decision="ABORTING", note=str(exc))
            return MigrationResult(
                migration_id=self.migration_id,
                success=False,
                final_state=self.state,
                total_duration_ms=round((time.monotonic() - self._t_start) * 1000.0, 2),
                error_message=f"Preflight error: {exc}",
                state_history=list(self.state_history),
            )

        if not report.compatible:
            reasons = "; ".join(f"{b.identifier}: {b.reason}" for b in report.blockers)
            self._transition(MigrationState.ABORTED, commit_decision="ABORTING", note=reasons)
            return MigrationResult(
                migration_id=self.migration_id,
                success=False,
                final_state=self.state,
                total_duration_ms=round((time.monotonic() - self._t_start) * 1000.0, 2),
                error_message=f"Preflight failed: {reasons}",
                state_history=list(self.state_history),
            )

        cfg_dict = config_to_dict(self.config)
        prev_round: Optional[str] = None

        try:
            # Phase 2: Prepare
            self._transition(MigrationState.PREPARE, commit_decision="PREPARING")
            self.source.call("prepare_migration", migration_id=self.migration_id)
            dst_prep = self.dest.call("prepare_migration", migration_id=self.migration_id)
            dest_images_dir = (
                dst_prep.get("images_dir")
                if isinstance(dst_prep, dict)
                and is_same_host_or_shared_storage(self.config.source_addr, self.dest.host)
                else None
            )

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
                    self._transition(MigrationState.PRE_COPY, commit_decision="PREPARING")
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
                    if not predump_res or "dirty_bytes" not in predump_res:
                        break
                    ps_final = self.dest.call(
                        "finalize_page_server_round",
                        migration_id=self.migration_id,
                        round_name=round_name,
                    )
                    prev_round = round_name
                    # Prefer actual received page-server bytes on B, fallback to local A size
                    dirty_bytes = max(
                        int(ps_final.get("received_dirty_bytes", 0)) if ps_final else 0,
                        int(predump_res["dirty_bytes"]),
                    )
                    duration_ms = float(predump_res.get("duration_ms", 0.0))

                    decision = tracker.evaluate(iteration=iteration, dirty_bytes=dirty_bytes)
                    self._precopy_stats.append(
                        PreCopyIterationStats(
                            iteration=iteration,
                            dirty_bytes=dirty_bytes,
                            duration_ms=duration_ms,
                            converged=decision.converged,
                            stop_reason=decision.reason if decision.should_stop else None,
                        )
                    )
                    if decision.should_stop:
                        if (
                            decision.recommend_hybrid_upgrade
                            and self.config.allow_hybrid_upgrade
                            and self._dest_has_userfaultfd
                            and self.config.strategy == MigrationStrategy.PRE_COPY
                        ):
                            self.config.strategy = MigrationStrategy.HYBRID
                            cfg_dict = config_to_dict(self.config)
                        break

            # Phase 4: Freeze & Final Dump (Downtime begins)
            self._transition(MigrationState.FREEZE, commit_decision="PREPARING")
            freeze_start = time.monotonic()

            if self.config.strategy == MigrationStrategy.PRE_COPY:
                self.dest.call(
                    "start_page_server",
                    migration_id=self.migration_id,
                    round_name="final",
                    prev_round_name=prev_round,
                    config_dict=cfg_dict,
                )

            self._transition(MigrationState.FINAL_DUMP, commit_decision="PREPARING")
            self.source.call(
                "freeze_and_final_dump",
                migration_id=self.migration_id,
                prev_round_name=prev_round,
                dest_host=self.dest.host,
                config_dict=cfg_dict,
            )

            dest_pages_merkle_root: Optional[str] = None
            if self.config.strategy == MigrationStrategy.PRE_COPY and self.config.verify_attestation:
                ps_final = self.dest.call(
                    "finalize_page_server_round",
                    migration_id=self.migration_id,
                    round_name="final",
                )
                dest_pages_merkle_root = ps_final.get("dest_pages_merkle_root") if ps_final else None

            # Phase 5: Transfer metadata, manifest.sig.json & final filesystem delta
            self._transition(MigrationState.TRANSFER, commit_decision="PREPARING")
            transfer_kwargs: Dict[str, object] = {
                "migration_id": self.migration_id,
                "dest_host": self.dest.host,
                "config_dict": cfg_dict,
                "dest_pages_merkle_root": dest_pages_merkle_root,
            }
            if dest_images_dir:
                transfer_kwargs["dest_images_dir"] = dest_images_dir
            self.source.call("transfer_final_state", **transfer_kwargs)

            # Phase 6: Release IP on Source A (while locked) & Restore on Destination B
            # Note: `restore_process` assigns the IP on B BEFORE running `criu restore --tcp-established`
            self._transition(MigrationState.RESTORE, commit_decision="PREPARING")
            self.source.call(
                "release_ip",
                config_dict=cfg_dict,
                migration_id=self.migration_id,
            )
            restore_res = self.dest.call(
                "restore_process",
                migration_id=self.migration_id,
                source_host=self.source.host,
                config_dict=cfg_dict,
            )
            self._restored_pid = int(restore_res["restored_pid"])
            if self.journal is not None:
                self.journal.append(
                    state=MigrationState.RESTORE,
                    commit_decision="PREPARING",
                    restored_pid=self._restored_pid,
                    note="Restore completed, pid recorded",
                )

            if keep_stopped_on_prepare:
                # Keep process stopped and network-fenced on Destination B for gang coordination
                verify_res = self.dest.call(
                    "verify_restored_stopped",
                    restored_pid=self._restored_pid,
                    migration_id=self.migration_id,
                )
                if not verify_res.get("healthy"):
                    raise RuntimeError(
                        f"Destination stopped verification failed: {verify_res.get('reason')}"
                    )
                self._transition(MigrationState.VERIFY, commit_decision="PREPARED_STOPPED")
                return MigrationResult(
                    migration_id=self.migration_id,
                    success=True,
                    final_state=MigrationState.VERIFY,
                    restored_pid=self._restored_pid,
                    total_duration_ms=round((time.monotonic() - self._t_start) * 1000.0, 2),
                    freeze_downtime_ms=round(self._freeze_downtime_ms, 2),
                    precopy_iterations=list(self._precopy_stats),
                    rolled_back=False,
                    state_history=list(self.state_history),
                )

            # Phase 7: Switchover (announce GARP/BGP, unlock network on B, resume process on B)
            self._transition(MigrationState.SWITCHOVER, commit_decision="PREPARING")
            self.dest.call(
                "claim_ip_and_resume",
                restored_pid=self._restored_pid,
                target_host=self.dest.host,
                config_dict=cfg_dict,
                migration_id=self.migration_id,
            )
            self._freeze_downtime_ms = (time.monotonic() - freeze_start) * 1000.0

            # Phase 8: Verify on Destination B (Source A still frozen and alive!)
            self._transition(MigrationState.VERIFY, commit_decision="PREPARING")
            verify_res = self.dest.call(
                "verify_process",
                restored_pid=self._restored_pid,
                health_check_cmd=self.config.health_check_cmd,
                timeout_sec=self.config.health_check_timeout_sec,
            )
            if not verify_res.get("healthy"):
                raise RuntimeError(
                    f"Destination verification failed: {verify_res.get('reason')}"
                )

            return MigrationResult(
                migration_id=self.migration_id,
                success=True,
                final_state=MigrationState.VERIFY,
                restored_pid=self._restored_pid,
                total_duration_ms=round((time.monotonic() - self._t_start) * 1000.0, 2),
                freeze_downtime_ms=round(self._freeze_downtime_ms, 2),
                precopy_iterations=list(self._precopy_stats),
                rolled_back=False,
                state_history=list(self.state_history),
            )

        except Exception as exc:
            if freeze_start is not None and self._freeze_downtime_ms == 0.0:
                self._freeze_downtime_ms = (time.monotonic() - freeze_start) * 1000.0
            return self.rollback(str(exc))

    def complete_switchover_and_verify(self) -> None:
        """
        Execute Phase 7 (SWITCHOVER: claim_ip_and_resume) and Phase 8 (VERIFY: verify_process)
        transitioning from a stopped prepare to active execution on Destination B.
        """
        cfg_dict = config_to_dict(self.config)
        self._transition(MigrationState.SWITCHOVER, commit_decision="COMMITTED")
        self.dest.call(
            "claim_ip_and_resume",
            restored_pid=self._restored_pid,
            target_host=self.dest.host,
            config_dict=cfg_dict,
            migration_id=self.migration_id,
        )
        self._transition(MigrationState.VERIFY, commit_decision="COMMITTED")
        verify_res = self.dest.call(
            "verify_process",
            restored_pid=self._restored_pid,
            health_check_cmd=self.config.health_check_cmd,
            timeout_sec=self.config.health_check_timeout_sec,
            migration_id=self.migration_id,
        )
        if not verify_res.get("healthy"):
            raise RuntimeError(
                f"Destination verification failed: {verify_res.get('reason')}"
            )

    def commit(self) -> MigrationResult:
        """
        Execute Phase 9 (`COMMIT`): record durable COMMITTED decision in WAL, terminate the
        frozen source process on Host A, and wipe checkpoint images.
        Once `commit_source` succeeds, cleanup errors on Destination B never trigger rollback.
        """
        cfg_dict = config_to_dict(self.config)
        self._transition(MigrationState.COMMIT, commit_decision="COMMITTED")
        self.source.call(
            "commit_source",
            migration_id=self.migration_id,
            config_dict=cfg_dict,
        )
        if self.config.strategy not in (MigrationStrategy.LAZY, MigrationStrategy.HYBRID):
            try:
                self.dest.call(
                    "cleanup_dest",
                    migration_id=self.migration_id,
                    wipe_images=self.config.wipe_images_on_commit,
                )
            except Exception:
                # Non-fatal cleanup error after irrevocable commit
                pass

        result = MigrationResult(
            migration_id=self.migration_id,
            success=True,
            final_state=self.state,
            restored_pid=self._restored_pid,
            total_duration_ms=round((time.monotonic() - self._t_start) * 1000.0, 2),
            freeze_downtime_ms=round(self._freeze_downtime_ms, 2),
            precopy_iterations=list(self._precopy_stats),
            rolled_back=False,
            state_history=list(self.state_history),
        )
        if self.metrics is not None:
            self.metrics.record_migration(self.config.strategy.value, result)
        return result

    def rollback(self, reason: str) -> MigrationResult:
        """
        Execute Phase 10 (`ROLLBACK`): terminate any partial restore on Destination B,
        re-claim IP & unlock network on Source A, and resume the frozen process on Source A.
        Reports `rolled_back=True` ONLY if Source A was verified alive and resumed.
        """
        cfg_dict = config_to_dict(self.config)
        self._transition(MigrationState.ROLLBACK, commit_decision="ABORTING", note=reason)
        rb_errors: List[str] = []
        dest_ok = False
        src_ok = False

        try:
            dest_res = self.dest.call(
                "rollback_dest",
                migration_id=self.migration_id,
                restored_pid=self._restored_pid,
                config_dict=cfg_dict,
            )
            dest_ok = bool(dest_res.get("rolled_back_dest", True))
            if dest_res.get("errors"):
                rb_errors.extend(dest_res["errors"])
        except Exception as dest_exc:
            rb_errors.append(f"rollback_dest error: {dest_exc}")

        if dest_ok:
            try:
                src_res = self.source.call(
                    "rollback_source",
                    migration_id=self.migration_id,
                    source_host=self.source.host,
                    config_dict=cfg_dict,
                )
                src_ok = bool(src_res.get("rolled_back_source", False))
            except Exception as src_exc:
                rb_errors.append(f"rollback_source error: {src_exc}")
        else:
            rb_errors.append(
                "Skipping rollback_source because rollback_dest failed; keeping source fenced to prevent dual execution"
            )

        rolled_back = dest_ok and src_ok
        if self.journal is not None and rolled_back:
            self.journal.append(
                state=MigrationState.ROLLBACK,
                commit_decision="ROLLED_BACK",
                restored_pid=None,
                note=reason,
            )

        full_error = reason
        if rb_errors:
            full_error = f"{reason} (rollback errors: {'; '.join(rb_errors)})"

        result = MigrationResult(
            migration_id=self.migration_id,
            success=False,
            final_state=self.state,
            restored_pid=None,
            total_duration_ms=round((time.monotonic() - self._t_start) * 1000.0, 2),
            freeze_downtime_ms=round(self._freeze_downtime_ms, 2),
            precopy_iterations=list(self._precopy_stats),
            rolled_back=rolled_back,
            error_message=full_error,
            state_history=list(self.state_history),
        )
        if self.metrics is not None:
            self.metrics.record_migration(self.config.strategy.value, result)
        return result

    def execute(self) -> MigrationResult:
        """Run the complete migration state machine (`execute_prepare_phase` + `commit`)."""
        prep = self.execute_prepare_phase()
        if not prep.success or prep.final_state != MigrationState.VERIFY:
            return prep
        return self.commit()

    @classmethod
    def recover_from_journal(
        cls,
        journal_path: str | Path,
        source_client: AgentClient,
        dest_client: AgentClient,
    ) -> MigrationResult:
        """
        Recover an interrupted migration from its durable Write-Ahead Log (`.wal.jsonl`):
        - If a `COMMITTED` decision was logged prior to the controller crash, completes `commit()`.
        - Otherwise, deterministically executes `rollback()` so Source A resumes safely.
        """
        journal = MigrationJournal.load(journal_path)
        cfg_dict = journal.initial_config_dict
        if cfg_dict is None:
            raise ValueError(f"Journal {journal_path} does not contain migration configuration")
        config = config_from_dict(cfg_dict)
        orch = cls(
            config=config,
            source_client=source_client,
            dest_client=dest_client,
            migration_id=journal.migration_id,
            journal_dir=Path(journal_path).parent,
        )
        orch._t_start = time.monotonic()
        last = journal.last_entry
        if last and last.restored_pid is not None:
            orch._restored_pid = last.restored_pid
        orch.state_history = [MigrationState(e.state) for e in journal.entries]
        if orch.state_history:
            orch.state = orch.state_history[-1]

        if journal.has_committed_decision:
            return orch.commit()
        return orch.rollback("Controller crash recovery: no COMMITTED record in WAL")
