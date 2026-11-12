"""Migration Controller, 2PC Prepare/Commit Engine & WAL Crash Recovery."""

from __future__ import annotations

import json
import os
import re
import time
import uuid
from pathlib import Path
from typing import Dict, List, Optional

from lkmp.agent import AgentClient, config_from_dict, config_to_dict
from lkmp.attestation import generate_ephemeral_key_hex
from lkmp.config import FilesystemMode, IpMobilityMode, MigrationConfig, MigrationStrategy
from lkmp.convergence import PreCopyConvergenceTracker
from lkmp.drivers import WorkloadKind
from lkmp.journal import MigrationJournal, open_migration_journal, validate_safe_identifier
from lkmp.logging_utils import get_logger, migration_log_context
from lkmp.models import (
    FileArtifact,
    HostCapabilities,
    MigrationResult,
    MigrationState,
    PortabilityReport,
    PortabilityStatus,
    PreCopyIterationStats,
    PreflightReport,
    ProcessSnapshotInfo,
)
from lkmp.pagemap import select_optimal_strategy
from lkmp.preflight import evaluate_compatibility, evaluate_portability
from lkmp.telemetry import PrometheusMetricsCollector

logger = get_logger("orchestrator")


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
        gang_id: Optional[str] = None,
        require_persistent_journal: bool = True,
    ) -> None:
        self.config = config
        self.source = source_client
        self.dest = dest_client
        self.migration_id = validate_safe_identifier(
            migration_id or f"mig-{uuid.uuid4().hex[:8]}",
            "migration_id",
        )
        self.gang_id = validate_safe_identifier(gang_id, "gang_id") if gang_id else None
        self.metrics = metrics
        self.state = MigrationState.INIT
        self.state_history: List[MigrationState] = [MigrationState.INIT]
        j_dir = journal_dir if journal_dir is not None else getattr(self.config, "journal_dir", None)
        self.journal: Optional[MigrationJournal] = None
        if j_dir:
            self.journal = open_migration_journal(
                j_dir,
                self.migration_id,
                gang_id=self.gang_id,
                require_persistent=require_persistent_journal,
            )

        # Ensure an ephemeral per-migration attestation key is set if not already provided
        if (
            self.config.verify_attestation
            and not self.config.attestation_key_hex
            and not os.environ.get("LKMP_ATTESTATION_KEY")
        ):
            self.config.attestation_key_hex = generate_ephemeral_key_hex()

        self._t_start: float = 0.0
        self._freeze_start_ts: Optional[float] = None
        self._freeze_downtime_ms: float = 0.0
        self._precopy_stats: List[PreCopyIterationStats] = []
        self._restored_pid: Optional[int] = None
        self._restored_starttime: Optional[int] = None
        self._dest_has_userfaultfd: bool = False
        self._fenced_canary_active: bool = False
        self._last_persisted_config_json: Optional[str] = None
        if self.journal is not None and self.journal.effective_config_dict is not None:
            self._last_persisted_config_json = json.dumps(
                self.journal.effective_config_dict, sort_keys=True, separators=(",", ":")
            )

    def _transition(
        self,
        next_state: MigrationState,
        commit_decision: str = "PREPARING",
        note: Optional[str] = None,
    ) -> None:
        self.state = next_state
        self.state_history.append(next_state)
        if self.journal is not None:
            current_cfg = config_to_dict(self.config)
            current_cfg_json = json.dumps(current_cfg, sort_keys=True, separators=(",", ":"))
            if (
                self._last_persisted_config_json is None
                or current_cfg_json != self._last_persisted_config_json
                or (len(self.journal.entries) == 0 and not self.journal.path.exists())
            ):
                cfg_dict = current_cfg
                self._last_persisted_config_json = current_cfg_json
            else:
                cfg_dict = None
            self.journal.append(
                state=next_state,
                commit_decision=commit_decision,
                restored_pid=self._restored_pid,
                restored_starttime=self._restored_starttime,
                config_dict=cfg_dict,
                note=note,
            )

    def _enrich_runtime_profile(self, snapshot: ProcessSnapshotInfo) -> None:
        """Populate `workload_kind` and `runtime_metadata` from source process-tree fingerprint."""
        if (self.config.workload_kind or "auto").lower() == WorkloadKind.AUTO.value:
            self.config.workload_kind = (snapshot.workload_kind or WorkloadKind.POSIX_TREE.value).lower()

        prof = snapshot.runtime_profile or {}
        if not prof:
            return
        meta = dict(self.config.runtime_metadata or {})
        if prof.get("control_socket") and "qmp_socket" not in meta:
            meta["qmp_socket"] = prof["control_socket"]
        if prof.get("control_socket") and "control_socket" not in meta:
            meta["control_socket"] = prof["control_socket"]
        if prof.get("cmdline") and "qemu_cmdline" not in meta:
            meta["qemu_cmdline"] = list(prof["cmdline"])
        if prof.get("container_id") and "container_id" not in meta:
            meta["container_id"] = prof["container_id"]
        if prof.get("container_engine") and "container_engine" not in meta:
            meta["container_engine"] = prof["container_engine"]
        if prof.get("subkind") and "subkind" not in meta:
            meta["subkind"] = prof["subkind"]
        if prof.get("overlay_upperdir") and "overlay_upperdir" not in meta:
            meta["overlay_upperdir"] = prof["overlay_upperdir"]
        if prof.get("starttime") is not None and "source_starttime" not in meta:
            meta["source_starttime"] = prof["starttime"]
        self.config.runtime_metadata = meta

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
        self._enrich_runtime_profile(snapshot)

        file_paths = [f.path for f in snapshot.files if not f.is_deleted]
        dst_files_raw = self.dest.call("stat_files", paths=file_paths)
        dst_files: Dict[str, FileArtifact] = {
            path: FileArtifact.from_dict(meta) for path, meta in dst_files_raw.items()
        }

        if self.config.strategy == MigrationStrategy.AUTO:
            if (self.config.workload_kind or "").lower() == WorkloadKind.QEMU_VM.value:
                self.config.strategy = MigrationStrategy.PRE_COPY
            else:
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
        self._enrich_runtime_profile(snapshot)

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

    def execute_prepare_phase(
        self,
        keep_stopped_on_prepare: bool = False,
        defer_switchover_until_commit: bool = False,
    ) -> MigrationResult:
        """
        Execute Phases 1 through 6/8 while keeping the frozen source process on Host A intact (`--leave-stopped`).
        - When `keep_stopped_on_prepare=True` (2PC gang migration), stops at `VERIFY` (`PREPARED_STOPPED`)
          with Destination B stopped (`--leave-stopped`) and network-fenced.
        - When `defer_switchover_until_commit=True` (default single-workload strict 2PC cutover without
          `--health-cmd`), verifies stopped readiness at `RESTORE` so `COMMIT_DECIDED` is fsynced to WAL
          *before* Destination B ever executes an instruction (`claim_ip_and_resume`).
        - When `--health-cmd` is configured (`defer_switchover_until_commit=False`), resumes Destination B
          inside a loopback-only network fence (`fenced_canary=True`) to run the health probe prior to commit.
        """
        self._t_start = time.monotonic()
        self._precopy_stats = []
        self._restored_pid = None
        self._restored_starttime = None
        self._fenced_canary_active = False
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
        use_driver_prepare = (
            (self.config.workload_kind or "auto").lower()
            in (
                WorkloadKind.QEMU_VM.value,
                WorkloadKind.OCI_CONTAINER.value,
                WorkloadKind.MICROVM.value,
            )
            or bool(self.config.prefer_tmpfs_work_dir)
        )

        with migration_log_context(
            migration_id=self.migration_id,
            gang_id=self.gang_id,
            pid=self.config.pid,
            driver=self.config.workload_kind,
        ):
            try:
                # Phase 2: Prepare
                self._transition(MigrationState.PREPARE, commit_decision="PREPARING")
                if use_driver_prepare:
                    self.source.call(
                        "prepare_migration",
                        migration_id=self.migration_id,
                        config_dict=cfg_dict,
                        is_dest=False,
                    )
                    dst_prep = self.dest.call(
                        "prepare_migration",
                        migration_id=self.migration_id,
                        config_dict=cfg_dict,
                        is_dest=True,
                    )
                else:
                    self.source.call("prepare_migration", migration_id=self.migration_id)
                    dst_prep = self.dest.call("prepare_migration", migration_id=self.migration_id)
                dest_images_dir = (
                    dst_prep.get("images_dir")
                    if isinstance(dst_prep, dict) and self.config.same_host_cow
                    else None
                )
                dest_probe_token = (
                    dst_prep.get("storage_probe_token")
                    if isinstance(dst_prep, dict) and self.config.same_host_cow
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

                        decision = tracker.evaluate(
                            iteration=iteration,
                            dirty_bytes=dirty_bytes,
                            duration_ms=duration_ms,
                        )
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

                # Pre-spawn final page-server BEFORE freeze_start so daemon startup is outside blackout!
                if self.config.strategy == MigrationStrategy.PRE_COPY:
                    self.dest.call(
                        "start_page_server",
                        migration_id=self.migration_id,
                        round_name="final",
                        prev_round_name=prev_round,
                        config_dict=cfg_dict,
                    )

                # Phase 4: Freeze & Final Dump (Downtime begins)
                self._transition(MigrationState.FREEZE, commit_decision="PREPARING")
                freeze_start = time.monotonic()
                self._freeze_start_ts = freeze_start

                self._transition(MigrationState.FINAL_DUMP, commit_decision="PREPARING")
                self.source.call(
                    "freeze_and_final_dump",
                    migration_id=self.migration_id,
                    prev_round_name=prev_round,
                    dest_host=self.dest.host,
                    config_dict=cfg_dict,
                )

                dest_pages_merkle_root: Optional[str] = None
                if (
                    self.config.strategy == MigrationStrategy.PRE_COPY
                    and self.config.verify_attestation
                    and (self.config.workload_kind or "auto").lower()
                    not in (
                        WorkloadKind.QEMU_VM.value,
                        WorkloadKind.OCI_CONTAINER.value,
                        WorkloadKind.MICROVM.value,
                    )
                ):
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
                if dest_probe_token:
                    transfer_kwargs["dest_probe_token"] = dest_probe_token

                inband_done = False
                if self.config.inband_metadata_transfer:
                    try:
                        inband_res = self.source.call("export_inband_metadata", **transfer_kwargs)
                        if isinstance(inband_res, dict) and inband_res.get("eligible"):
                            if not inband_res.get("skip_upload"):
                                self.dest.call(
                                    "upload_checkpoint_files",
                                    migration_id=self.migration_id,
                                    round_name="final",
                                    files_b64=inband_res.get("files_b64") or {},
                                )
                            if self.config.writable_paths or self.config.volume_snapshot_cmd:
                                self.source.call(
                                    "transfer_final_state",
                                    **transfer_kwargs,
                                    skip_images_sync=True,
                                )
                            inband_done = True
                    except Exception:
                        inband_done = False

                if not inband_done:
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
                raw_rst_st = restore_res.get("restored_starttime")
                self._restored_starttime = int(raw_rst_st) if raw_rst_st is not None else None
                if self.journal is not None:
                    self.journal.append(
                        state=MigrationState.RESTORE,
                        commit_decision="PREPARING",
                        restored_pid=self._restored_pid,
                        restored_starttime=self._restored_starttime,
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

                if defer_switchover_until_commit:
                    # Verify restored process is alive, starttime-matched, and stopped BEFORE commit barrier
                    stopped_kwargs: Dict[str, object] = {
                        "restored_pid": self._restored_pid,
                        "health_check_cmd": None,
                        "timeout_sec": self.config.health_check_timeout_sec,
                        "migration_id": self.migration_id,
                        "allow_stopped": True,
                    }
                    if self._restored_starttime is not None:
                        stopped_kwargs["expected_restored_starttime"] = self._restored_starttime
                    try:
                        stopped_chk = self.dest.call("verify_process", **stopped_kwargs)
                    except TypeError:
                        stopped_kwargs.pop("allow_stopped", None)
                        stopped_kwargs.pop("expected_restored_starttime", None)
                        stopped_chk = self.dest.call("verify_process", **stopped_kwargs)
                    if not stopped_chk.get("healthy"):
                        raise RuntimeError(
                            f"Destination pre-cutover stopped verification failed: {stopped_chk.get('reason')}"
                        )
                    return MigrationResult(
                        migration_id=self.migration_id,
                        success=True,
                        final_state=MigrationState.RESTORE,
                        restored_pid=self._restored_pid,
                        total_duration_ms=round((time.monotonic() - self._t_start) * 1000.0, 2),
                        freeze_downtime_ms=round(self._freeze_downtime_ms, 2),
                        precopy_iterations=list(self._precopy_stats),
                        rolled_back=False,
                        state_history=list(self.state_history),
                    )

                # Phase 7: Fenced Canary Switchover (used when `--health-cmd` requires probing before COMMIT)
                use_fenced_canary = bool(self.config.health_check_cmd)
                self._transition(MigrationState.SWITCHOVER, commit_decision="PREPARING")
                if use_fenced_canary:
                    try:
                        self.dest.call(
                            "claim_ip_and_resume",
                            restored_pid=self._restored_pid,
                            target_host=self.dest.host,
                            config_dict=cfg_dict,
                            migration_id=self.migration_id,
                            fenced_canary=True,
                        )
                        self._fenced_canary_active = True
                    except TypeError:
                        self.dest.call(
                            "claim_ip_and_resume",
                            restored_pid=self._restored_pid,
                            target_host=self.dest.host,
                            config_dict=cfg_dict,
                            migration_id=self.migration_id,
                        )
                else:
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
                verify_kwargs: Dict[str, object] = {
                    "restored_pid": self._restored_pid,
                    "health_check_cmd": self.config.health_check_cmd,
                    "timeout_sec": self.config.health_check_timeout_sec,
                    "migration_id": self.migration_id,
                }
                if self._restored_starttime is not None:
                    verify_kwargs["expected_restored_starttime"] = self._restored_starttime
                try:
                    verify_res = self.dest.call("verify_process", **verify_kwargs)
                except TypeError:
                    verify_kwargs.pop("expected_restored_starttime", None)
                    verify_res = self.dest.call("verify_process", **verify_kwargs)
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
        self._transition(MigrationState.SWITCHOVER, commit_decision="COMMIT_DECIDED")
        self.dest.call(
            "claim_ip_and_resume",
            restored_pid=self._restored_pid,
            target_host=self.dest.host,
            config_dict=cfg_dict,
            migration_id=self.migration_id,
        )
        if self._freeze_start_ts is not None and self._freeze_downtime_ms == 0.0:
            self._freeze_downtime_ms = (time.monotonic() - self._freeze_start_ts) * 1000.0
        self._transition(MigrationState.VERIFY, commit_decision="COMMIT_DECIDED")
        verify_kwargs: Dict[str, object] = {
            "restored_pid": self._restored_pid,
            "health_check_cmd": self.config.health_check_cmd,
            "timeout_sec": self.config.health_check_timeout_sec,
            "migration_id": self.migration_id,
        }
        if self._restored_starttime is not None:
            verify_kwargs["expected_restored_starttime"] = self._restored_starttime
        try:
            verify_res = self.dest.call("verify_process", **verify_kwargs)
        except TypeError:
            verify_kwargs.pop("expected_restored_starttime", None)
            verify_res = self.dest.call("verify_process", **verify_kwargs)
        if not verify_res.get("healthy"):
            raise RuntimeError(
                f"Destination verification failed: {verify_res.get('reason')}"
            )

    def commit(self) -> MigrationResult:
        """
        Execute Phase 9 (`COMMIT`): record durable COMMITTED decision in WAL, terminate the
        frozen source process on Host A (waiting for lazy-pages completion on LAZY/HYBRID),
        and wipe checkpoint images.
        Once `COMMIT_DECIDED` / `COMMITTED` is recorded, post-commit errors never trigger rollback.
        """
        cfg_dict = config_to_dict(self.config)
        if self._fenced_canary_active or bool(self.config.health_check_cmd):
            try:
                self.dest.call(
                    "finalize_canary_network",
                    target_host=self.dest.host,
                    config_dict=cfg_dict,
                    migration_id=self.migration_id,
                )
                self._fenced_canary_active = False
            except Exception:
                pass

        if self.config.strategy in (MigrationStrategy.LAZY, MigrationStrategy.HYBRID):
            lazy_done = True
            try:
                wait_res = self.dest.call(
                    "wait_lazy_transfer",
                    migration_id=self.migration_id,
                    timeout_sec=self.config.lazy_transfer_timeout_sec,
                )
                if isinstance(wait_res, dict) and "exited" in wait_res:
                    lazy_done = bool(wait_res.get("exited"))
            except Exception:
                lazy_done = False

            if lazy_done:
                self._transition(MigrationState.COMMIT, commit_decision="COMMITTED")
                try:
                    self.source.call(
                        "commit_source",
                        migration_id=self.migration_id,
                        config_dict=cfg_dict,
                        lazy_transfer_confirmed_by_dest=True,
                    )
                except TypeError:
                    self.source.call(
                        "commit_source",
                        migration_id=self.migration_id,
                        config_dict=cfg_dict,
                    )
                try:
                    self.dest.call(
                        "cleanup_dest",
                        migration_id=self.migration_id,
                        wipe_images=self.config.wipe_images_on_commit,
                    )
                except Exception:
                    pass
            else:
                self._transition(
                    MigrationState.COMMIT,
                    commit_decision="COMMITTED",
                    note="lazy_transfer_pending",
                )
                self.source.call(
                    "commit_source",
                    migration_id=self.migration_id,
                    config_dict=cfg_dict,
                )
        else:
            self._transition(MigrationState.COMMIT, commit_decision="COMMITTED")
            self.source.call(
                "commit_source",
                migration_id=self.migration_id,
                config_dict=cfg_dict,
            )
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
            rb_kwargs: Dict[str, object] = {
                "migration_id": self.migration_id,
                "restored_pid": self._restored_pid,
                "config_dict": cfg_dict,
            }
            if self._restored_starttime is not None:
                rb_kwargs["expected_restored_starttime"] = self._restored_starttime
            try:
                dest_res = self.dest.call("rollback_dest", **rb_kwargs)
            except TypeError:
                rb_kwargs.pop("expected_restored_starttime", None)
                dest_res = self.dest.call("rollback_dest", **rb_kwargs)
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
        """
        Run the complete migration state machine:
        - Without `--health-cmd`: strict 2PC stopped-barrier cutover (`COMMIT_DECIDED` is fsynced to WAL
          and Source A is fenced/committed BEFORE Destination B executes any instruction).
        - With `--health-cmd`: Destination B probes inside a loopback-only network fence prior to `COMMIT`.
        """
        if not self.config.health_check_cmd:
            prep = self.execute_prepare_phase(defer_switchover_until_commit=True)
            if not prep.success or prep.final_state != MigrationState.RESTORE:
                return prep
            try:
                self._transition(MigrationState.SWITCHOVER, commit_decision="COMMIT_DECIDED")
                cfg_dict = config_to_dict(self.config)
                self.source.call(
                    "commit_source",
                    migration_id=self.migration_id,
                    config_dict=cfg_dict,
                )
                self.dest.call(
                    "claim_ip_and_resume",
                    restored_pid=self._restored_pid,
                    target_host=self.dest.host,
                    config_dict=cfg_dict,
                    migration_id=self.migration_id,
                )
                if self._freeze_start_ts is not None and self._freeze_downtime_ms == 0.0:
                    self._freeze_downtime_ms = (time.monotonic() - self._freeze_start_ts) * 1000.0
                self._transition(MigrationState.VERIFY, commit_decision="COMMIT_DECIDED")
                verify_kwargs: Dict[str, object] = {
                    "restored_pid": self._restored_pid,
                    "health_check_cmd": None,
                    "timeout_sec": self.config.health_check_timeout_sec,
                    "migration_id": self.migration_id,
                }
                if self._restored_starttime is not None:
                    verify_kwargs["expected_restored_starttime"] = self._restored_starttime
                try:
                    verify_res = self.dest.call("verify_process", **verify_kwargs)
                except TypeError:
                    verify_kwargs.pop("expected_restored_starttime", None)
                    verify_res = self.dest.call("verify_process", **verify_kwargs)
                if not verify_res.get("healthy"):
                    raise RuntimeError(
                        f"Destination post-cutover verification failed: {verify_res.get('reason')}"
                    )
                return self.commit()
            except Exception as exc:
                return MigrationResult(
                    migration_id=self.migration_id,
                    success=False,
                    final_state=MigrationState.ABORTED,
                    restored_pid=self._restored_pid,
                    total_duration_ms=round((time.monotonic() - self._t_start) * 1000.0, 2),
                    freeze_downtime_ms=round(self._freeze_downtime_ms, 2),
                    precopy_iterations=list(self._precopy_stats),
                    rolled_back=False,
                    error_message=f"Post-commit cutover error (reconcile via recover): {exc}",
                    state_history=list(self.state_history),
                )

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
        *,
        require_persistent_journal: bool = True,
    ) -> MigrationResult:
        """
        Recover an interrupted migration from its durable Write-Ahead Log (`.wal.jsonl`):
        - If this member belongs to a 2PC gang (`gang_id` recorded in WAL or matching sibling
          `<gang_id>.gang.wal.jsonl`), consults the authoritative gang WAL FIRST so a crash
          between `GangJournal` `COMMIT_DECIDED`/`COMMITTED` and member WAL never rolls back a
          committed gang member (fails closed if the referenced gang WAL is missing).
        - Uses `effective_config_dict` so runtime profile enrichment and `HYBRID` upgrades survive crash.
        - Inspects actual Destination B process state: if B is alive and still stopped (`still_stopped=True`),
          wakes B via `complete_switchover_and_verify()` and verifies B is running before reporting success.
        - Otherwise, deterministically executes `rollback()` so Source A resumes safely.
        """
        j_path = Path(journal_path)
        journal = MigrationJournal.load(j_path, require_persistent=require_persistent_journal)
        cfg_dict = journal.effective_config_dict
        if cfg_dict is None:
            raise ValueError(f"Journal {journal_path} does not contain migration configuration")

        coupled_gang_id = journal.coupled_gang_id
        if coupled_gang_id is None:
            m_gang = re.match(r"^(.+)-m\d+$", journal.migration_id)
            if m_gang:
                candidate_gang = m_gang.group(1)
                if (j_path.parent / f"{candidate_gang}.gang.wal.jsonl").exists():
                    coupled_gang_id = candidate_gang

        should_commit = journal.has_committed_decision
        if coupled_gang_id is not None:
            gang_wal_path = j_path.parent / f"{coupled_gang_id}.gang.wal.jsonl"
            if not gang_wal_path.exists():
                raise FileNotFoundError(
                    f"Cannot recover gang member {journal.migration_id!r}: authoritative gang WAL "
                    f"is missing at {gang_wal_path} (refusing independent decision)"
                )
            gang_journal = MigrationJournal.load(
                gang_wal_path, require_persistent=require_persistent_journal
            )
            should_commit = gang_journal.has_committed_decision

        config = config_from_dict(cfg_dict)
        orch = cls(
            config=config,
            source_client=source_client,
            dest_client=dest_client,
            migration_id=journal.migration_id,
            journal_dir=j_path.parent,
            gang_id=coupled_gang_id,
            require_persistent_journal=require_persistent_journal,
        )
        orch._t_start = time.monotonic()
        for entry in reversed(journal.entries):
            if entry.restored_pid is not None:
                orch._restored_pid = entry.restored_pid
                orch._restored_starttime = entry.restored_starttime
                break
        orch.state_history = [MigrationState(e.state) for e in journal.entries]
        if orch.state_history:
            orch.state = orch.state_history[-1]

        if should_commit:
            verify_kwargs: Dict[str, object] = {
                "restored_pid": orch._restored_pid,
                "health_check_cmd": None,
                "migration_id": orch.migration_id,
            }
            if orch._restored_starttime is not None:
                verify_kwargs["expected_restored_starttime"] = orch._restored_starttime
            try:
                pre_verify = dest_client.call("verify_process", **verify_kwargs)
            except TypeError:
                verify_kwargs.pop("expected_restored_starttime", None)
                pre_verify = dest_client.call("verify_process", **verify_kwargs)

            if not pre_verify.get("healthy"):
                if pre_verify.get("still_stopped") is True:
                    try:
                        orch.source.call(
                            "commit_source",
                            migration_id=orch.migration_id,
                            config_dict=config_to_dict(orch.config),
                        )
                        orch.complete_switchover_and_verify()
                        return orch.commit()
                    except Exception as exc:
                        return MigrationResult(
                            migration_id=orch.migration_id,
                            success=False,
                            final_state=MigrationState.ABORTED,
                            rolled_back=False,
                            error_message=f"Roll-forward wakeup of stopped destination failed: {exc}",
                            state_history=list(orch.state_history),
                        )
                return MigrationResult(
                    migration_id=orch.migration_id,
                    success=False,
                    final_state=MigrationState.ABORTED,
                    rolled_back=False,
                    error_message=(
                        "Refusing roll-forward commit before killing source: "
                        f"{pre_verify.get('reason')}"
                    ),
                    state_history=list(orch.state_history),
                )

            was_prepared_stopped = any(
                e.commit_decision == "PREPARED_STOPPED" for e in journal.entries
            )
            already_resumed = any(
                e.state == MigrationState.VERIFY.value
                and e.commit_decision in ("COMMIT_DECIDED", "COMMITTED")
                for e in journal.entries
            )
            if was_prepared_stopped and not already_resumed:
                try:
                    orch.source.call(
                        "commit_source",
                        migration_id=orch.migration_id,
                        config_dict=config_to_dict(orch.config),
                    )
                    orch.complete_switchover_and_verify()
                except Exception as exc:
                    return MigrationResult(
                        migration_id=orch.migration_id,
                        success=False,
                        final_state=MigrationState.ABORTED,
                        rolled_back=False,
                        error_message=f"Roll-forward switchover failed: {exc}",
                        state_history=list(orch.state_history),
                    )
            return orch.commit()

        # If a prior recovery already completed rollback and recorded ROLLED_BACK, avoid
        # re-signaling a stale restored_pid on Destination B (which may have been recycled).
        if journal.has_rolled_back_decision:
            orch._restored_pid = None
            orch._restored_starttime = None

        return orch.rollback("Controller crash recovery: no COMMITTED record in WAL")
