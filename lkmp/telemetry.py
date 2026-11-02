"""Prometheus metrics exporter and rich terminal report renderer for LKMP."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Tuple

from lkmp.models import (
    MigrationResult,
    MigrationState,
    PortabilityReport,
    PortabilityStatus,
    PreflightReport,
    ResourceClassification,
)


class PrometheusMetricsCollector:
    """In-memory OpenMetrics / Prometheus metrics collector for `lkmp-agent` and controller."""

    def __init__(self) -> None:
        self.migrations_by_label: Dict[Tuple[str, str], int] = defaultdict(int)
        self.rollbacks_total: int = 0
        self.last_freeze_downtime_ms: float = 0.0
        self.last_total_duration_ms: float = 0.0
        self.last_precopy_rounds: int = 0
        self.precopy_dirty_bytes_total: int = 0

    def record_migration(self, strategy: str, result: MigrationResult) -> None:
        self.migrations_by_label[(strategy, result.final_state.value)] += 1
        if result.rolled_back:
            self.rollbacks_total += 1
        self.last_freeze_downtime_ms = result.freeze_downtime_ms
        self.last_total_duration_ms = result.total_duration_ms
        self.last_precopy_rounds = len(result.precopy_iterations)
        for it in result.precopy_iterations:
            self.precopy_dirty_bytes_total += it.dirty_bytes

    def export_prometheus_text(self) -> str:
        """Render collected telemetry in standard Prometheus / OpenMetrics text format."""
        lines: List[str] = [
            "# HELP lkmp_migrations_total Total process migrations attempted by strategy and final state.",
            "# TYPE lkmp_migrations_total counter",
        ]
        for (strategy, state), count in sorted(self.migrations_by_label.items()):
            lines.append(
                f'lkmp_migrations_total{{strategy="{strategy}",final_state="{state}"}} {count}'
            )
        lines.extend(
            [
                "# HELP lkmp_rollbacks_total Total migrations that triggered transactional rollback.",
                "# TYPE lkmp_rollbacks_total counter",
                f"lkmp_rollbacks_total {self.rollbacks_total}",
                "# HELP lkmp_last_freeze_downtime_milliseconds Freeze window downtime of the most recent migration.",
                "# TYPE lkmp_last_freeze_downtime_milliseconds gauge",
                f"lkmp_last_freeze_downtime_milliseconds {self.last_freeze_downtime_ms:.2f}",
                "# HELP lkmp_last_total_duration_milliseconds Total wall-clock duration of the most recent migration.",
                "# TYPE lkmp_last_total_duration_milliseconds gauge",
                f"lkmp_last_total_duration_milliseconds {self.last_total_duration_ms:.2f}",
                "# HELP lkmp_last_precopy_rounds Number of iterative pre-dump rounds in the most recent migration.",
                "# TYPE lkmp_last_precopy_rounds gauge",
                f"lkmp_last_precopy_rounds {self.last_precopy_rounds}",
                "# HELP lkmp_precopy_dirty_bytes_total Cumulative dirty memory bytes streamed across pre-dump rounds.",
                "# TYPE lkmp_precopy_dirty_bytes_total counter",
                f"lkmp_precopy_dirty_bytes_total {self.precopy_dirty_bytes_total}",
            ]
        )
        return "\n".join(lines) + "\n"


def format_bytes(num_bytes: int) -> str:
    if num_bytes >= 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.1f} MiB"
    if num_bytes >= 1024:
        return f"{num_bytes / 1024:.1f} KiB"
    return f"{num_bytes} B"


def render_preflight_scorecard(report: PreflightReport, selected_strategy: str) -> str:
    """Render a formatted terminal scorecard for `lkmp preflight`."""
    verdict = "PASS (COMPATIBLE)" if report.compatible else "FAIL (BLOCKED)"
    lines = [
        "┌──────────────────────────────────────────────────────────────────────────┐",
        f"│ LKMP PREFLIGHT COMPATIBILITY SCORECARD                                   │",
        "├──────────────────────────────┬───────────────────────────────────────────┤",
        f"│ Verdict                      │ {verdict:<41} │",
        f"│ Active Migration Strategy    │ {selected_strategy:<41} │",
        f"│ Est. Cold Stop&Copy Downtime │ {f'{report.estimated_cold_downtime_ms:.1f} ms':<41} │",
        f"│ Est. Live Switchover Window  │ {f'{report.estimated_live_downtime_ms:.1f} ms':<41} │",
        f"│ Auto-Applied CRIU Flags      │ {(', '.join(report.required_criu_flags) or 'none'):<41} │",
        "└──────────────────────────────┴───────────────────────────────────────────┘",
    ]
    if report.findings:
        lines.append("\nFindings:")
        for f in report.findings:
            tag = f.classification.value.upper()
            lines.append(f"  • [{tag}] {f.resource_type} ({f.identifier}): {f.reason}")
    return "\n".join(lines)


def render_migration_report(result: MigrationResult, strategy: str) -> str:
    """Render a detailed terminal dashboard for `lkmp migrate` / `lkmp demo`."""
    outcome = (
        "COMMITTED ON DESTINATION B"
        if result.success
        else ("ROLLED BACK TO SOURCE A (ZERO DATA LOSS)" if result.rolled_back else "ABORTED")
    )
    pid_str = str(result.restored_pid) if result.restored_pid is not None else "N/A (Source A active)"
    lines = [
        "┌──────────────────────────────────────────────────────────────────────────┐",
        "│ LKMP LIVE MIGRATION EXECUTION SUMMARY                                    │",
        "├──────────────────────────────┬───────────────────────────────────────────┤",
        f"│ Migration ID                 │ {result.migration_id:<41} │",
        f"│ Strategy                     │ {strategy:<41} │",
        f"│ Outcome                      │ {outcome:<41} │",
        f"│ Final FSM State              │ {result.final_state.value:<41} │",
        f"│ Restored PID on Host B       │ {pid_str:<41} │",
        f"│ Freeze Window Downtime       │ {f'{result.freeze_downtime_ms:.2f} ms':<41} │",
        f"│ Total Migration Duration     │ {f'{result.total_duration_ms:.2f} ms':<41} │",
        "└──────────────────────────────┴───────────────────────────────────────────┘",
    ]

    if result.precopy_iterations:
        lines.append("\nIterative Pre-Copy Convergence (Online Phase — 0 ms Downtime):")
        max_dirty = max(max(it.dirty_bytes for it in result.precopy_iterations), 1)
        for it in result.precopy_iterations:
            bar_len = max(1, int((it.dirty_bytes / max_dirty) * 24))
            bar = "█" * bar_len + "░" * (24 - bar_len)
            status = "CONVERGED" if it.converged else ("STOPPED" if it.stop_reason else "STREAMED")
            lines.append(
                f"  Round {it.iteration}: [{bar}] {format_bytes(it.dirty_bytes):>10} "
                f"in {it.duration_ms:>6.1f} ms  ({status})"
            )
            if it.stop_reason:
                lines.append(f"           └─ {it.stop_reason}")

    state_chain = " -> ".join(s.value for s in result.state_history)
    lines.append(f"\nFSM Trajectory:\n  {state_chain}")

    if result.error_message:
        lines.append(f"\nFault / Rollback Trigger:\n  {result.error_message}")

    return "\n".join(lines)


def render_portability_report(report: PortabilityReport) -> str:
    """Render a formatted terminal scorecard for process portability across 5 domains."""
    if report.trial_restore_executed:
        depth = "Isolated Trial Restore"
    elif report.check_only_executed:
        depth = "CRIU --check-only"
    else:
        depth = "Static /proc Inspection"

    fast_path = "Available (Same-Host CoW)" if report.same_host_fast_path_available else "Not Available (Cross-Host)"
    status_str = report.overall_status.value

    lines = [
        "┌──────────────────────────────────────────────────────────────────────────────┐",
        "│ LKMP PROCESS PORTABILITY & MIGRATION READINESS                               │",
        "├──────────────────────────────┬───────────────────────────────────────────────┤",
        f"│ Overall Portability Status   │ {status_str:<45} │",
        f"│ Verification Depth           │ {depth:<45} │",
        f"│ Same-Host CoW Fast Path      │ {fast_path:<45} │",
        f"│ Est. Cold Stop&Copy Downtime │ {f'{report.estimated_cold_downtime_ms:.1f} ms':<45} │",
        f"│ Est. Live Switchover Window  │ {f'{report.estimated_live_downtime_ms:.1f} ms':<45} │",
        f"│ Required CRIU Flags          │ {(', '.join(report.required_criu_flags) or 'none'):<45} │",
        "├──────────────────────────────┴───────────────────────────────────────────────┤",
        "│ DOMAIN ASSESSMENT                                                            │",
        "├──────────────────────┬──────────┬────────────────────────────────────────────┤",
        "│ Domain               │ Status   │ Summary & Required Actions                 │",
        "├──────────────────────┼──────────┼────────────────────────────────────────────┤",
    ]

    domain_order = ["memory_and_cpu", "files", "network", "devices", "external_resources"]
    for d_name in domain_order:
        assessment = report.domains.get(d_name)
        if assessment:
            st = assessment.status.value
            summ = assessment.summary
            flags = [f.suggested_flag for f in assessment.findings if f.suggested_flag]
            if flags:
                summ += f" [Flags: {', '.join(flags)}]"
            if len(summ) > 42:
                summ = summ[:39] + "..."
            lines.append(f"│ {d_name:<20} │ {st:<8} │ {summ:<42} │")
        else:
            lines.append(f"│ {d_name:<20} │ UNKNOWN  │ Domain not evaluated                       │")

    lines.append("└──────────────────────┴──────────┴────────────────────────────────────────────┘")

    if report.findings:
        lines.append("\nFindings & Recommended Actions:")
        for f in report.findings:
            tag = f.classification.value.upper()
            flag_info = f" -> suggested flag: {f.suggested_flag}" if f.suggested_flag else ""
            lines.append(f"  • [{tag}] {f.resource_type} ({f.identifier}): {f.reason}{flag_info}")

    return "\n".join(lines)


def _get_val(obj: Any, *keys: str, default: Any = None) -> Any:
    for k in keys:
        if isinstance(obj, dict):
            if k in obj and obj[k] is not None:
                return obj[k]
        else:
            val = getattr(obj, k, None)
            if val is not None:
                return val
    return default


def render_process_set_portability_report(report: Any) -> str:
    """Render a formatted terminal scorecard for multi-process set portability (v2.0)."""
    set_id = str(_get_val(report, "set_id", "migration_id", default="set-unknown"))

    topology = _get_val(report, "topology")
    pointed_pids = _get_val(report, "pointed_pids", "target_pids", "pids", default=[])
    if not pointed_pids and topology:
        pointed_pids = _get_val(topology, "pointed_pids", default=[])

    root_pids = _get_val(report, "root_pids", "disjoint_root_pids", default=[])
    if not root_pids and topology:
        root_pids = _get_val(topology, "root_pids", default=[])

    absorbed_pids = _get_val(report, "absorbed_pids", default=[])
    if not absorbed_pids and topology:
        absorbed_pids = _get_val(topology, "absorbed_pids", default=[])

    exec_mode = _get_val(report, "execution_mode", default=None)
    if not exec_mode and topology:
        exec_mode = _get_val(topology, "execution_mode", default="LOCKSTEP_FOREST")
    if hasattr(exec_mode, "value"):
        exec_mode = exec_mode.value
    exec_mode_str = str(exec_mode or "LOCKSTEP_FOREST")

    overall_status = _get_val(report, "overall_status", "status", default="UNKNOWN")
    if hasattr(overall_status, "value"):
        overall_status = overall_status.value
    overall_status_str = str(overall_status).upper()

    pointed_str = ", ".join(str(p) for p in pointed_pids) or "none"
    roots_str = ", ".join(str(p) for p in root_pids) or "none"
    absorbed_str = ", ".join(str(p) for p in absorbed_pids) or "none"

    lines = [
        "┌──────────────────────────────────────────────────────────────────────────────┐",
        "│ LKMP MULTI-PROCESS SET PORTABILITY REPORT (v2.0)                             │",
        "├──────────────────────────────┬───────────────────────────────────────────────┤",
        f"│ Set ID                       │ {set_id:<45} │",
        f"│ Pointed PIDs                 │ {pointed_str:<45} │",
        f"│ Normalized Disjoint Roots    │ {roots_str:<45} │",
        f"│ Absorbed Descendant PIDs     │ {absorbed_str:<45} │",
        f"│ Execution Mode               │ {exec_mode_str:<45} │",
        f"│ Overall Portability Status   │ {overall_status_str:<45} │",
        "└──────────────────────────────┴───────────────────────────────────────────────┘",
    ]

    edges = _get_val(report, "coupling_edges", "edges", default=[])
    unclosed_peers: List[int] = []
    auto_included = _get_val(report, "auto_included_pids", default=[])

    if edges:
        lines.append("\nKernel Coupling & Resource Closure Edges:")
        for e in edges:
            e_type = _get_val(e, "scope", "edge_type", "coupling_type", default="INTRA_TREE")
            if hasattr(e_type, "value"):
                e_type = e_type.value
            e_type_str = str(e_type).upper()

            src_pid = _get_val(e, "source_pid", "src_pid", default="?")
            tgt_pid = _get_val(e, "target_pid", "peer_pid", "dst_pid", default="?")
            resource = _get_val(e, "resource_type", "resource", "target_resource", default="")
            peer_comm = _get_val(e, "peer_comm", "comm", default="")

            detail = f"{resource}" if resource else ""
            if peer_comm:
                detail += f" (comm: {peer_comm})"

            if e_type_str == "EXTERNAL_UNCLOSED_PEER":
                if tgt_pid not in ("?", None):
                    try:
                        p_int = int(tgt_pid)
                        if p_int not in unclosed_peers:
                            unclosed_peers.append(p_int)
                    except (ValueError, TypeError):
                        pass
                lines.append(f"  • [{e_type_str}] PID {src_pid} -> External Peer PID {tgt_pid}: {detail}")
            elif e_type_str == "INTER_TREE_CLOSED":
                lines.append(f"  • [{e_type_str}] PID {src_pid} <-> PID {tgt_pid}: {detail}")
            else:
                lines.append(f"  • [{e_type_str}] PID {src_pid} -> PID {tgt_pid}: {detail}")

    if unclosed_peers:
        rec_str = ", ".join(str(p) for p in unclosed_peers)
        lines.append(f"\n⚠️  Recommended additional PIDs to close kernel set: {rec_str}")
        lines.append("   (Use `--auto-include-coupled` to automatically include them)")
    elif auto_included:
        inc_str = ", ".join(str(p) for p in auto_included)
        lines.append(f"\nℹ️  Auto-Included Coupled PIDs: {inc_str}")

    root_reports = _get_val(report, "root_reports", "root_snapshots", "root_portability", default={})
    if root_reports:
        lines.append("\nPer-Root Portability Summary:")
        if isinstance(root_reports, dict):
            items = list(root_reports.items())
        else:
            items = [(getattr(r, "root_pid", getattr(r, "pid", i)), r) for i, r in enumerate(root_reports)]
        for r_pid, r_rep in items:
            st = _get_val(r_rep, "overall_status", "status", default="UNKNOWN")
            if hasattr(st, "value"):
                st = st.value
            findings = _get_val(r_rep, "findings", default=[])
            blockers = [f for f in findings if _get_val(f, "classification") in ("blocker", "BLOCKER")]
            lines.append(f"  • Root PID {r_pid}: {str(st).upper()} ({len(findings)} findings, {len(blockers)} blockers)")

    return "\n".join(lines)


def render_process_set_migration_summary(result: Any) -> str:
    """Render a clean ASCII summary table of ProcessSetMigrationResult."""
    set_id = str(_get_val(result, "set_id", "migration_id", default="set-unknown"))

    pointed_pids = _get_val(result, "pointed_pids", "target_pids", "pids", default=[])
    root_pids = _get_val(result, "root_pids", "disjoint_root_pids", default=[])
    absorbed_pids = _get_val(result, "absorbed_pids", default=[])
    auto_included_pids = _get_val(result, "auto_included_pids", "auto_included", default=[])

    success = bool(_get_val(result, "all_committed", "success", default=False))
    rolled_back = bool(_get_val(result, "atomic_rollback_triggered", "rolled_back", default=False))

    if success:
        outcome = "ALL COMMITTED ON DEST B"
    elif rolled_back:
        outcome = "ATOMIC ROLLBACK TO SOURCE A"
    else:
        outcome = str(_get_val(result, "outcome", default="ABORTED"))

    co_freeze_achieved = _get_val(result, "co_freeze_barrier_achieved", "co_freeze_achieved", default=True)
    co_freeze_ms = _get_val(
        result,
        "co_freeze_duration_ms",
        "co_freeze_downtime_ms",
        "freeze_downtime_ms",
        default=None,
    )
    if co_freeze_ms is not None:
        co_freeze_str = (
            f"ACHIEVED ({float(co_freeze_ms):.2f} ms)"
            if co_freeze_achieved
            else f"FAILED ({float(co_freeze_ms):.2f} ms)"
        )
    else:
        co_freeze_str = "ACHIEVED" if co_freeze_achieved else "FAILED"

    merkle_root = str(_get_val(result, "set_merkle_root", "merkle_root", default="N/A"))
    if len(merkle_root) > 42:
        merkle_root = merkle_root[:39] + "..."

    tot_dur = _get_val(result, "total_duration_ms", default=None)
    tot_dur_str = f"{float(tot_dur):.2f} ms" if tot_dur is not None else "N/A"

    pointed_str = ", ".join(str(p) for p in pointed_pids) or "none"
    roots_str = ", ".join(str(p) for p in root_pids) or "none"
    absorbed_str = ", ".join(str(p) for p in absorbed_pids) or "none"
    auto_inc_str = ", ".join(str(p) for p in auto_included_pids) or "none"

    lines = [
        "┌──────────────────────────────────────────────────────────────────────────────┐",
        "│ LKMP MULTI-PROCESS SET LIVE MIGRATION SUMMARY (v2.0)                         │",
        "├──────────────────────────────┬───────────────────────────────────────────────┤",
        f"│ Set ID                       │ {set_id:<45} │",
        f"│ Outcome                      │ {outcome:<45} │",
        f"│ Pointed PIDs                 │ {pointed_str:<45} │",
        f"│ Disjoint Root PIDs           │ {roots_str:<45} │",
        f"│ Absorbed PIDs                │ {absorbed_str:<45} │",
        f"│ Auto-Included Coupled PIDs   │ {auto_inc_str:<45} │",
        f"│ Co-Freeze Barrier            │ {co_freeze_str:<45} │",
        f"│ Set Merkle Root              │ {merkle_root:<45} │",
        f"│ Total Migration Duration     │ {tot_dur_str:<45} │",
        "└──────────────────────────────┴───────────────────────────────────────────────┘",
    ]

    restored = _get_val(result, "restored_root_pids", "restored_pids", default={})
    if restored:
        lines.append("\nRestored Process Roots on Destination Host:")
        if isinstance(restored, dict):
            items = list(restored.items())
        else:
            items = [(i, p) for i, p in enumerate(restored)]
        for r_pid, dest_pid in items:
            status_tag = "COMMITTED" if success else ("ROLLED_BACK" if rolled_back else "FAILED")
            lines.append(f"  • Root PID {r_pid} -> Restored PID {dest_pid} ({status_tag})")

    err = _get_val(result, "error_message", "error", default=None)
    if err:
        lines.append(f"\nFault / Rollback Trigger:\n  {err}")

    return "\n".join(lines)
