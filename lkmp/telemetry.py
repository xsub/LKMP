"""Prometheus metrics exporter and rich terminal report renderer for LKMP."""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any, Dict, List, Tuple

from lkmp.models import (
    MigrationResult,
    PortabilityReport,
    PreflightReport,
)


class PrometheusMetricsCollector:
    """Thread-safe OpenMetrics / Prometheus metrics collector for `lkmp-agent` and controller."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.migrations_by_label: Dict[Tuple[str, str], int] = defaultdict(int)
        self.rollbacks_total: int = 0
        self.last_freeze_downtime_ms: float = 0.0
        self.last_total_duration_ms: float = 0.0
        self.last_precopy_rounds: int = 0
        self.precopy_dirty_bytes_total: int = 0
        self.rpc_requests_by_method: Dict[str, int] = defaultdict(int)
        self.rpc_errors_by_method: Dict[str, int] = defaultdict(int)
        self.rpc_duration_ms_by_method: Dict[str, float] = defaultdict(float)
        self.active_migrations: int = 0

    def record_migration(self, strategy: str, result: MigrationResult) -> None:
        with self._lock:
            self.migrations_by_label[(strategy, result.final_state.value)] += 1
            if result.rolled_back:
                self.rollbacks_total += 1
            self.last_freeze_downtime_ms = result.freeze_downtime_ms
            self.last_total_duration_ms = result.total_duration_ms
            self.last_precopy_rounds = len(result.precopy_iterations)
            for it in result.precopy_iterations:
                self.precopy_dirty_bytes_total += it.dirty_bytes

    def record_rpc(self, method: str, duration_ms: float, error: bool = False) -> None:
        with self._lock:
            self.rpc_requests_by_method[method] += 1
            self.rpc_duration_ms_by_method[method] += max(0.0, duration_ms)
            if error:
                self.rpc_errors_by_method[method] += 1

    def set_active_migrations(self, count: int) -> None:
        with self._lock:
            self.active_migrations = max(0, int(count))

    def export_prometheus_text(self) -> str:
        """Render collected telemetry in standard Prometheus / OpenMetrics text format."""
        with self._lock:
            mig_items = sorted(self.migrations_by_label.items())
            rollbacks = self.rollbacks_total
            last_freeze = self.last_freeze_downtime_ms
            last_total = self.last_total_duration_ms
            last_rounds = self.last_precopy_rounds
            dirty_total = self.precopy_dirty_bytes_total
            rpc_reqs = sorted(self.rpc_requests_by_method.items())
            rpc_errs = sorted(self.rpc_errors_by_method.items())
            rpc_durs = sorted(self.rpc_duration_ms_by_method.items())
            active_migs = self.active_migrations

        lines: List[str] = [
            "# HELP lkmp_migrations_total Total process migrations attempted by strategy and final state.",
            "# TYPE lkmp_migrations_total counter",
        ]
        for (strategy, state), count in mig_items:
            lines.append(
                f'lkmp_migrations_total{{strategy="{strategy}",final_state="{state}"}} {count}'
            )
        lines.extend(
            [
                "# HELP lkmp_rollbacks_total Total migrations that triggered transactional rollback.",
                "# TYPE lkmp_rollbacks_total counter",
                f"lkmp_rollbacks_total {rollbacks}",
                "# HELP lkmp_last_freeze_downtime_milliseconds Freeze window downtime of the most recent migration.",
                "# TYPE lkmp_last_freeze_downtime_milliseconds gauge",
                f"lkmp_last_freeze_downtime_milliseconds {last_freeze:.2f}",
                "# HELP lkmp_last_total_duration_milliseconds Total wall-clock duration of the most recent migration.",
                "# TYPE lkmp_last_total_duration_milliseconds gauge",
                f"lkmp_last_total_duration_milliseconds {last_total:.2f}",
                "# HELP lkmp_last_precopy_rounds Number of iterative pre-dump rounds in the most recent migration.",
                "# TYPE lkmp_last_precopy_rounds gauge",
                f"lkmp_last_precopy_rounds {last_rounds}",
                "# HELP lkmp_precopy_dirty_bytes_total Cumulative dirty memory bytes streamed across pre-dump rounds.",
                "# TYPE lkmp_precopy_dirty_bytes_total counter",
                f"lkmp_precopy_dirty_bytes_total {dirty_total}",
                "# HELP lkmp_active_migrations Currently frozen/in-flight source migrations on this agent.",
                "# TYPE lkmp_active_migrations gauge",
                f"lkmp_active_migrations {active_migs}",
                "# HELP lkmp_rpc_requests_total Total control-plane RPC requests handled by method.",
                "# TYPE lkmp_rpc_requests_total counter",
            ]
        )
        for method, count in rpc_reqs:
            lines.append(f'lkmp_rpc_requests_total{{method="{method}"}} {count}')
        lines.extend(
            [
                "# HELP lkmp_rpc_errors_total Total control-plane RPC errors by method.",
                "# TYPE lkmp_rpc_errors_total counter",
            ]
        )
        for method, count in rpc_errs:
            lines.append(f'lkmp_rpc_errors_total{{method="{method}"}} {count}')
        lines.extend(
            [
                "# HELP lkmp_rpc_duration_milliseconds_total Cumulative RPC execution duration in milliseconds by method.",
                "# TYPE lkmp_rpc_duration_milliseconds_total counter",
            ]
        )
        for method, dur in rpc_durs:
            lines.append(f'lkmp_rpc_duration_milliseconds_total{{method="{method}"}} {dur:.2f}')
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
        "│ LKMP PREFLIGHT COMPATIBILITY SCORECARD                                   │",
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


def render_gang_migration_report(result: Any) -> str:
    """Render a terminal summary table for `lkmp gang-migrate` or `lkmp recover --gang-journal`."""
    data = result.to_dict() if hasattr(result, "to_dict") else dict(result)
    gang_id = str(data.get("gang_id", "unknown"))
    all_committed = bool(data.get("all_committed"))
    rollback_triggered = bool(data.get("atomic_rollback_triggered"))
    outcome = (
        "ALL MEMBERS COMMITTED (2PC)"
        if all_committed
        else ("ATOMIC ROLLBACK COMPLETE" if rollback_triggered else "PARTIAL / ERROR")
    )
    members = data.get("member_results") or []
    dur_str = f"{float(data.get('total_duration_ms', 0.0)):.2f} ms"
    lines = [
        "┌──────────────────────────────────────────────────────────────────────────┐",
        "│ LKMP 2PC GANG MIGRATION SUMMARY                                          │",
        "├──────────────────────────────┬───────────────────────────────────────────┤",
        f"│ Gang ID                      │ {gang_id:<41} │",
        f"│ Outcome                      │ {outcome:<41} │",
        f"│ Member Count                 │ {len(members):<41} │",
        f"│ Total Duration               │ {dur_str:<41} │",
        "└──────────────────────────────┴───────────────────────────────────────────┘",
    ]
    if members:
        lines.append("\nMembers:")
        for idx, m in enumerate(members):
            mid = m.get("migration_id", f"m{idx}")
            st = m.get("final_state", "unknown")
            rpid = m.get("restored_pid")
            rpid_str = f"restored_pid={rpid}" if rpid is not None else "source_active"
            lines.append(f"  • [{idx}] {mid}: state={st} ({rpid_str})")
    if data.get("failed_member_index") is not None:
        lines.append(
            f"\nFailure Index {data['failed_member_index']}: {data.get('failure_reason') or 'unknown'}"
        )
    return "\n".join(lines)


def render_wal_inspection_report(report: Any) -> str:
    """Render a terminal diagnostic summary for `lkmp wal-inspect`."""
    data = report.to_dict() if hasattr(report, "to_dict") else dict(report)
    verdict = "VALID" if data.get("valid") else "CORRUPTED / INCOMPLETE"
    csum_ok = "OK" if (data.get("checksums_ok") and data.get("monotonic_seq_ok")) else "FAIL"
    rpid_val = data.get("restored_pid")
    rpid_str = (
        f"{rpid_val} ({data.get('restored_starttime')})"
        if rpid_val is not None
        else "none"
    )
    lines = [
        "┌──────────────────────────────────────────────────────────────────────────┐",
        "│ LKMP WAL JOURNAL DIAGNOSTIC REPORT                                       │",
        "├──────────────────────────────┬───────────────────────────────────────────┤",
        f"│ Verdict                      │ {verdict:<41} │",
        f"│ Migration / Gang ID          │ {str(data.get('migration_id') or 'N/A'):<41} │",
        f"│ Coupled Gang ID              │ {str(data.get('coupled_gang_id') or 'none'):<41} │",
        f"│ Valid Entries                │ {int(data.get('entry_count', 0)):<41} │",
        f"│ Checksums & Monotonic Seq    │ {csum_ok:<41} │",
        f"│ Discarded Torn Tail          │ {str(bool(data.get('discarded_torn_tail'))):<41} │",
        f"│ Last Commit Decision         │ {str(data.get('last_commit_decision') or 'N/A'):<41} │",
        f"│ Restored PID (starttime)     │ {rpid_str:<41} │",
        "└──────────────────────────────┴───────────────────────────────────────────┘",
    ]
    if data.get("expected_member_ids"):
        lines.append(f"\nExpected Gang Members: {', '.join(data['expected_member_ids'])}")
    if data.get("missing_member_wals"):
        lines.append("Missing Member WALs:")
        for p in data["missing_member_wals"]:
            lines.append(f"  • {p}")
    if data.get("entries"):
        lines.append("\nJournal Sequence:")
        for e in data["entries"]:
            lines.append(
                f"  seq={e['seq']:>2} | decision={e['commit_decision']:<16} | state={e['state']:<18} | sha256={e['checksum_prefix']}..."
            )
    if data.get("corruption_error"):
        lines.append(f"\nDiagnostic Error:\n  {data['corruption_error']}")
    return "\n".join(lines)


def render_agent_status_report(status: Dict[str, Any]) -> str:
    """Render a formatted terminal scorecard for `lkmp status`."""
    caps = status.get("capabilities") or {}
    free_b = caps.get("work_dir_free_bytes")
    free_str = format_bytes(int(free_b)) if isinstance(free_b, int) else "unknown"
    arch_kern = f"{caps.get('arch', '?')} / {caps.get('kernel_release', '?')}"
    criu_str = f"{caps.get('criu_available', False)} ({caps.get('criu_version') or 'N/A'})"
    lines = [
        "┌──────────────────────────────────────────────────────────────────────────┐",
        "│ LKMP AGENT NODE HEALTH & CAPABILITIES                                    │",
        "├──────────────────────────────┬───────────────────────────────────────────┤",
        f"│ Status                       │ {str(status.get('status', 'unknown')).upper():<41} │",
        f"│ Hostname                     │ {str(caps.get('hostname', status.get('hostname', 'unknown'))):<41} │",
        f"│ Architecture / Kernel        │ {arch_kern:<41} │",
        f"│ CRIU Available / Version     │ {criu_str:<41} │",
        f"│ Active Frozen Migrations     │ {str(status.get('active_migrations', 0)):<41} │",
        f"│ Work Dir Free Space          │ {free_str:<41} │",
        "└──────────────────────────────┴───────────────────────────────────────────┘",
    ]
    return "\n".join(lines)


def render_workload_doctor_report(diag: Dict[str, Any]) -> str:
    """Render a terminal advisor scorecard for `lkmp doctor`."""
    kind = str(diag.get("kind", "posix")).upper()
    subkind = str(diag.get("subkind") or "generic")
    driver = str(diag.get("recommended_driver", "criu"))
    ready = "READY (SEAMLESS)" if diag.get("ready") else "ACTION REQUIRED"
    zc = "YES (MSG_ZEROCOPY / memfd / reflink)" if diag.get("zero_copy_capable") else "PARTIAL / STANDARD"
    ctrl = str(diag.get("control_socket") or diag.get("container_id") or "none")
    if len(ctrl) > 41:
        ctrl = "..." + ctrl[-38:]

    lines = [
        "┌──────────────────────────────────────────────────────────────────────────┐",
        "│ LKMP WORKLOAD RUNTIME FINGERPRINT & PORTING DOCTOR                       │",
        "├──────────────────────────────┬───────────────────────────────────────────┤",
        f"│ Target PID                   │ {str(diag.get('pid', '?')):<41} │",
        f"│ Detected Runtime Kind        │ {f'{kind} ({subkind})':<41} │",
        f"│ Recommended LKMP Driver      │ {driver:<41} │",
        f"│ Readiness Verdict            │ {ready:<41} │",
        f"│ Zero-Copy Capable            │ {zc:<41} │",
        f"│ Control Socket / Handle      │ {ctrl:<41} │",
        "└──────────────────────────────┴───────────────────────────────────────────┘",
    ]
    blockers = diag.get("blockers") or []
    if blockers:
        lines.append("\nPorting Blockers:")
        for b in blockers:
            lines.append(f"  ✗ {b}")
    warnings = diag.get("warnings") or []
    if warnings:
        lines.append("\nZero-Copy & Low-Latency Warnings:")
        for w in warnings:
            lines.append(f"  ! {w}")
    recs = diag.get("recommended_launch_flags") or []
    if recs:
        lines.append("\nRecommended Launch Flags for Seamless Porting:")
        for r in recs:
            lines.append(f"  → {r}")
    return "\n".join(lines)
