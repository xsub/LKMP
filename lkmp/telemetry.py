"""Prometheus metrics exporter and rich terminal report renderer for LKMP."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Tuple

from lkmp.models import MigrationResult, MigrationState, PreflightReport, ResourceClassification


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
