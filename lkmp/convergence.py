"""Iterative pre-copy convergence calculator and dirty-page volume tracker."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple


@dataclass
class ConvergenceDecision:
    """Decision whether to stop iterative pre-copy and proceed to Freeze + FinalDump."""

    should_stop: bool
    converged: bool
    reason: str
    threshold_bytes: int


class PreCopyConvergenceTracker:
    """Evaluates iterative pre-copy stopping criteria after each pre-dump round."""

    def __init__(
        self,
        bandwidth_mbps: float = 1000.0,
        target_downtime_ms: int = 200,
        min_shrink_ratio: float = 0.10,
        max_iterations: int = 8,
    ) -> None:
        self.bandwidth_mbps = bandwidth_mbps
        self.target_downtime_ms = target_downtime_ms
        self.min_shrink_ratio = min_shrink_ratio
        self.max_iterations = max_iterations
        self._previous_dirty_bytes: Optional[int] = None

    @property
    def target_threshold_bytes(self) -> int:
        """Maximum dirty bytes transferable within `target_downtime_ms` at `bandwidth_mbps`."""
        bytes_per_sec = (self.bandwidth_mbps * 1_000_000.0) / 8.0
        return int(bytes_per_sec * (self.target_downtime_ms / 1000.0))

    def evaluate(self, iteration: int, dirty_bytes: int) -> ConvergenceDecision:
        """
        Decide whether to stop pre-copy after `iteration` (1-indexed).

        Stopping conditions (Section 3.4 Phase 3):
        1. dirty_bytes <= bandwidth * target_downtime  (converged)
        2. dirty set shrank by < min_shrink_ratio (default 10%) vs previous round
        3. iteration >= max_iterations (default 8)
        """
        threshold = self.target_threshold_bytes

        if dirty_bytes <= threshold:
            self._previous_dirty_bytes = dirty_bytes
            return ConvergenceDecision(
                should_stop=True,
                converged=True,
                reason=(
                    f"Dirty set ({dirty_bytes} B) is within target downtime budget "
                    f"({threshold} B)"
                ),
                threshold_bytes=threshold,
            )

        if self._previous_dirty_bytes is not None and self._previous_dirty_bytes > 0:
            shrink_ratio = (
                self._previous_dirty_bytes - dirty_bytes
            ) / float(self._previous_dirty_bytes)
            if shrink_ratio < self.min_shrink_ratio:
                self._previous_dirty_bytes = dirty_bytes
                return ConvergenceDecision(
                    should_stop=True,
                    converged=False,
                    reason=(
                        f"Dirty set shrank by {shrink_ratio * 100:.1f}% "
                        f"(< {self.min_shrink_ratio * 100:.1f}% threshold); "
                        "not converging further"
                    ),
                    threshold_bytes=threshold,
                )

        self._previous_dirty_bytes = dirty_bytes

        if iteration >= self.max_iterations:
            return ConvergenceDecision(
                should_stop=True,
                converged=False,
                reason=f"Reached max pre-copy iterations ({self.max_iterations})",
                threshold_bytes=threshold,
            )

        return ConvergenceDecision(
            should_stop=False,
            converged=False,
            reason=f"Continuing pre-copy (dirty={dirty_bytes} B > threshold={threshold} B)",
            threshold_bytes=threshold,
        )


def measure_predump_dirty_bytes(images_dir: str | Path) -> int:
    """Measure the volume of memory pages captured in a CRIU pre-dump/dump directory."""
    path = Path(images_dir)
    if not path.exists():
        return 0
    total = 0
    for entry in path.iterdir():
        if entry.is_file() and (
            entry.name.startswith("pages-") or entry.name.startswith("pagemap-")
        ):
            try:
                total += entry.stat().st_size
            except OSError:
                pass
    return total
