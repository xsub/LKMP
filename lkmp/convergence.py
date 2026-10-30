"""Iterative pre-copy convergence calculator & asymptotic hot-working-set floor predictor."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass
class ConvergenceDecision:
    """Decision whether to stop iterative pre-copy and proceed to Freeze + FinalDump."""

    should_stop: bool
    converged: bool
    reason: str
    threshold_bytes: int
    predicted_floor_bytes: Optional[int] = None
    recommend_hybrid_upgrade: bool = False


class PreCopyConvergenceTracker:
    """
    Evaluates iterative pre-copy stopping criteria after each pre-dump round,
    including asymptotic hot-working-set floor prediction (`D_inf`).
    """

    def __init__(
        self,
        bandwidth_mbps: float = 1000.0,
        target_downtime_ms: int = 200,
        min_shrink_ratio: float = 0.10,
        max_iterations: int = 8,
        compression_ratio: float = 1.0,
    ) -> None:
        self.bandwidth_mbps = bandwidth_mbps
        self.target_downtime_ms = target_downtime_ms
        self.min_shrink_ratio = min_shrink_ratio
        self.max_iterations = max_iterations
        self.compression_ratio = max(1.0, compression_ratio)
        self._history: List[int] = []

    @property
    def target_threshold_bytes(self) -> int:
        """Maximum dirty bytes transferable within `target_downtime_ms` at effective bandwidth."""
        bytes_per_sec = ((self.bandwidth_mbps * 1_000_000.0) / 8.0) * self.compression_ratio
        return int(bytes_per_sec * (self.target_downtime_ms / 1000.0))

    def predict_asymptotic_floor(self) -> Optional[int]:
        """
        Estimate the asymptotic hot-working-set floor `D_inf` from 3 consecutive points
        `(D_{k-2}, D_{k-1}, D_k)` under exponential decay `D(t) = D_inf + A * r^t`.
        Returns None if the series is not decelerating toward a positive plateau.
        """
        if len(self._history) < 3:
            return None
        d0, d1, d2 = self._history[-3], self._history[-2], self._history[-1]
        delta1 = d0 - d1
        delta2 = d1 - d2
        # Requires strictly decreasing values where the step size is shrinking (0 < delta2 < delta1)
        if delta1 <= 0 or delta2 <= 0 or delta2 >= delta1:
            return None
        denom = d0 - 2 * d1 + d2
        if denom <= 0:
            return None
        d_inf = (d0 * d2 - d1 * d1) / float(denom)
        return max(0, int(d_inf))

    def evaluate(self, iteration: int, dirty_bytes: int) -> ConvergenceDecision:
        """
        Decide whether to stop pre-copy after `iteration` (1-indexed).

        Stopping conditions:
        1. dirty_bytes <= effective_bandwidth * target_downtime  (converged)
        2. dirty set shrank by < min_shrink_ratio (default 10%) vs previous round
        3. Asymptotic floor predictor `D_inf > threshold` and current `dirty_bytes` is within 15% of `D_inf`
           (knee-of-curve reached; further pre-dump rounds will only re-copy hot thrashing pages)
        4. iteration >= max_iterations (default 8)
        """
        threshold = self.target_threshold_bytes
        prev_dirty = self._history[-1] if self._history else None
        self._history.append(dirty_bytes)
        floor = self.predict_asymptotic_floor()

        if dirty_bytes <= threshold:
            return ConvergenceDecision(
                should_stop=True,
                converged=True,
                reason=(
                    f"Dirty set ({dirty_bytes} B) is within target downtime budget "
                    f"({threshold} B)"
                ),
                threshold_bytes=threshold,
                predicted_floor_bytes=floor,
            )

        if prev_dirty is not None and prev_dirty > 0:
            shrink_ratio = (prev_dirty - dirty_bytes) / float(prev_dirty)
            if shrink_ratio < self.min_shrink_ratio:
                return ConvergenceDecision(
                    should_stop=True,
                    converged=False,
                    reason=(
                        f"Dirty set shrank by {shrink_ratio * 100:.1f}% "
                        f"(< {self.min_shrink_ratio * 100:.1f}% threshold); "
                        "not converging further"
                    ),
                    threshold_bytes=threshold,
                    predicted_floor_bytes=floor,
                    recommend_hybrid_upgrade=True,
                )

        # SOTA Knee-of-Curve detection via asymptotic floor prediction
        if floor is not None and floor > threshold and dirty_bytes <= int(floor * 1.20):
            return ConvergenceDecision(
                should_stop=True,
                converged=False,
                reason=(
                    f"Reached knee of curve: predicted hot-page floor ({floor} B) "
                    f"exceeds downtime budget ({threshold} B)"
                ),
                threshold_bytes=threshold,
                predicted_floor_bytes=floor,
                recommend_hybrid_upgrade=True,
            )

        if iteration >= self.max_iterations:
            return ConvergenceDecision(
                should_stop=True,
                converged=False,
                reason=f"Reached max pre-copy iterations ({self.max_iterations})",
                threshold_bytes=threshold,
                predicted_floor_bytes=floor,
                recommend_hybrid_upgrade=True,
            )

        return ConvergenceDecision(
            should_stop=False,
            converged=False,
            reason=f"Continuing pre-copy (dirty={dirty_bytes} B > threshold={threshold} B)",
            threshold_bytes=threshold,
            predicted_floor_bytes=floor,
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
