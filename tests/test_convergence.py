"""Tests for iterative pre-copy stopping criteria and convergence math."""

from __future__ import annotations

import unittest

from lkmp.convergence import PreCopyConvergenceTracker


class TestPreCopyConvergence(unittest.TestCase):
    def test_converges_when_dirty_bytes_within_target_downtime_budget(self) -> None:
        # 1000 Mbps = 125 MB/s; 200 ms budget = 25,000,000 bytes
        tracker = PreCopyConvergenceTracker(
            bandwidth_mbps=1000.0,
            target_downtime_ms=200,
            min_shrink_ratio=0.10,
            max_iterations=8,
        )
        self.assertEqual(tracker.target_threshold_bytes, 25_000_000)

        d1 = tracker.evaluate(iteration=1, dirty_bytes=100_000_000)
        self.assertFalse(d1.should_stop)
        self.assertFalse(d1.converged)

        d2 = tracker.evaluate(iteration=2, dirty_bytes=20_000_000)
        self.assertTrue(d2.should_stop)
        self.assertTrue(d2.converged)

    def test_stops_early_when_dirty_set_shrinks_less_than_ten_percent(self) -> None:
        tracker = PreCopyConvergenceTracker(
            bandwidth_mbps=1000.0,
            target_downtime_ms=200,
            min_shrink_ratio=0.10,
            max_iterations=8,
        )
        d1 = tracker.evaluate(iteration=1, dirty_bytes=100_000_000)
        self.assertFalse(d1.should_stop)

        # Only 5% reduction (95 MB vs 100 MB) -> < 10% shrink threshold
        d2 = tracker.evaluate(iteration=2, dirty_bytes=95_000_000)
        self.assertTrue(d2.should_stop)
        self.assertFalse(d2.converged)
        self.assertIn("not converging", d2.reason)

    def test_stops_at_max_iterations(self) -> None:
        tracker = PreCopyConvergenceTracker(
            bandwidth_mbps=1000.0,
            target_downtime_ms=10,
            min_shrink_ratio=0.10,
            max_iterations=3,
        )
        self.assertFalse(tracker.evaluate(1, 200_000_000).should_stop)
        self.assertFalse(tracker.evaluate(2, 100_000_000).should_stop)
        d3 = tracker.evaluate(3, 50_000_000)
        self.assertTrue(d3.should_stop)
        self.assertFalse(d3.converged)
        self.assertIn("max pre-copy iterations", d3.reason)


if __name__ == "__main__":
    unittest.main()
