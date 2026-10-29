"""Tests for binary `/proc/<pid>/pagemap` soft-dirty parser, auto-strategy selector, and Prometheus telemetry."""

from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from lkmp.config import MigrationStrategy
from lkmp.demo import run_live_demo
from lkmp.pagemap import (
    PAGE_SIZE,
    PTE_PRESENT_BIT,
    PTE_SOFT_DIRTY_BIT,
    count_pagemap_flags,
    parse_writable_vmas,
    sample_process_dirty_rate,
    select_optimal_strategy,
)


class TestPagemapAndTelemetry(unittest.TestCase):
    def test_parse_writable_vmas_skips_readonly_and_vdso(self) -> None:
        maps = """
00400000-00405000 r-xp 00000000 08:01 100 /usr/bin/app
00605000-00607000 rw-p 00005000 08:01 100 /usr/bin/app
7f0000000000-7f0000100000 rw-p 00000000 00:00 0 [heap]
7ffdf0000000-7ffdf0002000 rw-p 00000000 00:00 0 [vdso]
"""
        vmas = parse_writable_vmas(maps)
        self.assertEqual(
            vmas,
            [
                (0x00605000, 0x00607000),
                (0x7F0000000000, 0x7F0000100000),
            ],
        )

    def test_count_pagemap_flags_counts_present_and_soft_dirty_bits(self) -> None:
        entries = [
            PTE_PRESENT_BIT | PTE_SOFT_DIRTY_BIT,  # present + dirty
            PTE_PRESENT_BIT,                       # present + clean
            PTE_PRESENT_BIT | PTE_SOFT_DIRTY_BIT,  # present + dirty
            0,                                     # unmapped
        ]
        raw = b"".join(struct.pack("<Q", e) for e in entries)
        present, dirty = count_pagemap_flags(raw)
        self.assertEqual(present, 3)
        self.assertEqual(dirty, 2)

    def test_sample_process_dirty_rate_on_synthetic_proc_pagemap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp)
            pid_dir = proc_root / "999"
            pid_dir.mkdir(parents=True)

            # Map 4 pages starting at page index 0 (0x0000..0x4000)
            (pid_dir / "maps").write_text(
                "00000000-00004000 rw-p 00000000 00:00 0 [heap]\n",
                encoding="utf-8",
            )
            (pid_dir / "clear_refs").write_text("", encoding="utf-8")

            entries = [
                PTE_PRESENT_BIT | PTE_SOFT_DIRTY_BIT,
                PTE_PRESENT_BIT | PTE_SOFT_DIRTY_BIT,
                PTE_PRESENT_BIT,
                PTE_PRESENT_BIT,
            ]
            (pid_dir / "pagemap").write_bytes(
                b"".join(struct.pack("<Q", e) for e in entries)
            )

            profile = sample_process_dirty_rate(
                pid=999,
                proc_root=str(proc_root),
                sample_ms=0,
                bandwidth_mbps=1000.0,
            )
            self.assertEqual(profile.total_present_pages, 4)
            self.assertEqual(profile.soft_dirty_pages, 2)
            self.assertEqual(profile.rss_bytes, 4 * PAGE_SIZE)
            self.assertEqual(profile.dirty_bytes, 2 * PAGE_SIZE)

    def test_select_optimal_strategy_branches(self) -> None:
        # 1. Tiny process (2 MiB RSS, 0 dirty) -> COLD
        s_cold, _ = select_optimal_strategy(
            rss_bytes=2 * 1024 * 1024,
            dirty_rate_bytes_per_sec=0,
            bandwidth_mbps=1000.0,
        )
        self.assertEqual(s_cold, MigrationStrategy.COLD)

        # 2. Normal stateful workload (512 MiB RSS, 20 MiB/s dirty on 1 Gbps = 125 MB/s link) -> PRE_COPY
        s_pre, _ = select_optimal_strategy(
            rss_bytes=512 * 1024 * 1024,
            dirty_rate_bytes_per_sec=20 * 1024 * 1024,
            bandwidth_mbps=1000.0,
        )
        self.assertEqual(s_pre, MigrationStrategy.PRE_COPY)

        # 3. Write-heavy workload (512 MiB RSS, 110 MiB/s dirty on 1 Gbps link >= 70%) -> HYBRID
        s_hyb, _ = select_optimal_strategy(
            rss_bytes=512 * 1024 * 1024,
            dirty_rate_bytes_per_sec=110 * 1024 * 1024,
            bandwidth_mbps=1000.0,
            has_userfaultfd=True,
        )
        self.assertEqual(s_hyb, MigrationStrategy.HYBRID)

    def test_live_demo_commit_and_rollback_with_prometheus_metrics(self) -> None:
        res_ok, strat_ok, metrics_ok = run_live_demo(
            strategy=MigrationStrategy.AUTO,
            rss_mb=128,
            dirty_mbps=25,
            inject_fault="none",
        )
        self.assertTrue(res_ok.success)
        self.assertEqual(strat_ok, "pre-copy")
        prom_text = metrics_ok.export_prometheus_text()
        self.assertIn('lkmp_migrations_total{strategy="pre-copy",final_state="COMMIT"} 1', prom_text)

        res_rb, _strat_rb, metrics_rb = run_live_demo(
            strategy=MigrationStrategy.PRE_COPY,
            rss_mb=128,
            dirty_mbps=25,
            inject_fault="verify",
        )
        self.assertFalse(res_rb.success)
        self.assertTrue(res_rb.rolled_back)
        self.assertEqual(metrics_rb.rollbacks_total, 1)


if __name__ == "__main__":
    unittest.main()
