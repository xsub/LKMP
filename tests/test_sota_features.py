"""Tests for SOTA capabilities: Merkle attestation, VMA locality, entropy, floor prediction, eBPF redirect & 2PC gang migration."""

from __future__ import annotations

import signal
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import List

from lkmp.agent import AgentClient
from lkmp.attestation import CheckpointAttestor
from lkmp.config import IpMobilityMode, MigrationConfig, MigrationStrategy, TlsConfig
from lkmp.convergence import PreCopyConvergenceTracker
from lkmp.demo import run_live_demo
from lkmp.gang import GangMigrationCoordinator
from lkmp.models import MigrationState
from lkmp.network import NetworkMobilityManager
from lkmp.pagemap import (
    VmaHeatClass,
    VmaRegionProfile,
    compute_shannon_entropy,
    estimate_compression_ratio,
)
from tests.test_orchestrator_fsm import _FakeClusterHarness


class TestSotaCapabilities(unittest.TestCase):
    def test_merkle_checkpoint_attestation_and_bitflip_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            img_dir = Path(tmp)
            (img_dir / "core-100.img").write_bytes(b"REGISTER_STATE_V1")
            (img_dir / "pages-1.img").write_bytes(b"\xaa" * 4096)

            attestor = CheckpointAttestor(secret_key=b"test-secret-key")
            manifest = attestor.generate_manifest(img_dir, migration_id="mig-99", pid=100)
            self.assertEqual(len(manifest.files), 2)

            # 1. Clean verification succeeds
            verified = attestor.verify_directory(img_dir, expected_migration_id="mig-99")
            self.assertEqual(verified.merkle_root, manifest.merkle_root)

            # 2. Flip a single byte in core-100.img -> must fail SHA-256 & Merkle verification
            (img_dir / "core-100.img").write_bytes(b"REGISTER_STATE_V2")
            with self.assertRaises(ValueError) as ctx:
                attestor.verify_directory(img_dir, expected_migration_id="mig-99")
            self.assertIn("SHA-256 integrity failure", str(ctx.exception))

    def test_corrupted_image_triggers_transactional_rollback_in_demo(self) -> None:
        res, _strat, metrics = run_live_demo(
            strategy=MigrationStrategy.COLD,
            rss_mb=64,
            dirty_mbps=0,
            inject_fault="corrupt-image",
        )
        self.assertFalse(res.success)
        self.assertTrue(res.rolled_back)
        self.assertEqual(res.final_state, MigrationState.ROLLBACK)
        self.assertIn("integrity failure", res.error_message or "")
        self.assertEqual(metrics.rollbacks_total, 1)

    def test_shannon_entropy_and_vma_heat_classification(self) -> None:
        # All-zero page -> 0.0 bits/byte entropy, 8.0x compression ratio
        zeros = b"\x00" * 4096
        self.assertEqual(compute_shannon_entropy(zeros), 0.0)
        self.assertEqual(estimate_compression_ratio(zeros), 8.0)

        # Uniform 0..255 distribution -> 8.0 bits/byte entropy, 1.0x compression ratio
        uniform = bytes(range(256)) * 16
        self.assertAlmostEqual(compute_shannon_entropy(uniform), 8.0, places=3)
        self.assertEqual(estimate_compression_ratio(uniform), 1.0)

        # VMA heat classification
        cold_vma = VmaRegionProfile(0, 0x10000, "[rodata]", present_pages=100, soft_dirty_pages=2)
        warm_vma = VmaRegionProfile(0, 0x10000, "[heap]", present_pages=100, soft_dirty_pages=25)
        hot_vma = VmaRegionProfile(0, 0x10000, "[stack]", present_pages=100, soft_dirty_pages=85)
        self.assertEqual(cold_vma.heat_class, VmaHeatClass.COLD)
        self.assertEqual(warm_vma.heat_class, VmaHeatClass.WARM)
        self.assertEqual(hot_vma.heat_class, VmaHeatClass.HOT_THRASHING)

    def test_asymptotic_hot_floor_prediction_stops_at_knee_of_curve(self) -> None:
        # Target downtime budget = 25 MB (1000 Mbps * 0.2s)
        tracker = PreCopyConvergenceTracker(
            bandwidth_mbps=1000.0,
            target_downtime_ms=200,
            min_shrink_ratio=0.05,
            max_iterations=8,
        )
        # Exponential decay toward D_inf = 40 MB (> 25 MB budget) with r = 0.5:
        # D1 = 40M + 64M = 104M, D2 = 40M + 32M = 72M, D3 = 40M + 16M = 56M, D4 = 40M + 8M = 48M
        self.assertFalse(tracker.evaluate(1, 104_000_000).should_stop)
        self.assertFalse(tracker.evaluate(2, 72_000_000).should_stop)
        d3 = tracker.evaluate(3, 56_000_000)
        self.assertEqual(d3.predicted_floor_bytes, 40_000_000)
        self.assertFalse(d3.should_stop)

        d4 = tracker.evaluate(4, 48_000_000)
        self.assertTrue(d4.should_stop)
        self.assertFalse(d4.converged)
        self.assertTrue(d4.recommend_hybrid_upgrade)
        self.assertIn("knee of curve", d4.reason)

    def test_ebpf_tunnel_hairpin_redirect_commands(self) -> None:
        executed: List[List[str]] = []

        def fake_runner(cmd: List[str]) -> subprocess.CompletedProcess:
            executed.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        net = NetworkMobilityManager(runner=fake_runner)
        cfg = MigrationConfig(
            pid=100,
            source_addr="10.0.0.1:9700",
            dest_addr="10.0.0.2:9700",
            ip_mobility=IpMobilityMode.EBPF,
            workload_ip="10.20.0.99/24",
            net_interface="eth0",
        )
        net.release_ip_on_host(cfg)
        self.assertIn(
            ["ip", "tunnel", "add", "lkmp0", "mode", "ipip", "remote", "10.0.0.2"],
            executed,
        )
        self.assertIn(
            ["ip", "route", "replace", "10.20.0.99/32", "dev", "lkmp0"],
            executed,
        )

    def test_distributed_2pc_gang_migration_atomic_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            # Member 1 succeeds on B, but Member 2 fails restore on B -> BOTH must roll back to A!
            h1 = _FakeClusterHarness(tmp1)
            h2 = _FakeClusterHarness(tmp2)
            h2.fail_on_restore = True

            cfg1 = MigrationConfig(
                pid=1234,
                workload_id="srv-1",
                source_addr="a1:9700",
                dest_addr="b1:9700",
                strategy=MigrationStrategy.COLD,
                tls=TlsConfig(enabled=False),
            )
            cfg2 = MigrationConfig(
                pid=1234,
                workload_id="srv-1",
                source_addr="a2:9700",
                dest_addr="b2:9700",
                strategy=MigrationStrategy.COLD,
                tls=TlsConfig(enabled=False),
            )

            gang = GangMigrationCoordinator(
                gang_id="gang-test",
                members=[
                    (
                        cfg1,
                        AgentClient("a1:9700", direct_service=h1.service_a),
                        AgentClient("b1:9700", direct_service=h1.service_b),
                    ),
                    (
                        cfg2,
                        AgentClient("a2:9700", direct_service=h2.service_a),
                        AgentClient("b2:9700", direct_service=h2.service_b),
                    ),
                ],
            )
            gang_res = gang.execute_atomic()
            self.assertFalse(gang_res.all_committed)
            self.assertTrue(gang_res.atomic_rollback_triggered)
            self.assertTrue(all(r.rolled_back for r in gang_res.member_results))
            self.assertTrue(
                all(r.final_state == MigrationState.ROLLBACK for r in gang_res.member_results)
            )
            # Member 1's restored process on B (5678) was killed and Member 1 on A (1234) received SIGCONT
            self.assertIn((5678, signal.SIGKILL), h1.signals_b)
            self.assertIn((1234, signal.SIGCONT), h1.signals_a)


if __name__ == "__main__":
    unittest.main()
