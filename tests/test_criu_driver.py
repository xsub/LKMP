"""Tests for CRIU command construction, GPU hooks, and network mobility drivers."""

from __future__ import annotations

import subprocess
import unittest
from typing import List

from lkmp.config import (
    GpuPlugin,
    IpMobilityMode,
    MigrationConfig,
    MigrationStrategy,
    TlsConfig,
)
from lkmp.criu_driver import CriuDriver
from lkmp.network import NetworkMobilityManager


class TestCriuAndNetworkDrivers(unittest.TestCase):
    def test_precopy_and_final_dump_commands(self) -> None:
        cfg = MigrationConfig(
            pid=9876,
            source_addr="10.0.0.1:9700",
            dest_addr="10.0.0.2:9700",
            strategy=MigrationStrategy.PRE_COPY,
            tcp_established=True,
            tls=TlsConfig(enabled=True),
        )
        driver = CriuDriver()

        ps_cmd = driver.build_page_server_cmd(
            images_dir="/var/lib/lkmp/img/2",
            port=27000,
            tls=cfg.tls,
            prev_images_dir="../1",
        )
        self.assertEqual(
            ps_cmd,
            [
                "criu",
                "page-server",
                "--images-dir",
                "/var/lib/lkmp/img/2",
                "--port",
                "27000",
                "--prev-images-dir",
                "../1",
                "--tls",
            ],
        )

        predump_cmd = driver.build_pre_dump_cmd(
            config=cfg,
            images_dir="/var/lib/lkmp/img/2",
            prev_images_dir="../1",
            dest_host="10.0.0.2",
        )
        self.assertIn("--track-mem", predump_cmd)
        self.assertIn("--page-server", predump_cmd)
        self.assertIn("--tls", predump_cmd)

        dump_cmd = driver.build_dump_cmd(
            config=cfg,
            images_dir="/var/lib/lkmp/img/final",
            prev_images_dir="../2",
            dest_host="10.0.0.2",
        )
        self.assertIn("--leave-stopped", dump_cmd)
        self.assertIn("--tcp-established", dump_cmd)
        self.assertIn("nftables", dump_cmd)

    def test_lazy_postcopy_commands(self) -> None:
        cfg = MigrationConfig(
            pid=555,
            source_addr="10.0.0.1:9700",
            dest_addr="10.0.0.2:9700",
            strategy=MigrationStrategy.LAZY,
        )
        driver = CriuDriver()
        dump_cmd = driver.build_dump_cmd(cfg, images_dir="/img/final")
        self.assertIn("--lazy-pages", dump_cmd)

        restore_cmd = driver.build_restore_cmd(cfg, images_dir="/img/final")
        self.assertIn("--lazy-pages", restore_cmd)
        self.assertIn("--restore-detached", restore_cmd)
        self.assertIn("--leave-stopped", restore_cmd)

    def test_cuda_checkpoint_hooks(self) -> None:
        executed: List[List[str]] = []

        def fake_runner(cmd: List[str]) -> subprocess.CompletedProcess:
            executed.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        cfg = MigrationConfig(
            pid=777,
            source_addr="a:9700",
            dest_addr="b:9700",
            gpu_plugin=GpuPlugin.CUDA,
        )
        driver = CriuDriver(runner=fake_runner)
        driver.run_gpu_pre_dump_hook(cfg)
        driver.run_gpu_post_restore_hook(cfg, restored_pid=777)

        self.assertEqual(
            executed,
            [
                ["cuda-checkpoint", "--action", "lock", "--pid", "777"],
                ["cuda-checkpoint", "--action", "checkpoint", "--pid", "777"],
                ["cuda-checkpoint", "--action", "restore", "--pid", "777"],
                ["cuda-checkpoint", "--action", "unlock", "--pid", "777"],
            ],
        )

    def test_network_mobility_garp_and_bgp(self) -> None:
        executed: List[List[str]] = []

        def fake_runner(cmd: List[str]) -> subprocess.CompletedProcess:
            executed.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        net = NetworkMobilityManager(runner=fake_runner)
        cfg_garp = MigrationConfig(
            pid=100,
            source_addr="a:9700",
            dest_addr="b:9700",
            ip_mobility=IpMobilityMode.GARP,
            workload_ip="10.20.0.99/24",
            net_interface="eth0",
        )
        net.lock_network(cfg_garp.workload_ip)
        net.release_ip_on_host(cfg_garp)
        net.claim_ip_on_host(cfg_garp, target_host="10.0.0.2")
        net.unlock_network(cfg_garp.workload_ip)

        self.assertIn(
            ["arping", "-U", "-c", "3", "-I", "eth0", "10.20.0.99"],
            executed,
        )

        executed.clear()
        cfg_bgp = MigrationConfig(
            pid=100,
            source_addr="a:9700",
            dest_addr="b:9700",
            ip_mobility=IpMobilityMode.BGP,
            workload_ip="10.20.0.99/32",
            net_interface="eth0",
        )
        net.release_ip_on_host(cfg_bgp)
        net.claim_ip_on_host(cfg_bgp, target_host="10.0.0.2")
        self.assertIn(
            ["gobgp", "global", "rib", "del", "-a", "ipv4", "10.20.0.99/32"],
            executed,
        )
        self.assertIn(
            ["gobgp", "global", "rib", "add", "-a", "ipv4", "10.20.0.99/32"],
            executed,
        )


if __name__ == "__main__":
    unittest.main()
