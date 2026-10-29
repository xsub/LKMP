"""Self-contained two-node live migration simulator & benchmark (`lkmp demo`)."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path
from typing import List, Tuple

from lkmp.agent import AgentClient, AgentServer, AgentService
from lkmp.config import (
    FilesystemMode,
    IpMobilityMode,
    MigrationConfig,
    MigrationStrategy,
    TlsConfig,
)
from lkmp.criu_driver import CriuDriver
from lkmp.envelope import EnvelopeManager
from lkmp.fs_sync import FilesystemSyncManager
from lkmp.models import MigrationResult
from lkmp.network import NetworkMobilityManager
from lkmp.orchestrator import MigrationOrchestrator
from lkmp.telemetry import PrometheusMetricsCollector


class DemoClusterNodeSet:
    """In-memory two-node (Source A & Destination B) cluster communicating over real TCP RPC."""

    def __init__(
        self,
        tmp_dir: str,
        rss_mb: int = 256,
        dirty_mbps: int = 40,
        inject_fault: str = "none",
    ) -> None:
        self.root = Path(tmp_dir)
        self.rss_bytes = rss_mb * 1024 * 1024
        self.dirty_bps = dirty_mbps * 1024 * 1024
        self.inject_fault = inject_fault

        self.proc_a = self.root / "proc_a"
        self.proc_b = self.root / "proc_b"
        self.work_a = self.root / "work_a"
        self.work_b = self.root / "work_b"
        self.cgroup_a = self.root / "cgroup_a"
        self.cgroup_b = self.root / "cgroup_b"

        self.signals_a: List[Tuple[int, int]] = []
        self.signals_b: List[Tuple[int, int]] = []

        # Calculate realistic shrinking dirty page sizes across 3 pre-dump rounds
        r1 = max(4 * 1024 * 1024, int(self.rss_bytes * 0.45))
        r2 = max(2 * 1024 * 1024, int(self.dirty_bps * 0.60))
        r3 = max(1 * 1024 * 1024, int(self.dirty_bps * 0.25))
        self.predump_sizes = [r1, r2, r3]
        self._predump_idx = 0

        self._populate_synthetic_proc()

        self.service_a = AgentService(
            work_dir=str(self.work_a),
            proc_root=str(self.proc_a),
            criu_driver=CriuDriver(runner=self._run_a),
            net_manager=NetworkMobilityManager(runner=self._run_a),
            fs_manager=FilesystemSyncManager(runner=self._run_a),
            envelope_manager=EnvelopeManager(cgroup_root=str(self.cgroup_a), runner=self._run_a),
            signal_sender=lambda pid, sig: self.signals_a.append((pid, sig)),
            pid_alive_checker=lambda _pid: True,
        )
        self.service_b = AgentService(
            work_dir=str(self.work_b),
            proc_root=str(self.proc_b),
            criu_driver=CriuDriver(runner=self._run_b),
            net_manager=NetworkMobilityManager(runner=self._run_b),
            fs_manager=FilesystemSyncManager(runner=self._run_b),
            envelope_manager=EnvelopeManager(cgroup_root=str(self.cgroup_b), runner=self._run_b),
            signal_sender=lambda pid, sig: self.signals_b.append((pid, sig)),
            pid_alive_checker=lambda _pid: self.inject_fault != "verify",
        )

    def _populate_synthetic_proc(self) -> None:
        for proc in (self.proc_a, self.proc_b):
            proc.mkdir(parents=True, exist_ok=True)
            (proc / "cpuinfo").write_text(
                "vendor_id : GenuineIntel\nflags : sse4_2 avx avx2 avx512f bmi1 bmi2 xsave\n",
                encoding="utf-8",
            )
        pid_dir = self.proc_a / "4242"
        (pid_dir / "fd").mkdir(parents=True, exist_ok=True)
        rss_kb = self.rss_bytes // 1024
        (pid_dir / "status").write_text(
            f"Name:\tstateful-srv\nVmRSS:\t{rss_kb} kB\nTracerPid:\t0\nNSpid:\t4242\t1\n",
            encoding="utf-8",
        )
        (pid_dir / "cgroup").write_text("0::/lkmp/demo-srv\n", encoding="utf-8")
        (pid_dir / "maps").write_text("", encoding="utf-8")

    def _run_a(self, cmd: List[str]) -> subprocess.CompletedProcess:
        if len(cmd) >= 2 and cmd[0] == "criu" and cmd[1] == "pre-dump":
            idx = cmd.index("--images-dir")
            img_dir = Path(cmd[idx + 1])
            size = self.predump_sizes[min(self._predump_idx, len(self.predump_sizes) - 1)]
            self._predump_idx += 1
            pages_file = img_dir / "pages-1.img"
            with pages_file.open("wb") as f:
                f.truncate(size)
        elif len(cmd) >= 2 and cmd[0] == "criu" and cmd[1] == "dump":
            idx = cmd.index("--images-dir")
            img_dir = Path(cmd[idx + 1])
            (img_dir / "core-4242.img").write_bytes(b"DEMO_PROCESS_CONTEXT")
        return subprocess.CompletedProcess(cmd, 0, "CRIU 4.3\n", "")

    def _run_b(self, cmd: List[str]) -> subprocess.CompletedProcess:
        if len(cmd) >= 2 and cmd[0] == "criu" and cmd[1] == "restore":
            if self.inject_fault == "restore":
                raise RuntimeError("Injected fault: Destination B CRIU restore failed")
            if "--pidfile" in cmd:
                idx = cmd.index("--pidfile")
                Path(cmd[idx + 1]).write_text("8484\n", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "CRIU 4.3\n", "")


def run_live_demo(
    strategy: MigrationStrategy = MigrationStrategy.AUTO,
    rss_mb: int = 256,
    dirty_mbps: int = 40,
    inject_fault: str = "none",
) -> Tuple[MigrationResult, str, PrometheusMetricsCollector]:
    """Spin up two loopback TCP agents and execute a full live migration."""
    metrics = PrometheusMetricsCollector()
    with tempfile.TemporaryDirectory() as tmp:
        cluster = DemoClusterNodeSet(
            tmp_dir=tmp,
            rss_mb=rss_mb,
            dirty_mbps=dirty_mbps,
            inject_fault=inject_fault,
        )
        srv_a = AgentServer("127.0.0.1", 0, cluster.service_a)
        srv_b = AgentServer("127.0.0.1", 0, cluster.service_b)
        srv_a.start_background()
        srv_b.start_background()
        try:
            host_a, port_a = srv_a.bound_address
            host_b, port_b = srv_b.bound_address
            cfg = MigrationConfig(
                pid=4242,
                workload_id="demo-srv",
                source_addr=f"{host_a}:{port_a}",
                dest_addr=f"{host_b}:{port_b}",
                strategy=strategy,
                fs_mode=FilesystemMode.SHARED,
                ip_mobility=IpMobilityMode.GARP,
                workload_ip="10.0.0.99/24",
                tls=TlsConfig(enabled=False),
            )
            client_a = AgentClient(cfg.source_addr, tls=cfg.tls)
            client_b = AgentClient(cfg.dest_addr, tls=cfg.tls)
            orch = MigrationOrchestrator(cfg, client_a, client_b, metrics=metrics)
            result = orch.execute()
            return result, orch.config.strategy.value, metrics
        finally:
            srv_a.shutdown()
            srv_b.shutdown()
