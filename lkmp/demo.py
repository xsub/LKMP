"""Self-contained two-node live migration simulator & SOTA benchmark suite (`lkmp demo` / `lkmp benchmark`)."""

from __future__ import annotations

import shutil
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
from lkmp.pagemap import PAGE_SIZE, PTE_PRESENT_BIT, PTE_SOFT_DIRTY_BIT
from lkmp.telemetry import PrometheusMetricsCollector, format_bytes
import struct


class _SimulatedCluster:
    """In-memory two-node (Source A & Destination B) cluster communicating over real TCP RPC."""

    def __init__(
        self,
        tmp_dir: str,
        rss_mb: int = 256,
        dirty_mbps: int = 40,
        inject_fault: str = "none",
        corrupt_final_image: bool = False,
    ) -> None:
        self.root = Path(tmp_dir)
        self.rss_bytes = rss_mb * 1024 * 1024
        self.dirty_bps = dirty_mbps * 1024 * 1024
        self.inject_fault = inject_fault
        self.corrupt_final_image = corrupt_final_image or (inject_fault == "corrupt-image")

        self.proc_a = self.root / "proc_a"
        self.proc_b = self.root / "proc_b"
        self.work_a = self.root / "work_a"
        self.work_b = self.root / "work_b"
        self.cgroup_a = self.root / "cgroup_a"
        self.cgroup_b = self.root / "cgroup_b"

        self.signals_a: List[Tuple[int, int]] = []
        self.signals_b: List[Tuple[int, int]] = []

        r1 = max(4 * 1024 * 1024, int(self.rss_bytes * 0.45))
        r2 = max(2 * 1024 * 1024, int(self.dirty_bps * 0.60))
        r3 = max(1 * 1024 * 1024, int(self.dirty_bps * 0.25))
        self.predump_sizes = [r1, r2, r3]
        self._predump_idx = 0

        self._populate_synthetic_proc()

        self._run_a = self._make_runner(
            work_dir=self.work_a,
            peer_work_dir=self.work_b,
            is_source=True,
        )
        self._run_b = self._make_runner(
            work_dir=self.work_b,
            peer_work_dir=self.work_a,
            is_source=False,
        )

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

        # Create synthetic VMA & binary /proc/4242/pagemap reflecting dirty_bps ratio
        num_sample_pages = 256
        end_addr = num_sample_pages * PAGE_SIZE
        (pid_dir / "maps").write_text(
            f"00000000-{end_addr:08x} rw-p 00000000 00:00 0 [heap]\n",
            encoding="utf-8",
        )
        (pid_dir / "clear_refs").write_text("", encoding="utf-8")
        dirty_ratio = min(1.0, self.dirty_bps / float(125 * 1024 * 1024))
        dirty_pages = int(num_sample_pages * dirty_ratio)
        entries = [
            (PTE_PRESENT_BIT | PTE_SOFT_DIRTY_BIT) if i < dirty_pages else PTE_PRESENT_BIT
            for i in range(num_sample_pages)
        ]
        (pid_dir / "pagemap").write_bytes(b"".join(struct.pack("<Q", e) for e in entries))

    def _make_runner(
        self,
        work_dir: Optional[Path] = None,
        peer_work_dir: Optional[Path] = None,
        is_source: bool = True,
    ):
        if work_dir is None:
            work_dir = self.work_a if is_source else self.work_b
        if peer_work_dir is None:
            peer_work_dir = self.work_b if is_source else self.work_a

        def runner(cmd: List[str]) -> subprocess.CompletedProcess:
            if not cmd:
                return subprocess.CompletedProcess(cmd, 0, "", "")

            if is_source:
                if cmd[0] == "criu":
                    action = cmd[1] if len(cmd) > 1 else ""
                    if action in ("pre-dump", "dump"):
                        idx = cmd.index("--images-dir")
                        img_dir = Path(cmd[idx + 1])
                        img_dir.mkdir(parents=True, exist_ok=True)

                        if action == "pre-dump":
                            size = self.predump_sizes[min(self._predump_idx, len(self.predump_sizes) - 1)]
                            self._predump_idx += 1
                        else:
                            size = (
                                max(512 * 1024, int(self.dirty_bps * 0.15))
                                if self._predump_idx > 0
                                else self.predump_sizes[0]
                            )

                        # Create core-1.img and pages-1.img inside img_dir on Host A
                        core_file = img_dir / "core-1.img"
                        core_file.write_bytes(b"DEMO_PROCESS_CONTEXT_REGISTERS")

                        pages_file = img_dir / "pages-1.img"
                        with pages_file.open("wb") as f:
                            f.truncate(size)

                        # ALSO mirror pages-1.img into the corresponding directory on Host B
                        # (peer_work_dir / img_dir.relative_to(work_dir)) when --page-server or --lazy-pages is in cmd
                        if "--page-server" in cmd or "--lazy-pages" in cmd:
                            try:
                                rel = img_dir.relative_to(work_dir)
                            except ValueError:
                                try:
                                    rel = img_dir.resolve().relative_to(work_dir.resolve())
                                except ValueError:
                                    rel = Path(*img_dir.parts[-2:])
                            peer_dir = peer_work_dir / rel
                            peer_dir.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(pages_file, peer_dir / "pages-1.img")

                elif cmd[0] == "rsync":
                    # Copy all .img files (respecting --exclude=pages-*.img if present in cmd)
                    # AND manifest.sig.json from the source directory on Host A to the corresponding
                    # round directory on Host B (work_b / mig_id / round_name).
                    src_arg = cmd[-2].rstrip("/")
                    src_path = Path(src_arg)
                    if src_path.exists():
                        try:
                            rel = src_path.relative_to(work_dir)
                        except ValueError:
                            try:
                                rel = src_path.resolve().relative_to(work_dir.resolve())
                            except ValueError:
                                rel = Path(*src_path.parts[-2:])
                        dst_path = peer_work_dir / rel
                        dst_path.mkdir(parents=True, exist_ok=True)

                        exclude_pages = any(arg.startswith("--exclude=pages-") for arg in cmd)
                        for item in src_path.iterdir():
                            if not item.is_file():
                                continue
                            if item.name.endswith(".img"):
                                if exclude_pages and item.name.startswith("pages-"):
                                    continue
                                shutil.copy2(item, dst_path / item.name)
                            elif item.name == "manifest.sig.json":
                                shutil.copy2(item, dst_path / item.name)

                        # Note: keep the corrupt_final_image hook working! Specifically, if self.corrupt_final_image
                        # is True, flip a byte in core-1.img on Host B after copying it during rsync so
                        # restore_process's mandatory verify_directory detects the bit-rot and triggers rollback!
                        if self.corrupt_final_image or self.inject_fault == "corrupt-image":
                            corrupted = dst_path / "core-1.img"
                            if corrupted.exists():
                                raw = bytearray(corrupted.read_bytes())
                                if raw:
                                    raw[0] ^= 0xFF
                                    corrupted.write_bytes(bytes(raw))
            else:
                if len(cmd) >= 2 and cmd[0] == "criu" and cmd[1] == "restore":
                    if self.inject_fault == "restore":
                        raise RuntimeError("Injected fault: Destination B CRIU restore failed")
                    if "--pidfile" in cmd:
                        idx = cmd.index("--pidfile")
                        Path(cmd[idx + 1]).write_text("8484\n", encoding="utf-8")

            return subprocess.CompletedProcess(cmd, 0, "CRIU 4.3\n", "")

        return runner


class DemoClusterNodeSet(_SimulatedCluster):
    """Backward-compatible subclass for _SimulatedCluster."""
    pass


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
                ip_mobility=IpMobilityMode.TUNNEL,
                workload_ip="10.0.0.99/24",
                tls=TlsConfig(enabled=False),
            )
            client_a = AgentClient(cfg.source_addr, tls=cfg.tls)
            client_b = AgentClient(cfg.dest_addr, tls=cfg.tls)
            orch = MigrationOrchestrator(cfg, client_a, client_b, metrics=metrics)
            # Populate snapshot dirty_rate_bytes_per_sec for auto-strategy demo accuracy
            orig_inspect = cluster.service_a.inspect_process

            def _enriched_inspect(pid: int, ghost_limit_bytes: int) -> dict:
                d = orig_inspect(pid, ghost_limit_bytes)
                d["dirty_rate_bytes_per_sec"] = cluster.dirty_bps
                return d

            cluster.service_a.inspect_process = _enriched_inspect  # type: ignore[method-assign]
            cluster.service_b.get_capabilities = lambda: {  # type: ignore[method-assign]
                **AgentService.get_capabilities(cluster.service_b),
                "has_userfaultfd": True,
            }
            result = orch.execute()
            return result, orch.config.strategy.value, metrics
        finally:
            srv_a.shutdown()
            srv_b.shutdown()


def run_sota_benchmark_suite() -> str:
    """Run comparative benchmark across canonical workload profiles and render a table."""
    scenarios = [
        ("1. Edge Microservice", 6, 0, "none"),
        ("2. Stateful Redis / DB", 512, 35, "none"),
        ("3. Write-Heavy AI/Analytics", 1024, 105, "none"),
        ("4. Tampered .img Attack", 256, 30, "corrupt-image"),
    ]
    lines = [
        "┌──────────────────────────────┬──────────┬───────────┬──────────┬───────────┬────────────────────────────┐",
        "│ Workload Scenario            │ RSS      │ WriteRate │ AutoMode │ FreezeWin │ Final Outcome              │",
        "├──────────────────────────────┼──────────┼───────────┼──────────┼───────────┼────────────────────────────┤",
    ]
    for name, rss_mb, dirty_mbps, fault in scenarios:
        res, chosen_strat, _ = run_live_demo(
            strategy=MigrationStrategy.AUTO,
            rss_mb=rss_mb,
            dirty_mbps=dirty_mbps,
            inject_fault=fault,
        )
        outcome = (
            f"COMMIT (PID {res.restored_pid})"
            if res.success
            else ("ROLLBACK (Merkle Block)" if fault == "corrupt-image" else "ROLLBACK")
        )
        lines.append(
            f"│ {name:<28} │ {f'{rss_mb} MiB':<8} │ {f'{dirty_mbps} MiB/s':<9} │ "
            f"{chosen_strat:<8} │ {f'{res.freeze_downtime_ms:.2f} ms':<9} │ {outcome:<26} │"
        )
    lines.append(
        "└──────────────────────────────┴──────────┴───────────┴──────────┴───────────┴────────────────────────────┘"
    )
    return "\n".join(lines)
