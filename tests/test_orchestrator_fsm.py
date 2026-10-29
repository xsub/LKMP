"""Tests for the MigrationOrchestrator state machine, strategies, and rollback paths."""

from __future__ import annotations

import signal
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import List, Tuple

from lkmp.agent import AgentClient, AgentService
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
from lkmp.models import MigrationState
from lkmp.network import NetworkMobilityManager
from lkmp.orchestrator import MigrationOrchestrator


class _FakeClusterHarness:
    """Simulated two-node (Source A and Destination B) test harness with controllable faults."""

    def __init__(self, tmp_dir: str) -> None:
        self.root = Path(tmp_dir)
        self.proc_a = self.root / "proc_a"
        self.proc_b = self.root / "proc_b"
        self.work_a = self.root / "work_a"
        self.work_b = self.root / "work_b"
        self.cgroup_a = self.root / "cgroup_a"
        self.cgroup_b = self.root / "cgroup_b"

        self.signals_a: List[Tuple[int, int]] = []
        self.signals_b: List[Tuple[int, int]] = []
        self.commands_a: List[List[str]] = []
        self.commands_b: List[List[str]] = []

        self.fail_on_restore = False
        self.dest_pid_alive = True
        self.predump_sizes = [80_000_000, 15_000_000]  # Round 1: 80MB, Round 2: 15MB (converges)
        self._predump_idx = 0

        self._setup_proc_trees()

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
            pid_alive_checker=lambda _pid: self.dest_pid_alive,
        )

    def _setup_proc_trees(self) -> None:
        for proc in (self.proc_a, self.proc_b):
            proc.mkdir(parents=True, exist_ok=True)
            (proc / "cpuinfo").write_text(
                "vendor_id : GenuineIntel\nflags : sse4_2 avx avx2 xsave\n",
                encoding="utf-8",
            )
        pid_dir = self.proc_a / "1234"
        (pid_dir / "fd").mkdir(parents=True, exist_ok=True)
        (pid_dir / "status").write_text(
            "Name:\tserver\nVmRSS:\t65536 kB\nTracerPid:\t0\nNSpid:\t1234\t1\n",
            encoding="utf-8",
        )
        (pid_dir / "cgroup").write_text("0::/lkmp/srv-1\n", encoding="utf-8")
        (pid_dir / "maps").write_text("", encoding="utf-8")

    def _run_a(self, cmd: List[str]) -> subprocess.CompletedProcess:
        self.commands_a.append(cmd)
        if len(cmd) >= 2 and cmd[0] == "criu" and cmd[1] == "pre-dump":
            idx = cmd.index("--images-dir")
            img_dir = Path(cmd[idx + 1])
            size = self.predump_sizes[min(self._predump_idx, len(self.predump_sizes) - 1)]
            self._predump_idx += 1
            # Write synthetic page image with sparse size so dirty byte tracker reads it
            pages_file = img_dir / "pages-1.img"
            with pages_file.open("wb") as f:
                f.truncate(size)
        elif len(cmd) >= 2 and cmd[0] == "criu" and cmd[1] == "dump":
            idx = cmd.index("--images-dir")
            img_dir = Path(cmd[idx + 1])
            (img_dir / "core-1234.img").write_bytes(b"SECRET_KEY_MATERIAL_IN_RAM")
        return subprocess.CompletedProcess(cmd, 0, "CRIU 4.3\n", "")

    def _run_b(self, cmd: List[str]) -> subprocess.CompletedProcess:
        self.commands_b.append(cmd)
        if len(cmd) >= 2 and cmd[0] == "criu" and cmd[1] == "restore":
            if self.fail_on_restore:
                raise RuntimeError("Simulated CRIU restore failure on Destination B")
            if "--pidfile" in cmd:
                idx = cmd.index("--pidfile")
                Path(cmd[idx + 1]).write_text("5678\n", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "CRIU 4.3\n", "")


class TestOrchestratorStateMachine(unittest.TestCase):
    def test_precopy_happy_path_state_machine_and_convergence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            harness = _FakeClusterHarness(tmp)
            cfg = MigrationConfig(
                pid=1234,
                workload_id="srv-1",
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.PRE_COPY,
                fs_mode=FilesystemMode.SHARED,
                ip_mobility=IpMobilityMode.GARP,
                workload_ip="10.0.0.99/24",
                tls=TlsConfig(enabled=False),
            )
            src = AgentClient("10.0.0.1:9700", direct_service=harness.service_a)
            dst = AgentClient("10.0.0.2:9700", direct_service=harness.service_b)

            orch = MigrationOrchestrator(cfg, src, dst, migration_id="mig-test1")
            res = orch.execute()

            self.assertTrue(res.success)
            self.assertFalse(res.rolled_back)
            self.assertEqual(res.final_state, MigrationState.COMMIT)
            self.assertEqual(res.restored_pid, 5678)
            self.assertEqual(len(res.precopy_iterations), 2)
            self.assertTrue(res.precopy_iterations[-1].converged)

            expected_states = [
                MigrationState.INIT,
                MigrationState.PREFLIGHT,
                MigrationState.PREPARE,
                MigrationState.PRE_COPY,
                MigrationState.PRE_COPY,
                MigrationState.FREEZE,
                MigrationState.FINAL_DUMP,
                MigrationState.TRANSFER,
                MigrationState.RESTORE,
                MigrationState.SWITCHOVER,
                MigrationState.VERIFY,
                MigrationState.COMMIT,
            ]
            self.assertEqual(res.state_history, expected_states)

            # Verify Destination B resumed PID 5678 with SIGCONT and Source A killed PID 1234 on commit
            self.assertIn((5678, signal.SIGCONT), harness.signals_b)
            self.assertIn((1234, signal.SIGKILL), harness.signals_a)

            # Verify checkpoint directory on Source A was securely wiped on commit
            self.assertFalse((harness.work_a / "mig-test1").exists())

    def test_rollback_when_restore_fails_on_destination(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            harness = _FakeClusterHarness(tmp)
            harness.fail_on_restore = True

            cfg = MigrationConfig(
                pid=1234,
                workload_id="srv-1",
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                ip_mobility=IpMobilityMode.GARP,
                workload_ip="10.0.0.99/24",
                tls=TlsConfig(enabled=False),
            )
            src = AgentClient("10.0.0.1:9700", direct_service=harness.service_a)
            dst = AgentClient("10.0.0.2:9700", direct_service=harness.service_b)

            orch = MigrationOrchestrator(cfg, src, dst, migration_id="mig-rollback1")
            res = orch.execute()

            self.assertFalse(res.success)
            self.assertTrue(res.rolled_back)
            self.assertEqual(res.final_state, MigrationState.ROLLBACK)
            self.assertIn("Simulated CRIU restore failure", res.error_message or "")

            # Source A must NOT be killed; instead it must receive SIGCONT to resume execution
            self.assertNotIn((1234, signal.SIGKILL), harness.signals_a)
            self.assertIn((1234, signal.SIGCONT), harness.signals_a)

    def test_rollback_when_post_switchover_verification_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            harness = _FakeClusterHarness(tmp)
            harness.dest_pid_alive = False  # Simulate process crashing right after switchover on B

            cfg = MigrationConfig(
                pid=1234,
                workload_id="srv-1",
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                ip_mobility=IpMobilityMode.GARP,
                workload_ip="10.0.0.99/24",
                tls=TlsConfig(enabled=False),
            )
            src = AgentClient("10.0.0.1:9700", direct_service=harness.service_a)
            dst = AgentClient("10.0.0.2:9700", direct_service=harness.service_b)

            orch = MigrationOrchestrator(cfg, src, dst, migration_id="mig-rollback2")
            res = orch.execute()

            self.assertFalse(res.success)
            self.assertTrue(res.rolled_back)
            self.assertEqual(res.final_state, MigrationState.ROLLBACK)
            self.assertIn("not alive on destination", res.error_message or "")

            # Partial process on B (5678) is killed with SIGKILL, and Source A (1234) resumes with SIGCONT
            self.assertIn((5678, signal.SIGKILL), harness.signals_b)
            self.assertIn((1234, signal.SIGCONT), harness.signals_a)


if __name__ == "__main__":
    unittest.main()
