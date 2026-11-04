"""Tests for the MigrationOrchestrator state machine, strategies, and rollback paths."""

from __future__ import annotations

import shutil
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
        self.root = Path(tmp_dir).resolve()
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
        self._nft_a: dict = {}
        self._nft_b: dict = {}

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
            signal_sender=self._signal_b,
            pid_alive_checker=lambda _pid: self.dest_pid_alive,
        )

    def _signal_b(self, pid: int, sig: int) -> None:
        self.signals_b.append((pid, sig))
        if sig == signal.SIGCONT:
            st_file = self.proc_b / str(pid) / "status"
            if st_file.exists():
                txt = st_file.read_text(encoding="utf-8")
                st_file.write_text(txt.replace("State:\tT (stopped)", "State:\tS (sleeping)"), encoding="utf-8")

    @staticmethod
    def _eval_nft(tables: dict, cmd: List[str]) -> subprocess.CompletedProcess:
        if len(cmd) >= 5 and cmd[1:4] == ["add", "table", "inet"]:
            tname = cmd[4]
            if tname in tables:
                raise subprocess.CalledProcessError(1, cmd, stderr="File exists")
            tables[tname] = {"chains": {}, "rules": {}}
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if len(cmd) >= 5 and cmd[1:4] == ["flush", "table", "inet"]:
            tname = cmd[4]
            if tname not in tables:
                raise subprocess.CalledProcessError(1, cmd, stderr="No such file or directory")
            tables[tname] = {"chains": {}, "rules": {}}
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if len(cmd) >= 7 and cmd[1:4] == ["add", "chain", "inet"]:
            tname, cname, spec = cmd[4], cmd[5], cmd[6]
            if tname not in tables:
                raise subprocess.CalledProcessError(1, cmd, stderr="No such file or directory")
            tables[tname]["chains"][cname] = spec.strip("{} ").rstrip(" ;")
            tables[tname]["rules"].setdefault(cname, [])
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if len(cmd) >= 7 and cmd[1:4] == ["add", "rule", "inet"]:
            tname, cname = cmd[4], cmd[5]
            if tname not in tables or cname not in tables[tname]["chains"]:
                raise subprocess.CalledProcessError(1, cmd, stderr="No such file or directory")
            tables[tname]["rules"][cname].append(" ".join(cmd[6:]))
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if len(cmd) >= 5 and cmd[1:4] == ["delete", "table", "inet"]:
            tname = cmd[4]
            if tname not in tables:
                raise subprocess.CalledProcessError(1, cmd, stderr="No such file or directory")
            del tables[tname]
            return subprocess.CompletedProcess(cmd, 0, "", "")
        if len(cmd) >= 5 and cmd[1:4] == ["list", "table", "inet"]:
            tname = cmd[4]
            if tname not in tables:
                raise subprocess.CalledProcessError(1, cmd, stderr="No such file or directory")
            lines = [f"table inet {tname} {{"]
            for cname, spec in tables[tname]["chains"].items():
                lines.append(f"\tchain {cname} {{")
                lines.append(f"\t\t{spec}; policy accept;")
                for r in tables[tname]["rules"].get(cname, []):
                    lines.append(f"\t\t{r}")
                lines.append("\t}")
            lines.append("}")
            return subprocess.CompletedProcess(cmd, 0, "\n".join(lines) + "\n", "")
        return subprocess.CompletedProcess(cmd, 0, "", "")

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
        if cmd and cmd[0] == "nft":
            return self._eval_nft(self._nft_a, cmd)
        if len(cmd) >= 2 and cmd[0] == "criu":
            if cmd[1] == "pre-dump":
                idx = cmd.index("--images-dir")
                img_dir = Path(cmd[idx + 1])
                size = self.predump_sizes[min(self._predump_idx, len(self.predump_sizes) - 1)]
                self._predump_idx += 1
                # Write synthetic page image with sparse size so dirty byte tracker reads it
                pages_file = img_dir / "pages-1.img"
                with pages_file.open("wb") as f:
                    f.truncate(size)
            elif cmd[1] == "dump":
                idx = cmd.index("--images-dir")
                img_dir = Path(cmd[idx + 1])
                (img_dir / "core-1234.img").write_bytes(b"SECRET_KEY_MATERIAL_IN_RAM")
                (img_dir / "pages-1.img").write_bytes(b"COLD_PAGES_RAM_DATA")

            if "--page-server" in cmd and "--images-dir" in cmd:
                idx = cmd.index("--images-dir")
                src_img_dir = Path(cmd[idx + 1]).resolve()
                try:
                    rel = src_img_dir.relative_to(self.work_a)
                    dest_img_dir = self.work_b / rel
                    dest_img_dir.mkdir(parents=True, exist_ok=True)
                    src_pages = src_img_dir / "pages-1.img"
                    dest_pages = dest_img_dir / "pages-1.img"
                    if src_pages.exists():
                        shutil.copy2(src_pages, dest_pages)
                    else:
                        dest_pages.write_bytes(b"PAGE_SERVER_PAGES_DATA")
                except ValueError:
                    pass

        elif cmd and cmd[0] == "rsync":
            src_str = cmd[-2].rstrip("/")
            src_path = Path(src_str).resolve()
            try:
                rel = src_path.relative_to(self.work_a)
                dest_path = self.work_b / rel
                dest_path.mkdir(parents=True, exist_ok=True)
                exclude_pages = any("--exclude=pages-*.img" in arg for arg in cmd)
                if src_path.exists():
                    for item in src_path.iterdir():
                        if not item.is_file():
                            continue
                        if item.name == "manifest.sig.json":
                            shutil.copy2(item, dest_path / item.name)
                        elif item.name.endswith(".img"):
                            if exclude_pages and item.name.startswith("pages-"):
                                continue
                            shutil.copy2(item, dest_path / item.name)
            except ValueError:
                pass

        return subprocess.CompletedProcess(cmd, 0, "CRIU 4.3\n", "")

    def _run_b(self, cmd: List[str]) -> subprocess.CompletedProcess:
        self.commands_b.append(cmd)
        if cmd and cmd[0] == "nft":
            return self._eval_nft(self._nft_b, cmd)
        if len(cmd) >= 2 and cmd[0] == "criu" and cmd[1] == "restore":
            if self.fail_on_restore:
                raise RuntimeError("Simulated CRIU restore failure on Destination B")
            if "--pidfile" in cmd:
                idx = cmd.index("--pidfile")
                Path(cmd[idx + 1]).write_text("5678\n", encoding="utf-8")
            p5678 = self.proc_b / "5678"
            p5678.mkdir(parents=True, exist_ok=True)
            state_line = "State:\tT (stopped)\n" if "--leave-stopped" in cmd else "State:\tS (sleeping)\n"
            (p5678 / "status").write_text(
                f"Name:\tserver\n{state_line}VmRSS:\t65536 kB\nTracerPid:\t0\nNSpid:\t5678\t1\n",
                encoding="utf-8",
            )
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

            orch = MigrationOrchestrator(cfg, src, dst, migration_id="mig-test1", journal_dir=f"{tmp}/wal")
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

            orch = MigrationOrchestrator(cfg, src, dst, migration_id="mig-rollback1", journal_dir=f"{tmp}/wal")
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

            orch = MigrationOrchestrator(cfg, src, dst, migration_id="mig-rollback2", journal_dir=f"{tmp}/wal")
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
