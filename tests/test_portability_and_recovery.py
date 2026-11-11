"""Acceptance and Regression Test Suite for LKMP Process Portability and Crash Recovery.

Verifies:
1. Process-tree recursive inspection discovering child PIDs and surfacing child blockers.
2. Classification of internal/external pipes, sockets, and anon_inodes.
3. Four portability states: BLOCKED, PREPARE, UNKNOWN, and VERIFIED.
4. Consistent Podman-style freeze + volume snapshot ordering:
   quiesce_cmd -> lock_network -> freeze_cgroup (frozen 1) -> criu dump --leave-stopped -> volume_snapshot_cmd.
5. Same-host two-VM CoW snapshot fast path (cow_clone_directory & is_same_host_or_shared_storage).
6. CLI migrate WAL journal creation by default & CLI portability --json command.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
from typing import Any, List
import unittest
from unittest.mock import MagicMock, patch

from lkmp.agent import AgentClient, AgentService, config_to_dict
from lkmp.cli import main as cli_main
from lkmp.config import (
    MigrationConfig,
    TlsConfig,
)
from lkmp.criu_driver import CriuDriver
from lkmp.envelope import EnvelopeManager
from lkmp.fs_sync import FilesystemSyncManager
from lkmp.models import (
    HostCapabilities,
    PortabilityStatus,
    ResourceClassification,
    ResourceFinding,
)
from lkmp.network import NetworkMobilityManager
from lkmp.orchestrator import MigrationOrchestrator
import lkmp.preflight
from lkmp.preflight import (
    assess_portability,
    evaluate_portability,
)


# ==============================================================================
# Unit Test Suite: TestPortabilityAndRecovery
# ==============================================================================

class TestPortabilityAndRecovery(unittest.TestCase):
    """Verifies P0, P1, and P2 extensions for process portability and recovery."""

    def test_01_portability_inspects_all_child_pids_not_just_root(self) -> None:
        """
        Verify that inspect_process_tree discovers child PIDs via /proc/<pid>/task/*/children
        and inspects the child PIDs, surfacing blockers such as anon_inode:[io_uring] or /dev/nvidia0.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc_root = root / "proc"
            root_pid = 1000
            child_pid = 1001

            # Root PID 1000: clean maps, status, fd
            p1000 = proc_root / str(root_pid)
            p1000.mkdir(parents=True, exist_ok=True)
            (p1000 / "status").write_text("Name:\tparent\nVmRSS:\t16384 kB\nTracerPid:\t0\nNSpid:\t1000\n", encoding="utf-8")
            (p1000 / "maps").write_text("", encoding="utf-8")
            (p1000 / "cgroup").write_text("0::/lkmp/w1\n", encoding="utf-8")
            (p1000 / "fd").mkdir(parents=True, exist_ok=True)
            task1000 = p1000 / "task" / str(root_pid)
            task1000.mkdir(parents=True, exist_ok=True)
            (task1000 / "children").write_text(f"{child_pid}\n", encoding="utf-8")

            # Child PID 1001: open anon_inode:[io_uring] blocker!
            p1001 = proc_root / str(child_pid)
            p1001.mkdir(parents=True, exist_ok=True)
            (p1001 / "status").write_text("Name:\tchild\nVmRSS:\t8192 kB\nTracerPid:\t0\nNSpid:\t1001\n", encoding="utf-8")
            (p1001 / "maps").write_text("", encoding="utf-8")
            fd1001 = p1001 / "fd"
            fd1001.mkdir(parents=True, exist_ok=True)
            os.symlink("anon_inode:[io_uring]", fd1001 / "3")

            snapshot = lkmp.preflight.inspect_process_tree(root_pid, proc_root=str(proc_root))

            # Invariant 1: Child PID 1001 is discovered
            self.assertIn(child_pid, snapshot.child_pids)

            # Invariant 2: The blocker in child PID 1001 is surfaced in findings
            io_uring_findings = [
                f for f in snapshot.findings
                if "io_uring" in f.identifier and f.classification == ResourceClassification.BLOCKER
            ]
            self.assertGreaterEqual(
                len(io_uring_findings),
                1,
                "Child process blocker (anon_inode:[io_uring]) was not surfaced in snapshot findings!",
            )

    def test_02_portability_classifies_sockets_pipes_and_anon_inodes(self) -> None:
        """
        Verify process resource classification:
        - Internal pipe (both ends in tree) -> OK
        - External pipe (only one end in tree) -> UNKNOWN (external_pipe)
        - Socket -> NEEDS_FLAG (--tcp-established)
        - anon_inode:[eventpoll] -> OK
        - anon_inode:[custom_driver] -> UNKNOWN
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc_root = root / "proc"
            root_pid = 1000
            child_pid = 1001

            p1000 = proc_root / str(root_pid)
            p1000.mkdir(parents=True, exist_ok=True)
            (p1000 / "status").write_text("Name:\tparent\nVmRSS:\t16384 kB\nTracerPid:\t0\nNSpid:\t1000\n", encoding="utf-8")
            (p1000 / "maps").write_text("", encoding="utf-8")
            (p1000 / "cgroup").write_text("0::/lkmp/w1\n", encoding="utf-8")
            fd1000 = p1000 / "fd"
            fd1000.mkdir(parents=True, exist_ok=True)
            task1000 = p1000 / "task" / str(root_pid)
            task1000.mkdir(parents=True, exist_ok=True)
            (task1000 / "children").write_text(f"{child_pid}\n", encoding="utf-8")

            p1001 = proc_root / str(child_pid)
            p1001.mkdir(parents=True, exist_ok=True)
            (p1001 / "status").write_text("Name:\tchild\nVmRSS:\t8192 kB\nTracerPid:\t0\nNSpid:\t1001\n", encoding="utf-8")
            (p1001 / "maps").write_text("", encoding="utf-8")
            fd1001 = p1001 / "fd"
            fd1001.mkdir(parents=True, exist_ok=True)

            # 1. Internal pipe pipe:[11111]: fd 3 in 1000, fd 4 in 1001
            os.symlink("pipe:[11111]", fd1000 / "3")
            os.symlink("pipe:[11111]", fd1001 / "4")

            # 2. External pipe pipe:[99999]: fd 5 in 1000 only
            os.symlink("pipe:[99999]", fd1000 / "5")

            # 3. Socket socket:[22222]: fd 6 in 1000
            os.symlink("socket:[22222]", fd1000 / "6")

            # 4. anon_inode:[eventpoll]: fd 7 in 1000
            os.symlink("anon_inode:[eventpoll]", fd1000 / "7")

            # 5. anon_inode:[custom_driver]: fd 8 in 1000
            os.symlink("anon_inode:[custom_driver]", fd1000 / "8")

            snapshot = lkmp.preflight.inspect_process_tree(root_pid, proc_root=str(proc_root))

            findings_by_id = {f.identifier: f for f in snapshot.findings}

            # 1. Internal pipe is OK
            self.assertIn("pipe:[11111]", findings_by_id)
            self.assertEqual(findings_by_id["pipe:[11111]"].classification, ResourceClassification.OK)

            # 2. External pipe is UNKNOWN
            self.assertIn("pipe:[99999]", findings_by_id)
            ext_class = getattr(findings_by_id["pipe:[99999]"].classification, "value", str(findings_by_id["pipe:[99999]"].classification))
            self.assertEqual(ext_class.lower(), "unknown")

            # 3. Socket is NEEDS_FLAG (--tcp-established)
            self.assertIn("socket:[22222]", findings_by_id)
            self.assertEqual(findings_by_id["socket:[22222]"].classification, ResourceClassification.NEEDS_FLAG)
            self.assertEqual(findings_by_id["socket:[22222]"].suggested_flag, "--tcp-established")

            # 4. anon_inode:[eventpoll] is OK
            self.assertIn("anon_inode:[eventpoll]", findings_by_id)
            self.assertEqual(findings_by_id["anon_inode:[eventpoll]"].classification, ResourceClassification.OK)

            # 5. anon_inode:[custom_driver] is UNKNOWN
            self.assertIn("anon_inode:[custom_driver]", findings_by_id)
            custom_class = getattr(findings_by_id["anon_inode:[custom_driver]"].classification, "value", str(findings_by_id["anon_inode:[custom_driver]"].classification))
            self.assertEqual(custom_class.lower(), "unknown")

    def test_03_portability_four_states_blocked_prepare_unknown_verified(self) -> None:
        """
        Verify evaluate_portability returns the 4 distinct states:
        - BLOCKED: blocker finding present or missing ISA CPU flag.
        - PREPARE: flags required (ghost limit, socket flag).
        - UNKNOWN: static /proc inspection without dirty sampling or trial restore.
        - VERIFIED: passed trial restore on Destination B with clean rollback.
        """
        # 1. BLOCKED via blocker finding
        blocker_f = ResourceFinding(
            resource_type="fd",
            identifier="anon_inode:[io_uring]",
            classification=ResourceClassification.BLOCKER,
            reason="io_uring",
        )
        self.assertEqual(
            evaluate_portability(findings=[blocker_f]),
            PortabilityStatus.BLOCKED,
        )

        # 1b. BLOCKED via missing ISA flags
        caps_a = HostCapabilities(arch="x86_64", kernel_release="6.1", cpu_vendor="Intel", cpu_flags={"avx", "avx2", "sse4_2"})
        caps_b = HostCapabilities(arch="x86_64", kernel_release="6.1", cpu_vendor="Intel", cpu_flags={"sse4_2"})
        self.assertEqual(
            evaluate_portability(findings=[], source_caps=caps_a, dest_caps=caps_b),
            PortabilityStatus.BLOCKED,
        )

        # 2. PREPARE via needs_flag
        prepare_f = ResourceFinding(
            resource_type="ghost_file",
            identifier="/tmp/deleted.dat",
            classification=ResourceClassification.NEEDS_FLAG,
            reason="exceeds ghost limit",
            suggested_flag="--ghost-limit 134217728",
        )
        self.assertEqual(
            evaluate_portability(findings=[prepare_f]),
            PortabilityStatus.PREPARE,
        )

        # 3. UNKNOWN on static /proc inspection alone
        ok_f = ResourceFinding(
            resource_type="anon_inode",
            identifier="anon_inode:[eventpoll]",
            classification=ResourceClassification.OK,
            reason="eventpoll",
        )
        self.assertEqual(
            evaluate_portability(findings=[ok_f], dirty_rate_actively_sampled=False, trial_restore_passed=False),
            PortabilityStatus.UNKNOWN,
        )

        # 4. VERIFIED ONLY after assess_portability(run_check_only=True, run_trial_restore=True)
        # executes the isolated trial restore on Destination B and rolls back cleanly to Source A!
        self.assertEqual(
            evaluate_portability(findings=[ok_f], dirty_rate_actively_sampled=True, trial_restore_passed=True),
            PortabilityStatus.VERIFIED,
        )

        cfg = MigrationConfig(
            pid=1234,
            source_addr="10.0.0.1:9700",
            dest_addr="10.0.0.2:9700",
            tls=TlsConfig(enabled=False),
        )
        mock_src = MagicMock(spec=AgentClient)
        mock_dst = MagicMock(spec=AgentClient)
        mock_src.host = "10.0.0.1"
        mock_dst.host = "10.0.0.2"
        mock_src.call.side_effect = lambda method, **kw: {
            "get_capabilities": {"arch": "x86_64", "kernel_release": "6.1", "cpu_vendor": "Intel", "cpu_flags": ["avx", "sse4_2"], "criu_available": True, "has_userfaultfd": True, "has_soft_dirty": True},
            "inspect_process": {"root_pid": 1234, "child_pids": [], "rss_bytes": 1024, "dirty_rate_bytes_per_sec": 0, "files": [], "findings": [], "in_envelope": True},
            "prepare_migration": {},
            "freeze_and_final_dump": {"images_dir": "/tmp/img"},
            "transfer_final_state": {},
            "release_ip": {},
            "rollback_source": {"rolled_back_source": True},
        }.get(method, {})
        mock_dst.call.side_effect = lambda method, **kw: {
            "get_capabilities": {"arch": "x86_64", "kernel_release": "6.1", "cpu_vendor": "Intel", "cpu_flags": ["avx", "sse4_2"], "criu_available": True, "has_userfaultfd": True, "has_soft_dirty": True},
            "stat_files": {},
            "prepare_migration": {},
            "restore_process": {"restored_pid": 5678},
            "verify_restored_stopped": {"healthy": True},
            "rollback_dest": {"rolled_back_dest": True},
        }.get(method, {})

        assessed_status = assess_portability(
            config=cfg,
            source_client=mock_src,
            dest_client=mock_dst,
            run_check_only=True,
            run_trial_restore=True,
        )
        self.assertEqual(assessed_status, PortabilityStatus.VERIFIED)

    def test_04_consistent_podman_style_freeze_and_volume_snapshot(self) -> None:
        """
        Verify consistent Podman-style freeze + volume snapshot ordering:
        quiesce_cmd -> lock_network -> freeze_cgroup (frozen 1) -> criu dump --leave-stopped -> volume_snapshot_cmd.
        """
        execution_order: List[str] = []

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work_dir = root / "work"
            proc_dir = root / "proc"
            cg_dir = root / "cgroup"
            work_dir.mkdir(parents=True, exist_ok=True)
            proc_dir.mkdir(parents=True, exist_ok=True)
            cg_dir.mkdir(parents=True, exist_ok=True)

            wl_cg = cg_dir / "wl-snap"
            wl_cg.mkdir(parents=True, exist_ok=True)
            (wl_cg / "cgroup.freeze").write_text("0\n", encoding="utf-8")
            (wl_cg / "cgroup.events").write_text("populated 1\nfrozen 1\n", encoding="utf-8")

            p1000 = proc_dir / "1000"
            p1000.mkdir(parents=True, exist_ok=True)
            (p1000 / "stat").write_text("1000 (app) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 100 0\n", encoding="utf-8")
            (p1000 / "status").write_text("Name:\tapp\nVmRSS:\t16384 kB\n", encoding="utf-8")

            nft_cmds: List[List[str]] = []

            def mock_runner(cmd: List[str]) -> subprocess.CompletedProcess:
                if cmd and cmd[0] == "nft":
                    nft_cmds.append(list(cmd))
                    if not execution_order or execution_order[-1] != "lock_network":
                        execution_order.append("lock_network")
                elif cmd and cmd[0] == "criu":
                    execution_order.append("criu dump --leave-stopped")
                return subprocess.CompletedProcess(cmd, 0, "", "")

            env = EnvelopeManager(cgroup_root=str(cg_dir), runner=mock_runner)
            orig_freeze = env.freeze_cgroup

            def hooked_freeze(w_id: str, timeout_sec: float = 5.0) -> Path:
                execution_order.append("freeze_cgroup")
                return orig_freeze(w_id, timeout_sec)

            env.freeze_cgroup = hooked_freeze

            service = AgentService(
                work_dir=str(work_dir),
                proc_root=str(proc_dir),
                criu_driver=CriuDriver(runner=mock_runner),
                net_manager=NetworkMobilityManager(runner=mock_runner),
                envelope_manager=env,
                pid_alive_checker=lambda _p: True,
            )

            cfg = MigrationConfig(
                pid=1000,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                workload_id="wl-snap",
                workload_ip="10.0.0.55",
                quiesce_cmd="touch_quiesce",
                tls=TlsConfig(enabled=False),
            )
            cfg_dict = config_to_dict(cfg)
            cfg_dict["volume_snapshot_cmd"] = "touch_vol_snap"

            with patch("subprocess.run") as mock_subproc:
                def fake_subproc(cmd: Any, **kwargs: Any) -> subprocess.CompletedProcess:
                    cmd_list = cmd if isinstance(cmd, list) else shlex.split(str(cmd))
                    if "touch_quiesce" in cmd_list:
                        execution_order.append("quiesce_cmd")
                    elif "touch_vol_snap" in cmd_list:
                        execution_order.append("volume_snapshot_cmd")
                    return subprocess.CompletedProcess(cmd_list, 0, "", "")

                mock_subproc.side_effect = fake_subproc

                service.prepare_migration("mig-order-snap")
                service.freeze_and_final_dump(
                    migration_id="mig-order-snap",
                    prev_round_name=None,
                    dest_host="10.0.0.2",
                    config_dict=cfg_dict,
                )

                expected_order = [
                    "quiesce_cmd",
                    "lock_network",
                    "freeze_cgroup",
                    "criu dump --leave-stopped",
                    "volume_snapshot_cmd",
                ]
                self.assertEqual(execution_order, expected_order)
                self.assertEqual(len(nft_cmds), 1)
                self.assertIn("flush table inet", nft_cmds[0][1])
                self.assertEqual(nft_cmds[0][1].count(" drop;"), 2)

    def test_05_same_host_cow_fast_path(self) -> None:
        """
        Verify FilesystemSyncManager.cow_clone_directory clones .img files respecting include_pages,
        and FilesystemSyncManager.is_same_host_or_shared_storage rejects address/loopback heuristics
        and requires cryptographic storage-probe verification.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            src_dir = root / "src_img"
            dst_dir_nopages = root / "dst_nopages"
            dst_dir_all = root / "dst_all"
            src_dir.mkdir(parents=True, exist_ok=True)

            # Create test images
            (src_dir / "core-1.img").write_bytes(b"CORE_REGISTERS")
            (src_dir / "manifest.sig.json").write_text('{"merkle": "abc"}', encoding="utf-8")
            (src_dir / "pages-1.img").write_bytes(b"MEMORY_PAGES_DATA" * 1024)

            # 1. Clone with include_pages=False (excludes pages-*.img)
            cloned_nopages = FilesystemSyncManager.cow_clone_directory(
                src_dir, dst_dir_nopages, include_pages=False
            )
            self.assertTrue((dst_dir_nopages / "core-1.img").exists())
            self.assertTrue((dst_dir_nopages / "manifest.sig.json").exists())
            self.assertFalse((dst_dir_nopages / "pages-1.img").exists())
            self.assertEqual(len(cloned_nopages), 2)

            # 2. Clone with include_pages=True (includes pages-*.img)
            cloned_all = FilesystemSyncManager.cow_clone_directory(
                src_dir, dst_dir_all, include_pages=True
            )
            self.assertTrue((dst_dir_all / "core-1.img").exists())
            self.assertTrue((dst_dir_all / "manifest.sig.json").exists())
            self.assertTrue((dst_dir_all / "pages-1.img").exists())
            self.assertEqual(len(cloned_all), 3)

            # 3. Address/loopback equality NEVER suffices without verified shared storage probe
            self.assertFalse(FilesystemSyncManager.is_same_host_or_shared_storage("10.0.0.1:9700", "10.0.0.1:9701"))
            self.assertFalse(FilesystemSyncManager.is_same_host_or_shared_storage("127.0.0.1:9700", "127.0.0.1:9701"))
            self.assertFalse(FilesystemSyncManager.is_same_host_or_shared_storage("localhost:9700", "127.0.0.1:9700"))
            self.assertFalse(FilesystemSyncManager.is_same_host_or_shared_storage("10.0.0.1:9700", "10.0.0.2:9700"))
            self.assertFalse(
                FilesystemSyncManager.is_same_host_or_shared_storage(
                    "127.0.0.1:9700", "127.0.0.1:9701", source_dir=src_dir, dest_dir=dst_dir_all
                )
            )
            (dst_dir_all / ".lkmp_storage_probe.json").write_text(
                json.dumps({"agent_id": "agent-b", "migration_id": "m1", "token": "tok-123"}),
                encoding="utf-8",
            )
            self.assertTrue(
                FilesystemSyncManager.is_same_host_or_shared_storage(
                    "10.0.0.1:9700",
                    "10.0.0.2:9700",
                    source_dir=src_dir,
                    dest_dir=dst_dir_all,
                    expected_probe_token="tok-123",
                    source_agent_id="agent-a",
                    expected_migration_id="m1",
                )
            )

    def test_06_cli_migrate_enables_wal_by_default_and_cli_portability_command(self) -> None:
        """
        Verify `lkmp portability --json` outputs valid JSON,
        and `lkmp migrate` creates a durable `.wal.jsonl` file in `--journal-dir`.
        """
        with tempfile.TemporaryDirectory() as tmp:
            wal_dir = Path(tmp) / "journals"
            wal_dir.mkdir(parents=True, exist_ok=True)

            # Mock AgentClients
            mock_src = MagicMock(spec=AgentClient)
            mock_src.host = "10.0.0.1"
            mock_dst = MagicMock(spec=AgentClient)
            mock_dst.host = "10.0.0.2"

            mock_src.call.side_effect = lambda method, **kw: {
                "get_capabilities": {"arch": "x86_64", "kernel_release": "6.1", "cpu_vendor": "Intel", "cpu_flags": ["avx", "sse4_2"], "criu_available": True, "has_userfaultfd": True, "has_soft_dirty": True},
                "inspect_process": {"root_pid": 1234, "child_pids": [], "rss_bytes": 1024, "dirty_rate_bytes_per_sec": 0, "files": [], "findings": [], "in_envelope": True},
                "prepare_migration": {},
                "freeze_and_final_dump": {"images_dir": "/tmp/img"},
                "transfer_final_state": {},
                "release_ip": {},
                "commit_source": {},
            }.get(method, {})

            mock_dst.call.side_effect = lambda method, **kw: {
                "get_capabilities": {"arch": "x86_64", "kernel_release": "6.1", "cpu_vendor": "Intel", "cpu_flags": ["avx", "sse4_2"], "criu_available": True, "has_userfaultfd": True, "has_soft_dirty": True},
                "stat_files": {},
                "prepare_migration": {},
                "restore_process": {"restored_pid": 5678},
                "claim_ip_and_resume": {},
                "verify_process": {"healthy": True},
                "cleanup_dest": {},
            }.get(method, {})

            # 1. Test real `lkmp portability --json` CLI path against mocked AgentClients
            captured_stdout = io.StringIO()
            with patch(
                "lkmp.cli.AgentClient",
                side_effect=lambda addr, **kw: mock_src if "10.0.0.1" in addr else mock_dst,
            ), patch("sys.stdout", captured_stdout):
                code = cli_main([
                    "portability",
                    "--pid", "1234",
                    "--source", "10.0.0.1:9700",
                    "--dest", "10.0.0.2:9700",
                    "--json",
                    "--no-tls",
                ])
            self.assertEqual(code, 0)
            output = captured_stdout.getvalue()
            parsed_json = json.loads(output)
            self.assertIn("status", parsed_json)

            # 2. Test `lkmp migrate` creates .wal.jsonl in --journal-dir
            cfg = MigrationConfig(
                pid=1234,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                journal_dir=str(wal_dir),
                tls=TlsConfig(enabled=False),
            )

            orch = MigrationOrchestrator(
                config=cfg,
                source_client=mock_src,
                dest_client=mock_dst,
                migration_id="mig-cli-wal",
                journal_dir=wal_dir,
            )
            res = orch.execute()
            self.assertTrue(res.success)

            wal_file = wal_dir / "mig-cli-wal.wal.jsonl"
            self.assertTrue(wal_file.exists(), f"WAL file {wal_file} was not created by orchestrator!")
            wal_lines = [json.loads(line) for line in wal_file.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertGreaterEqual(len(wal_lines), 3)
            decisions = [entry.get("commit_decision") for entry in wal_lines]
            self.assertIn("COMMITTED", decisions)


if __name__ == "__main__":
    unittest.main()
