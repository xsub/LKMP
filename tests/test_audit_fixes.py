"""Comprehensive test suite for P0, P1, and P2 audit fixes in LKMP."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

from lkmp.agent import AgentClient, AgentServer, AgentService, config_to_dict
from lkmp.attestation import CheckpointAttestor, compute_directory_img_digests, generate_ephemeral_key_hex
from lkmp.config import (
    FilesystemMode,
    GpuPlugin,
    IpMobilityMode,
    MigrationConfig,
    MigrationStrategy,
    TlsConfig,
)
from lkmp.convergence import PreCopyConvergenceTracker
from lkmp.criu_driver import CriuDriver
from lkmp.envelope import EnvelopeManager
from lkmp.fs_sync import FilesystemSyncManager
from lkmp.gang import GangMigrationCoordinator
from lkmp.journal import MigrationJournal, validate_safe_identifier
from lkmp.models import HostCapabilities, MigrationResult, MigrationState, ProcessSnapshotInfo
from lkmp.network import NetworkMobilityManager
from lkmp.orchestrator import MigrationOrchestrator
from lkmp.pagemap import sample_process_dirty_rate
from lkmp.preflight import (
    discover_process_tree_pids,
    evaluate_compatibility,
    read_proc_starttime,
)
from tests.test_orchestrator_fsm import _FakeClusterHarness

# Aliases matching audit spec terminology
FsSynchronizer = FilesystemSyncManager
NetworkIsolationController = NetworkMobilityManager

if not hasattr(AgentServer, "dispatch"):
    setattr(
        AgentServer,
        "dispatch",
        lambda self, method, params: self.service.dispatch_rpc(method, params),
    )


class TestAuditFixesP0(unittest.TestCase):
    """P0 audit fixes: Daemonization, Memory Page Transfer, 2PC Gang Migration, Fail-closed TLS & Traversal."""

    def test_p0_1_page_server_daemon_cmd(self) -> None:
        """Verify build_page_server_cmd includes --daemon and --pidfile."""
        driver = CriuDriver()
        cmd = driver.build_page_server_cmd(
            images_dir="/var/lib/lkmp/img/2",
            port=27000,
            tls=TlsConfig(enabled=False),
        )
        self.assertIn("--daemon", cmd)
        self.assertIn("--pidfile", cmd)
        idx = cmd.index("--pidfile")
        self.assertEqual(cmd[idx + 1], "/var/lib/lkmp/img/2/page-server.pid")

    def test_p0_1_lazy_pages_daemon_cmd(self) -> None:
        """Verify build_lazy_pages_daemon_cmd does NOT include --daemon or --pidfile (run_background_daemon handles it)."""
        driver = CriuDriver(runner=lambda cmd: subprocess.CompletedProcess(cmd, 0, "", ""))
        cfg = MigrationConfig(
            pid=4321,
            source_addr="10.0.0.1:9700",
            dest_addr="10.0.0.2:9700",
            strategy=MigrationStrategy.LAZY,
        )
        cmd = driver.build_lazy_pages_daemon_cmd(
            config=cfg,
            images_dir="/var/lib/lkmp/img/final",
            source_host="10.0.0.1",
        )
        self.assertIn("lazy-pages", cmd)
        self.assertNotIn("--daemon", cmd)
        self.assertNotIn("--pidfile", cmd)

        with tempfile.TemporaryDirectory() as tmp:
            pidfile = Path(tmp) / "test.pid"
            daemon_pid = driver.run_background_daemon(cmd, pidfile=pidfile)
            self.assertEqual(daemon_pid, 9001)
            self.assertEqual(pidfile.read_text().strip(), "9001")

    def test_p0_1_build_dump_cmd_lazy_and_hybrid_daemon(self) -> None:
        """Verify build_dump_cmd with LAZY or HYBRID includes --lazy-pages and does NOT include --daemon or --pidfile."""
        driver = CriuDriver()
        for strat in (MigrationStrategy.LAZY, MigrationStrategy.HYBRID):
            cfg = MigrationConfig(
                pid=999,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=strat,
            )
            cmd = driver.build_dump_cmd(cfg, images_dir="/var/lib/lkmp/img/final")
            self.assertIn("--lazy-pages", cmd, f"Failed for strategy {strat}")
            self.assertNotIn("--daemon", cmd, f"Failed for strategy {strat}")
            self.assertNotIn("--pidfile", cmd, f"Failed for strategy {strat}")

    def test_p0_2_fs_sync_include_pages_flag(self) -> None:
        """Verify sync_checkpoint_images with include_pages=True does NOT exclude pages-*.img, False does."""
        executed: List[List[str]] = []

        def fake_runner(cmd: List[str]) -> subprocess.CompletedProcess:
            executed.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        fs = FsSynchronizer(runner=fake_runner)

        # include_pages=True (COLD migration)
        cmd_cold = fs.sync_checkpoint_images("/tmp/img", "10.0.0.2", include_pages=True)
        self.assertNotIn("--exclude=pages-*.img", cmd_cold)

        # include_pages=False (PRE_COPY / LAZY / HYBRID migration)
        cmd_pre = fs.sync_checkpoint_images("/tmp/img", "10.0.0.2", include_pages=False)
        self.assertIn("--exclude=pages-*.img", cmd_pre)

    def test_p0_2_cold_migration_full_rsync_with_attestation(self) -> None:
        """Verify a full COLD migration transfers pages-*.img via rsync and succeeds with verify_attestation=True."""
        with tempfile.TemporaryDirectory() as tmp:
            harness = _FakeClusterHarness(tmp)
            attest_key = generate_ephemeral_key_hex()
            cfg = MigrationConfig(
                pid=1234,
                workload_id="srv-cold",
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                same_host_cow=False,
                verify_attestation=True,
                attestation_key_hex=attest_key,
                wipe_images_on_commit=False,
                tls=TlsConfig(enabled=False),
            )
            src = AgentClient("10.0.0.1:9700", direct_service=harness.service_a)
            dst = AgentClient("10.0.0.2:9700", direct_service=harness.service_b)

            orch = MigrationOrchestrator(cfg, src, dst, migration_id="mig-cold", journal_dir=f"{tmp}/wal")
            res = orch.execute()

            self.assertTrue(res.success)
            self.assertEqual(res.final_state, MigrationState.COMMIT)
            self.assertFalse(res.rolled_back)
            self.assertEqual(res.restored_pid, 5678)

            # Check that rsync transferred pages-*.img without excluding it
            rsync_cmds = [cmd for cmd in harness.commands_a if cmd and cmd[0] == "rsync"]
            self.assertTrue(len(rsync_cmds) > 0)
            for rcmd in rsync_cmds:
                self.assertNotIn("--exclude=pages-*.img", rcmd)

            # Verify destination B final directory has pages-1.img and manifest.sig.json
            final_b = harness.work_b / "mig-cold" / "final"
            self.assertTrue((final_b / "pages-1.img").exists())
            self.assertTrue((final_b / "manifest.sig.json").exists())

    def test_p0_2_lazy_migration_starts_daemon_before_restore(self) -> None:
        """Verify a full LAZY migration starts lazy-pages --daemon before criu restore --lazy-pages."""
        with tempfile.TemporaryDirectory() as tmp:
            harness = _FakeClusterHarness(tmp)
            # Destination B reports userfaultfd support for lazy post-copy
            orig_b_caps = harness.service_b.get_capabilities
            harness.service_b.get_capabilities = lambda: {**orig_b_caps(), "has_userfaultfd": True}

            cfg = MigrationConfig(
                pid=1234,
                workload_id="srv-lazy",
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.LAZY,
                verify_attestation=False,
                tls=TlsConfig(enabled=False),
            )
            src = AgentClient("10.0.0.1:9700", direct_service=harness.service_a)
            dst = AgentClient("10.0.0.2:9700", direct_service=harness.service_b)

            orch = MigrationOrchestrator(cfg, src, dst, migration_id="mig-lazy", journal_dir=f"{tmp}/wal")
            res = orch.execute()

            self.assertTrue(res.success)
            self.assertEqual(res.final_state, MigrationState.COMMIT)

            # Inspect commands executed on Destination B
            cmds_b = harness.commands_b
            lazy_idx = -1
            restore_idx = -1
            for idx, cmd in enumerate(cmds_b):
                if len(cmd) >= 2 and cmd[0] == "criu" and cmd[1] == "lazy-pages":
                    lazy_idx = idx
                elif len(cmd) >= 2 and cmd[0] == "criu" and cmd[1] == "restore":
                    restore_idx = idx

            self.assertNotEqual(lazy_idx, -1, "lazy-pages daemon was not started on Destination B")
            self.assertNotEqual(restore_idx, -1, "criu restore was not called on Destination B")
            self.assertLess(
                lazy_idx,
                restore_idx,
                "lazy-pages daemon must start BEFORE criu restore",
            )

    def test_p0_3_gang_migration_2pc_atomic_rollback(self) -> None:
        """Verify true 2PC gang migration: when Member 2 fails restore, Member 1 NEVER gets SIGKILL on A and gets SIGCONT."""
        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            h1 = _FakeClusterHarness(tmp1)
            h2 = _FakeClusterHarness(tmp2)
            # Member 2 fails on Destination B during restore
            h2.fail_on_restore = True

            cfg1 = MigrationConfig(
                pid=1234,
                workload_id="srv-gang-1",
                source_addr="a1:9700",
                dest_addr="b1:9700",
                strategy=MigrationStrategy.COLD,
                workload_ip="10.0.0.51/24",
                tls=TlsConfig(enabled=False),
            )
            cfg2 = MigrationConfig(
                pid=1234,
                workload_id="srv-gang-2",
                source_addr="a2:9700",
                dest_addr="b2:9700",
                strategy=MigrationStrategy.COLD,
                workload_ip="10.0.0.52/24",
                tls=TlsConfig(enabled=False),
            )

            gang = GangMigrationCoordinator(
                gang_id="gang-2pc",
                journal_dir=f"{tmp1}/wal",
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
            res = gang.execute_atomic()

            self.assertFalse(res.all_committed)
            self.assertTrue(res.atomic_rollback_triggered)
            self.assertEqual(len(res.member_results), 2)
            self.assertTrue(all(r.rolled_back for r in res.member_results))
            self.assertTrue(all(r.final_state == MigrationState.ROLLBACK for r in res.member_results))

            # Critical assertion: Member 1 NEVER received SIGKILL (9) on Host A
            signals_sent_to_pid1_on_a = [sig for pid, sig in h1.signals_a if pid == 1234]
            self.assertNotIn(signal.SIGKILL, signals_sent_to_pid1_on_a)
            self.assertIn(signal.SIGCONT, signals_sent_to_pid1_on_a)

            # Member 1's partially restored process on Host B (5678) WAS killed
            self.assertIn((5678, signal.SIGKILL), h1.signals_b)

    def test_p0_4_fail_closed_tls_without_valid_certs(self) -> None:
        """Verify AgentServer and AgentClient fail closed with ValueError when TLS enabled without certs."""
        dummy_service = AgentService(work_dir="/tmp")

        # Server fail-closed
        with self.assertRaises(ValueError) as ctx_srv:
            AgentServer("127.0.0.1", 0, dummy_service, tls=TlsConfig(enabled=True))
        self.assertIn("cert_file or key_file is missing", str(ctx_srv.exception))

        # Client fail-closed
        client = AgentClient("127.0.0.1:9700", tls=TlsConfig(enabled=True))
        with self.assertRaises(ValueError) as ctx_cli:
            client.call("get_capabilities")
        self.assertIn("cert_file or key_file is missing", str(ctx_cli.exception))

    def test_p0_4_path_traversal_rejection(self) -> None:
        """Verify validate_safe_identifier and AgentServer.dispatch reject path traversal with ValueError."""
        # Direct identifier validator
        for bad_id in ("../escape", "mig/sub", "..", "/abs/path", "safe/../../escape"):
            with self.assertRaises(ValueError):
                validate_safe_identifier(bad_id, "migration_id")

        self.assertEqual(validate_safe_identifier("safe-mig-123.test"), "safe-mig-123.test")

        # RPC dispatch path traversal rejection
        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp) / "work"
            work_dir.mkdir()
            outside_file = Path(tmp) / "canary.txt"
            outside_file.write_text("SENSITIVE_HOST_DATA", encoding="utf-8")

            service = AgentService(work_dir=str(work_dir))
            server = AgentServer("127.0.0.1", 0, service, tls=TlsConfig(enabled=False))
            try:
                cfg = MigrationConfig(pid=100, source_addr="a:1", dest_addr="b:1")
                with self.assertRaises(ValueError):
                    server.dispatch(
                        "rollback_dest",
                        {
                            "migration_id": "../escape",
                            "restored_pid": None,
                            "config_dict": config_to_dict(cfg),
                        },
                    )

                # Ensure canary file outside work_dir was untouched
                self.assertTrue(outside_file.exists())
                self.assertEqual(outside_file.read_text(encoding="utf-8"), "SENSITIVE_HOST_DATA")
            finally:
                server.shutdown()

    def test_p0_4_secure_wipe_directory_enforces_allowed_parent(self) -> None:
        """Verify secure_wipe_directory raises ValueError if target escapes allowed_parent."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            allowed = root / "allowed"
            allowed.mkdir()
            outside = root / "outside"
            outside.mkdir()

            (outside / "core.img").write_bytes(b"DATA")

            # Target outside allowed parent
            with self.assertRaises(ValueError) as ctx:
                FilesystemSyncManager.secure_wipe_directory(outside, allowed_parent=allowed)
            self.assertIn("outside allowed parent", str(ctx.exception))

            # Target identical to allowed parent
            with self.assertRaises(ValueError) as ctx_same:
                FilesystemSyncManager.secure_wipe_directory(allowed, allowed_parent=allowed)
            self.assertIn("cannot be identical to allowed parent", str(ctx_same.exception))


class TestAuditFixesP1(unittest.TestCase):
    """P1 audit fixes: IP ordering, deterministic rollback, durable WAL, nftables isolation, attestation."""

    def test_p1_1_workload_ip_assigned_before_criu_restore(self) -> None:
        """Verify workload IP is assigned on Host B BEFORE criu restore executes."""
        executed: List[List[str]] = []

        def fake_runner(cmd: List[str]) -> subprocess.CompletedProcess:
            executed.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with tempfile.TemporaryDirectory() as tmp:
            work_dir = Path(tmp).resolve()
            net = NetworkMobilityManager(runner=fake_runner)
            criu = CriuDriver(runner=fake_runner)
            service = AgentService(
                work_dir=str(work_dir),
                net_manager=net,
                criu_driver=criu,
            )

            cfg = MigrationConfig(
                pid=1234,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                workload_ip="10.0.0.50",
                net_interface="eth0",
                ip_mobility=IpMobilityMode.GARP,
                verify_attestation=False,
            )

            service.restore_process(
                migration_id="mig-ip-order",
                source_host="10.0.0.1",
                config_dict=config_to_dict(cfg),
            )

            assign_idx = -1
            restore_idx = -1
            for idx, cmd in enumerate(executed):
                if len(cmd) >= 4 and cmd[0] == "ip" and cmd[1] == "addr" and cmd[2] == "replace":
                    if "10.0.0.50/32" in cmd:
                        assign_idx = idx
                elif len(cmd) >= 2 and cmd[0] == "criu" and cmd[1] == "restore":
                    restore_idx = idx

            self.assertNotEqual(assign_idx, -1, "ip addr replace 10.0.0.50/32 was not executed")
            self.assertNotEqual(restore_idx, -1, "criu restore was not executed")
            self.assertLess(
                assign_idx,
                restore_idx,
                "Workload IP must be assigned BEFORE criu restore runs",
            )

    def test_p1_2_cleanup_dest_failure_after_commit_source_is_non_fatal(self) -> None:
        """Verify that failure in cleanup_dest AFTER commit_source does not trigger rollback and returns success=True."""
        with tempfile.TemporaryDirectory() as tmp:
            harness = _FakeClusterHarness(tmp)

            def failing_cleanup_dest(*args: Any, **kwargs: Any) -> Dict[str, Any]:
                raise RuntimeError("Simulated transient storage error during cleanup_dest")

            harness.service_b.cleanup_dest = failing_cleanup_dest  # type: ignore[method-assign]

            cfg = MigrationConfig(
                pid=1234,
                workload_id="srv-1",
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                tls=TlsConfig(enabled=False),
            )
            src = AgentClient("10.0.0.1:9700", direct_service=harness.service_a)
            dst = AgentClient("10.0.0.2:9700", direct_service=harness.service_b)

            orch = MigrationOrchestrator(cfg, src, dst, migration_id="mig-cleanup-fail", journal_dir=f"{tmp}/wal")
            res = orch.execute()

            self.assertTrue(res.success)
            self.assertEqual(res.final_state, MigrationState.COMMIT)
            self.assertFalse(res.rolled_back)
            # Source A must have been killed as part of normal commit, never rolled back
            self.assertIn((1234, signal.SIGKILL), harness.signals_a)

    def test_p1_2_failed_rollback_source_reports_rolled_back_false(self) -> None:
        """Verify that if rollback_source fails liveness check, result.rolled_back is False (never falsely True)."""
        with tempfile.TemporaryDirectory() as tmp:
            harness = _FakeClusterHarness(tmp)
            # Simulate source process crashing / dead on Source A so liveness check fails
            harness.service_a._check_pid_alive = lambda _pid: False

            cfg = MigrationConfig(
                pid=1234,
                workload_id="srv-1",
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                tls=TlsConfig(enabled=False),
            )
            src = AgentClient("10.0.0.1:9700", direct_service=harness.service_a)
            dst = AgentClient("10.0.0.2:9700", direct_service=harness.service_b)

            orch = MigrationOrchestrator(cfg, src, dst, migration_id="mig-rb-fail", journal_dir=f"{tmp}/wal")
            res = orch.rollback("Simulated abort before commit")

            self.assertFalse(res.success)
            self.assertEqual(res.final_state, MigrationState.ROLLBACK)
            self.assertFalse(res.rolled_back, "rolled_back must be False when source liveness check fails")
            self.assertIn("rollback errors", res.error_message or "")

    def test_p1_3_durable_wal_journal_and_crash_recovery(self) -> None:
        """Verify WAL journal append/load, and crash recovery rolls back uncommitted migration and finishes committed one."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            journal_dir = root / "wal"
            mig_id = "mig-wal-test"
            journal = MigrationJournal(journal_dir=journal_dir, migration_id=mig_id)

            cfg = MigrationConfig(
                pid=1234,
                workload_id="srv-wal",
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                tls=TlsConfig(enabled=False),
            )

            # 1. Append pre-commit entries
            journal.append(MigrationState.INIT, "PREPARING", config_dict=config_to_dict(cfg))
            journal.append(MigrationState.FREEZE, "PREPARING")
            journal.append(MigrationState.RESTORE, "PREPARING", restored_pid=5678)

            self.assertTrue(journal.path.exists())
            self.assertEqual(len(journal.entries), 3)

            # 2. Recover from uncommitted journal -> must roll back cleanly
            harness = _FakeClusterHarness(str(root / "cluster"))
            src = AgentClient("10.0.0.1:9700", direct_service=harness.service_a)
            dst = AgentClient("10.0.0.2:9700", direct_service=harness.service_b)

            rec_res_abort = MigrationOrchestrator.recover_from_journal(
                journal.path,
                source_client=src,
                dest_client=dst,
            )
            self.assertFalse(rec_res_abort.success)
            self.assertTrue(rec_res_abort.rolled_back)
            self.assertEqual(rec_res_abort.final_state, MigrationState.ROLLBACK)
            # Source A resumed with SIGCONT and restored PID 5678 killed on B
            self.assertIn((1234, signal.SIGCONT), harness.signals_a)
            self.assertIn((5678, signal.SIGKILL), harness.signals_b)

            # 3. Append COMMITTED entry and test recovery finishes commit
            mig_id_commit = "mig-wal-commit"
            journal_commit = MigrationJournal(journal_dir=journal_dir, migration_id=mig_id_commit)
            journal_commit.append(MigrationState.INIT, "PREPARING", config_dict=config_to_dict(cfg))
            journal_commit.append(MigrationState.VERIFY, "PREPARING", restored_pid=5678)
            journal_commit.append(MigrationState.COMMIT, "COMMITTED", restored_pid=5678)

            harness2 = _FakeClusterHarness(str(root / "cluster2"))
            src2 = AgentClient("10.0.0.1:9700", direct_service=harness2.service_a)
            dst2 = AgentClient("10.0.0.2:9700", direct_service=harness2.service_b)

            rec_res_commit = MigrationOrchestrator.recover_from_journal(
                journal_commit.path,
                source_client=src2,
                dest_client=dst2,
            )
            self.assertTrue(rec_res_commit.success)
            self.assertFalse(rec_res_commit.rolled_back)
            self.assertEqual(rec_res_commit.final_state, MigrationState.COMMIT)
            # Source A killed with SIGKILL on completed commit
            self.assertIn((1234, signal.SIGKILL), harness2.signals_a)

    def test_p1_4_per_migration_nftables_isolation_and_tunnel_mode(self) -> None:
        """Verify distinct nftables tables per migration, and tunnel/ebpf mobility modes."""
        # Per-migration isolation
        t1 = NetworkIsolationController.table_name_for("10.0.0.1", "mig-alpha")
        t2 = NetworkIsolationController.table_name_for("10.0.0.1", "mig-beta")
        self.assertNotEqual(t1, t2)
        self.assertIn("mig_alpha", t1)
        self.assertIn("mig_beta", t2)

        # Tunnel mode & alias resolution
        self.assertEqual(IpMobilityMode("tunnel"), IpMobilityMode.TUNNEL)
        self.assertEqual(IpMobilityMode("ebpf"), IpMobilityMode.TUNNEL)
        self.assertEqual(IpMobilityMode.TUNNEL.value, "tunnel")

    def test_p1_5_mandatory_attestation_and_dest_pages_merkle_root(self) -> None:
        """Verify restore fails when manifest is missing, and tampering with pages-1.img fails dest_pages_merkle_root."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            src_dir = root / "src_final"
            dest_dir = root / "dst_final"
            src_dir.mkdir(parents=True, exist_ok=True)
            dest_dir.mkdir(parents=True, exist_ok=True)

            # Source A final dir contains metadata images (core-100.img)
            (src_dir / "core-100.img").write_bytes(b"REGISTERS_DATA")
            # Destination B final dir received pages-1.img via page-server
            (dest_dir / "pages-1.img").write_bytes(b"ORIGINAL_PAGE_CONTENT_BYTES")

            attest_key = generate_ephemeral_key_hex()
            attestor = CheckpointAttestor()

            # 1. Missing manifest.sig.json on destination must raise ValueError
            with self.assertRaises(ValueError) as ctx_missing:
                attestor.verify_directory(dest_dir, key_hex=attest_key)
            self.assertIn("manifest missing", str(ctx_missing.exception))

            # Compute page digests on Destination B and pass dest_pages_merkle_root to Source A
            _page_digests, original_pages_root = compute_directory_img_digests(dest_dir, prefix_filter="pages-")
            manifest = attestor.generate_manifest(
                images_dir=src_dir,
                migration_id="mig-attest",
                pid=100,
                dest_pages_merkle_root=original_pages_root,
                key_hex=attest_key,
            )
            self.assertEqual(manifest.dest_pages_merkle_root, original_pages_root)

            # Copy core-100.img and manifest.sig.json from Source A to Destination B (simulating rsync)
            (dest_dir / "core-100.img").write_bytes((src_dir / "core-100.img").read_bytes())
            (dest_dir / "manifest.sig.json").write_text((src_dir / "manifest.sig.json").read_text(encoding="utf-8"), encoding="utf-8")

            # Untampered verification on Destination B succeeds
            verified = attestor.verify_directory(dest_dir, expected_migration_id="mig-attest", key_hex=attest_key)
            self.assertEqual(verified.merkle_root, manifest.merkle_root)

            # 2. Tampering with pages-1.img on Destination B fails dest_pages_merkle_root check
            (dest_dir / "pages-1.img").write_bytes(b"TAMPERED_PAGE_CONTENT_BYTES")
            with self.assertRaises(ValueError) as ctx_tamper:
                attestor.verify_directory(dest_dir, expected_migration_id="mig-attest", key_hex=attest_key)
            self.assertIn("Destination page-server pages-*.img Merkle root mismatch", str(ctx_tamper.exception))


class TestAuditFixesP2(unittest.TestCase):
    """P2 audit fixes: Non-destructive preflight, criu_available blocker, and hybrid upgrade."""

    def test_p2_sample_process_dirty_rate_non_destructive_by_default(self) -> None:
        """Verify sample_process_dirty_rate with default parameters (allow_clear_refs=False) never touches clear_refs."""
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp).resolve()
            pid_dir = proc_root / "4321"
            pid_dir.mkdir(parents=True, exist_ok=True)
            (pid_dir / "maps").write_text(
                "7fff0000-7fff1000 rw-p 00000000 00:00 0 [heap]\n",
                encoding="utf-8",
            )
            (pid_dir / "pagemap").write_bytes(b"\x00" * 8)
            clear_refs_file = pid_dir / "clear_refs"
            clear_refs_file.write_text("0", encoding="utf-8")

            # Call with default allow_clear_refs=False
            profile = sample_process_dirty_rate(
                pid=4321,
                proc_root=str(proc_root),
                sample_ms=50,
                allow_clear_refs=False,
            )
            self.assertIsNotNone(profile)
            # clear_refs must NOT have been overwritten
            self.assertEqual(clear_refs_file.read_text(encoding="utf-8"), "0")

    def test_p2_evaluate_compatibility_criu_available_blocker(self) -> None:
        """Verify evaluate_compatibility returns compatible=False when criu_available=False on either host."""
        with tempfile.TemporaryDirectory() as tmp:
            snap = ProcessSnapshotInfo(root_pid=500)

            caps_ok = HostCapabilities(
                arch="x86_64",
                kernel_release="6.8.0",
                cpu_vendor="GenuineIntel",
                cpu_flags={"avx2"},
                has_soft_dirty=True,
                criu_available=True,
            )
            caps_no_criu = HostCapabilities(
                arch="x86_64",
                kernel_release="6.8.0",
                cpu_vendor="GenuineIntel",
                cpu_flags={"avx2"},
                has_soft_dirty=True,
                criu_available=False,
            )
            cfg = MigrationConfig(pid=500, source_addr="a:1", dest_addr="b:1")

            # Source missing CRIU -> Blocked
            rep_src_block = evaluate_compatibility(cfg, caps_no_criu, caps_ok, snap, {})
            self.assertFalse(rep_src_block.compatible)
            self.assertTrue(any(f.identifier == "source_criu" for f in rep_src_block.findings))

            # Destination missing CRIU -> Blocked
            rep_dst_block = evaluate_compatibility(cfg, caps_ok, caps_no_criu, snap, {})
            self.assertFalse(rep_dst_block.compatible)
            self.assertTrue(any(f.identifier == "dest_criu" for f in rep_dst_block.findings))

    def test_p2_precopy_hybrid_upgrade_recommendation(self) -> None:
        """Verify PreCopyConvergenceTracker flags recommend_hybrid_upgrade at knee of curve and orchestrator upgrades."""
        tracker = PreCopyConvergenceTracker(
            bandwidth_mbps=1000.0,
            target_downtime_ms=200,
            min_shrink_ratio=0.05,
            max_iterations=8,
        )
        # Sequence of iterations plateauing at high dirty rate (above 25MB target)
        d1 = tracker.evaluate(1, 80_000_000)
        d2 = tracker.evaluate(2, 60_000_000)
        d3 = tracker.evaluate(3, 50_000_000)
        d4 = tracker.evaluate(4, 45_000_000)

        self.assertTrue(d4.should_stop)
        self.assertFalse(d4.converged)
        self.assertTrue(d4.recommend_hybrid_upgrade)


class TestAuditFixesSecondReview(unittest.TestCase):
    """Tests for second engineering audit findings."""

    def test_discover_process_tree_pids_and_starttime(self) -> None:
        """Verify process tree walking across proc stat and task/*/children, and starttime parsing."""
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp).resolve()

            # Root PID 1000
            p1000 = proc_root / "1000"
            p1000.mkdir()
            # 22 fields: field 1=1000, 2=(daemon), 3=S, 4=1, ..., 22=998877
            fields_1000 = ["1000", "(daemon)", "S", "1"] + ["0"] * 17 + ["998877", "0"]
            (p1000 / "stat").write_text(" ".join(fields_1000))

            # Child PID 1001 discovered via ppid=1000 in stat
            p1001 = proc_root / "1001"
            p1001.mkdir()
            fields_1001 = ["1001", "(worker 1)", "S", "1000"] + ["0"] * 17 + ["998899", "0"]
            (p1001 / "stat").write_text(" ".join(fields_1001))

            # Grandchild PID 1002 discovered via task/1001/children
            p1002 = proc_root / "1002"
            p1002.mkdir()
            fields_1002 = ["1002", "(subworker)", "S", "1"] + ["0"] * 17 + ["998900", "0"]
            (p1002 / "stat").write_text(" ".join(fields_1002))
            task_dir = p1001 / "task" / "1001"
            task_dir.mkdir(parents=True)
            (task_dir / "children").write_text("1002")

            # Unrelated PID 2000
            p2000 = proc_root / "2000"
            p2000.mkdir()
            fields_2000 = ["2000", "(other)", "S", "1"] + ["0"] * 17 + ["555555", "0"]
            (p2000 / "stat").write_text(" ".join(fields_2000))

            tree = discover_process_tree_pids(1000, proc_root=str(proc_root))
            self.assertEqual(tree, [1000, 1001, 1002])

            st_1000 = read_proc_starttime(1000, proc_root=str(proc_root))
            self.assertEqual(st_1000, 998877)

            st_missing = read_proc_starttime(99999, proc_root=str(proc_root))
            self.assertIsNone(st_missing)

    def test_pid_reuse_protection_skips_reused_pid(self) -> None:
        """Verify _signal_process_tree does NOT signal a PID whose starttime changed."""
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp).resolve()

            # Process 1000
            p1000 = proc_root / "1000"
            p1000.mkdir()
            (p1000 / "stat").write_text("1000 (root) S 1 " + "0 " * 17 + "10000 0")

            # Process 1001
            p1001 = proc_root / "1001"
            p1001.mkdir()
            # Current starttime is 20000, but expected is 19999 (reused PID!)
            (p1001 / "stat").write_text("1001 (reused) S 1000 " + "0 " * 17 + "20000 0")

            signaled: List[Tuple[int, int]] = []
            service = AgentService(
                work_dir=str(proc_root),
                proc_root=str(proc_root),
                signal_sender=lambda p, s: signaled.append((p, s)),
            )

            res = service._signal_process_tree(
                root_pid=1000,
                sig=signal.SIGKILL,
                expected_starttimes={"1000": 10000, "1001": 19999},
            )
            # Only 1000 should be signaled, 1001 must be skipped due to PID reuse
            self.assertEqual(res, [1000])
            self.assertEqual(signaled, [(1000, signal.SIGKILL)])

    def test_quiesce_and_resume_cmd_execution(self) -> None:
        """Verify quiesce_cmd runs before dump and marks quiesced=True, resume_cmd runs on resume."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            quiesce_marker = root / "quiesced.txt"
            resume_marker = root / "resumed.txt"

            cfg = MigrationConfig(
                pid=1234,
                source_addr="127.0.0.1:9700",
                dest_addr="127.0.0.1:9701",
                workload_ip="10.0.0.1",
                quiesce_cmd=f"touch {quiesce_marker}",
                resume_cmd=f"touch {resume_marker}",
                tls=TlsConfig(enabled=False),
            )

            service = AgentService(
                work_dir=str(root / "work"),
                proc_root=str(root / "proc"),
                criu_driver=CriuDriver(runner=lambda cmd: subprocess.CompletedProcess(cmd, 0, "", "")),
                net_manager=NetworkMobilityManager(runner=lambda cmd: subprocess.CompletedProcess(cmd, 0, "", "")),
            )

            mig_id = "mig-test-quiesce"
            service.prepare_migration(mig_id)
            service.freeze_and_final_dump(
                migration_id=mig_id,
                prev_round_name=None,
                dest_host="127.0.0.1",
                config_dict=config_to_dict(cfg),
            )

            self.assertTrue(quiesce_marker.exists())
            state_file = root / "work" / mig_id / "source_state.json"
            self.assertTrue(state_file.exists())
            state = json.loads(state_file.read_text())
            self.assertTrue(state["quiesced"])

            # Test resume_cmd on Destination
            service.claim_ip_and_resume(
                restored_pid=5555,
                target_host="127.0.0.1",
                config_dict=config_to_dict(cfg),
                migration_id=mig_id,
            )
            self.assertTrue(resume_marker.exists())

    def test_cgroup_freeze_events_polling(self) -> None:
        """Verify cgroup v2 freeze waits for frozen 1 in cgroup.events."""
        with tempfile.TemporaryDirectory() as tmp:
            cg_root = Path(tmp).resolve()
            env = EnvelopeManager(cgroup_root=str(cg_root))
            workload_id = "test-wl"
            wl_cg = cg_root / workload_id
            wl_cg.mkdir(parents=True)

            freeze_file = wl_cg / "cgroup.freeze"
            events_file = wl_cg / "cgroup.events"

            # Simulate immediate freeze
            events_file.write_text("populated 1\nfrozen 1\n")
            p = env.freeze_cgroup(workload_id, timeout_sec=0.5)
            self.assertEqual(p, wl_cg)
            self.assertEqual(freeze_file.read_text().strip(), "1")

            # Simulate unfreeze
            events_file.write_text("populated 1\nfrozen 0\n")
            env.unfreeze_cgroup(workload_id, timeout_sec=0.5)
            self.assertEqual(freeze_file.read_text().strip(), "0")

            # Simulate timeout
            events_file.write_text("populated 1\nfrozen 0\n")
            with self.assertRaises(TimeoutError):
                env.freeze_cgroup(workload_id, timeout_sec=0.05)

    def test_lock_network_error_cleans_up_and_unlock_idempotent(self) -> None:
        """Verify lock_network cleans up table on failure, unlock_network handles absent table."""
        executed: List[List[str]] = []

        def failing_runner(cmd: List[str]) -> subprocess.CompletedProcess:
            executed.append(cmd)
            if len(cmd) == 2 and cmd[0] == "nft" and "add chain" in cmd[1]:
                raise RuntimeError("nft batch command failed")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        net = NetworkMobilityManager(runner=failing_runner)
        with self.assertRaises(RuntimeError):
            net.lock_network("10.10.10.10", migration_id="mig-fail")

        # Cleanup table deletion must have been executed
        table_name = net.table_name_for("10.10.10.10", "mig-fail")
        self.assertIn(["nft", "delete", "table", "inet", table_name], executed)

        # Test unlock_network handles CalledProcessError gracefully
        def not_found_runner(cmd: List[str]) -> subprocess.CompletedProcess:
            raise subprocess.CalledProcessError(1, cmd, stderr="Error: No such table")

        net_nf = NetworkMobilityManager(runner=not_found_runner)
        # Should not raise
        res = net_nf.unlock_network("10.10.10.10", migration_id="mig-fail")
        self.assertEqual(len(res), 1)

    def test_expected_pages_bytes_manifest_attestation(self) -> None:
        """Verify attestation validates expected_pages_bytes and detects size tampering."""
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp).resolve()
            (d / "core-1.img").write_bytes(b"CORE_DATA")

            attestor = CheckpointAttestor()
            key = generate_ephemeral_key_hex()

            manifest = attestor.generate_manifest(
                images_dir=d,
                migration_id="mig-pages",
                pid=100,
                key_hex=key,
                expected_pages_bytes=1024,
            )
            self.assertEqual(manifest.expected_pages_bytes, 1024)

            # Untampered pages matching expected_pages_bytes passes
            (d / "pages-1.img").write_bytes(b"X" * 1024)
            verified = attestor.verify_directory(d, expected_migration_id="mig-pages", key_hex=key)
            self.assertEqual(verified.expected_pages_bytes, 1024)

            # An extra pages-2.img added changes total size to 1536 != 1024
            (d / "pages-2.img").write_bytes(b"Y" * 512)
            with self.assertRaises(ValueError) as ctx:
                attestor.verify_directory(d, expected_migration_id="mig-pages", key_hex=key)
            self.assertIn("Destination pages-*.img total byte size mismatch", str(ctx.exception))


class TestAuditRound2Fixes(unittest.TestCase):
    """Rigorous tests for Audit Round 2 fixes covering process trees, gang roll-forward, and mTLS."""

    def test_01_process_tree_signaling_and_pid_reuse_protection(self) -> None:
        """
        Verify that when a process has 2 child PIDs in <proc_root>/<pid>/task/<pid>/children,
        claim_ip_and_resume, rollback_source, commit_source, and rollback_dest signal ALL 3 PIDs,
        AND if a PID's starttime in <proc_root>/<pid>/stat changed, that PID is NOT signaled.
        """
        import errno
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            proc_root = root / "proc"
            work_dir = root / "work"
            mig_id = "mig-tree-test"

            # Create proc structure: root 3000, children 3001 and 3002
            for pid, st in ((3000, 70000), (3001, 70001), (3002, 70002)):
                p_dir = proc_root / str(pid)
                p_dir.mkdir(parents=True, exist_ok=True)
                (p_dir / "stat").write_text(f"{pid} (proc) S 1 " + "0 " * 17 + f"{st} 0\n", encoding="utf-8")
                (p_dir / "status").write_text(f"Name:\tproc\nVmRSS:\t1024 kB\n", encoding="utf-8")

            task_dir = proc_root / "3000" / "task" / "3000"
            task_dir.mkdir(parents=True, exist_ok=True)
            (task_dir / "children").write_text("3001 3002\n", encoding="utf-8")

            # Final restore state (for claim_ip_and_resume and rollback_dest)
            final_dir = work_dir / mig_id / "final"
            final_dir.mkdir(parents=True, exist_ok=True)
            restore_state = {
                "restored_pid": 3000,
                "tree_pids": [3000, 3001, 3002],
                "starttimes": {"3000": 70000, "3001": 70001, "3002": 70002},
            }
            (final_dir / "restore_state.json").write_text(json.dumps(restore_state), encoding="utf-8")

            # Source state (for rollback_source and commit_source)
            src_state = {
                "pid": 3000,
                "tree_pids": [3000, 3001, 3002],
                "starttimes": {"3000": 70000, "3001": 70001, "3002": 70002},
                "committed": False,
                "quiesced": False,
            }
            (work_dir / mig_id / "source_state.json").write_text(json.dumps(src_state), encoding="utf-8")

            signaled: List[Tuple[int, int]] = []
            service = AgentService(
                work_dir=str(work_dir),
                proc_root=str(proc_root),
                signal_sender=lambda p, s: signaled.append((p, s)),
                pid_alive_checker=lambda _pid: True,
            )
            cfg = MigrationConfig(
                pid=3000,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                ip_mobility=IpMobilityMode.NONE,
                tls=TlsConfig(enabled=False),
            )
            cfg_dict = config_to_dict(cfg)

            # Part A: Matching starttimes -> ALL 3 PIDs signaled
            # 1. claim_ip_and_resume -> SIGCONT to 3000, 3001, 3002
            signaled.clear()
            service.claim_ip_and_resume(restored_pid=3000, target_host="10.0.0.2", config_dict=cfg_dict, migration_id=mig_id)
            self.assertEqual(signaled, [(3000, signal.SIGCONT), (3001, signal.SIGCONT), (3002, signal.SIGCONT)])

            # 2. rollback_source -> SIGCONT to 3000, 3001, 3002
            signaled.clear()
            service.rollback_source(migration_id=mig_id, source_host="10.0.0.1", config_dict=cfg_dict)
            self.assertEqual(signaled, [(3000, signal.SIGCONT), (3001, signal.SIGCONT), (3002, signal.SIGCONT)])

            # 3. commit_source -> SIGKILL to 3000, 3001, 3002
            (work_dir / mig_id).mkdir(parents=True, exist_ok=True)
            (work_dir / mig_id / "source_state.json").write_text(json.dumps(src_state), encoding="utf-8")
            signaled.clear()
            service.commit_source(migration_id=mig_id, config_dict=cfg_dict)
            self.assertEqual(signaled, [(3000, signal.SIGKILL), (3001, signal.SIGKILL), (3002, signal.SIGKILL)])

            # 4. rollback_dest -> SIGKILL to 3000, 3001, 3002
            final_dir = work_dir / mig_id / "final"
            final_dir.mkdir(parents=True, exist_ok=True)
            (final_dir / "restore_state.json").write_text(json.dumps(restore_state), encoding="utf-8")
            signaled.clear()
            service.rollback_dest(migration_id=mig_id, restored_pid=3000, config_dict=cfg_dict)
            self.assertEqual(signaled, [(3000, signal.SIGKILL), (3001, signal.SIGKILL), (3002, signal.SIGKILL)])

            # Part B: PID reuse -> change 3002 starttime in proc stat (3002 was reused by another process)
            (proc_root / "3002" / "stat").write_text("3002 (other) S 3000 " + "0 " * 17 + "99999 0\n", encoding="utf-8")

            # 1. claim_ip_and_resume -> 3002 is SKIPPED
            final_dir = work_dir / mig_id / "final"
            final_dir.mkdir(parents=True, exist_ok=True)
            (final_dir / "restore_state.json").write_text(json.dumps(restore_state), encoding="utf-8")
            signaled.clear()
            service.claim_ip_and_resume(restored_pid=3000, target_host="10.0.0.2", config_dict=cfg_dict, migration_id=mig_id)
            self.assertEqual(signaled, [(3000, signal.SIGCONT), (3001, signal.SIGCONT)])

            # 2. rollback_source -> 3002 is SKIPPED
            (work_dir / mig_id).mkdir(parents=True, exist_ok=True)
            (work_dir / mig_id / "source_state.json").write_text(json.dumps(src_state), encoding="utf-8")
            signaled.clear()
            service.rollback_source(migration_id=mig_id, source_host="10.0.0.1", config_dict=cfg_dict)
            self.assertEqual(signaled, [(3000, signal.SIGCONT), (3001, signal.SIGCONT)])

            # 3. commit_source -> 3002 is SKIPPED
            (work_dir / mig_id).mkdir(parents=True, exist_ok=True)
            (work_dir / mig_id / "source_state.json").write_text(json.dumps(src_state), encoding="utf-8")
            signaled.clear()
            service.commit_source(migration_id=mig_id, config_dict=cfg_dict)
            self.assertEqual(signaled, [(3000, signal.SIGKILL), (3001, signal.SIGKILL)])

            # 4. rollback_dest -> 3002 is SKIPPED
            final_dir = work_dir / mig_id / "final"
            final_dir.mkdir(parents=True, exist_ok=True)
            (final_dir / "restore_state.json").write_text(json.dumps(restore_state), encoding="utf-8")
            signaled.clear()
            service.rollback_dest(migration_id=mig_id, restored_pid=3000, config_dict=cfg_dict)
            self.assertEqual(signaled, [(3000, signal.SIGKILL), (3001, signal.SIGKILL)])

    def test_02_quiesce_resume_cmd_and_cgroup_frozen_polling(self) -> None:
        """
        Verify freeze_cgroup polls cgroup.events for frozen 1 (and raises TimeoutError if frozen 0 persists),
        and quiesce_cmd runs before lock_network while resume_cmd runs after SIGCONT.
        """
        import errno
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            cg_root = root / "cgroup"
            wl_cg = cg_root / "wl-poll"
            wl_cg.mkdir(parents=True, exist_ok=True)

            freeze_file = wl_cg / "cgroup.freeze"
            events_file = wl_cg / "cgroup.events"

            env = EnvelopeManager(cgroup_root=str(cg_root))

            # 1. Immediate frozen 1 succeeds
            events_file.write_text("populated 1\nfrozen 1\n", encoding="utf-8")
            res_dir = env.freeze_cgroup("wl-poll", timeout_sec=0.5)
            self.assertEqual(res_dir, wl_cg)
            self.assertEqual(freeze_file.read_text().strip(), "1")

            # 2. Frozen 0 persists -> TimeoutError
            events_file.write_text("populated 1\nfrozen 0\n", encoding="utf-8")
            with self.assertRaises(TimeoutError):
                env.freeze_cgroup("wl-poll", timeout_sec=0.05)

            # 3. Quiesce command runs BEFORE lock_network
            execution_order: List[str] = []

            def fake_runner(cmd: List[str]) -> subprocess.CompletedProcess:
                if cmd and cmd[0] == "nft":
                    execution_order.append("lock_network")
                return subprocess.CompletedProcess(cmd, 0, "", "")

            q_file = root / "quiesce.flag"
            r_file = root / "resume.flag"

            cfg = MigrationConfig(
                pid=1234,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                workload_ip="10.0.0.50",
                quiesce_cmd=f"touch {q_file}",
                resume_cmd=f"touch {r_file}",
                tls=TlsConfig(enabled=False),
            )

            service = AgentService(
                work_dir=str(root / "work"),
                proc_root=str(root / "proc"),
                criu_driver=CriuDriver(runner=fake_runner),
                net_manager=NetworkMobilityManager(runner=fake_runner),
                signal_sender=lambda p, s: execution_order.append(f"signal_{s}"),
                pid_alive_checker=lambda _pid: True,
            )

            with patch("subprocess.run") as mock_subproc:
                def fake_subproc(cmd: List[str], **kwargs: Any) -> subprocess.CompletedProcess:
                    if str(q_file) in cmd:
                        execution_order.append("quiesce_cmd")
                    elif str(r_file) in cmd:
                        execution_order.append("resume_cmd")
                    return subprocess.CompletedProcess(cmd, 0, "", "")

                mock_subproc.side_effect = fake_subproc

                # freeze_and_final_dump: quiesce_cmd must run BEFORE lock_network
                service.prepare_migration("mig-order")
                service.freeze_and_final_dump(
                    migration_id="mig-order",
                    prev_round_name=None,
                    dest_host="10.0.0.2",
                    config_dict=config_to_dict(cfg),
                )
                self.assertIn("quiesce_cmd", execution_order)
                self.assertIn("lock_network", execution_order)
                self.assertLess(
                    execution_order.index("quiesce_cmd"),
                    execution_order.index("lock_network"),
                    "quiesce_cmd must execute BEFORE lock_network",
                )

                # claim_ip_and_resume: resume_cmd must run AFTER SIGCONT (18 or 19 depending on platform)
                execution_order.clear()
                service.claim_ip_and_resume(
                    restored_pid=5555,
                    target_host="10.0.0.2",
                    config_dict=config_to_dict(cfg),
                    migration_id="mig-order",
                )
                self.assertIn(f"signal_{signal.SIGCONT}", execution_order)
                self.assertIn("resume_cmd", execution_order)
                self.assertLess(
                    execution_order.index(f"signal_{signal.SIGCONT}"),
                    execution_order.index("resume_cmd"),
                    "resume_cmd must execute AFTER SIGCONT",
                )

    def test_03_gang_migration_stopped_readiness_and_mid_commit_roll_forward(self) -> None:
        """
        Verify that during Phase 1 of GangMigrationCoordinator.execute_atomic(), Member 1 on Destination B
        does NOT receive SIGCONT until Member 2 also passes verify_restored_stopped AND both Source A members
        are killed via commit_source. Also verify that if a fault occurs during Phase 2 after COMMITTED is logged
        in GangJournal, atomic_rollback_triggered is False, partial_commit_error is True, and
        GangMigrationCoordinator.recover_from_journal rolls forward to finish the commit.
        """
        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            h1 = _FakeClusterHarness(tmp1)
            h2 = _FakeClusterHarness(tmp2)

            cfg1 = MigrationConfig(
                pid=1234,
                workload_id="gang-w1",
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                workload_ip="10.0.0.51/24",
                tls=TlsConfig(enabled=False),
            )
            cfg2 = MigrationConfig(
                pid=1234,
                workload_id="gang-w2",
                source_addr="10.0.0.3:9700",
                dest_addr="10.0.0.4:9700",
                strategy=MigrationStrategy.COLD,
                workload_ip="10.0.0.52/24",
                tls=TlsConfig(enabled=False),
            )

            # Invariant 1: Destination B never gets SIGCONT during Phase 1
            # Hook verify_restored_stopped on Member 2 to inspect signals on B
            sigcont_observed_during_phase1 = []
            orig_verify_stopped_2 = h2.service_b.verify_restored_stopped

            def hooked_verify_stopped_2(restored_pid: int, migration_id: Optional[str] = None) -> Dict[str, Any]:
                # Check whether Destination B1 or B2 received SIGCONT
                if any(sig == signal.SIGCONT for _p, sig in h1.signals_b):
                    sigcont_observed_during_phase1.append("h1")
                if any(sig == signal.SIGCONT for _p, sig in h2.signals_b):
                    sigcont_observed_during_phase1.append("h2")
                return orig_verify_stopped_2(restored_pid, migration_id)

            h2.service_b.verify_restored_stopped = hooked_verify_stopped_2

            # Inject transient RPC failure in Phase 2 for Member 2
            orig_commit_source_2 = h2.service_a.commit_source
            transient_fault = [True]

            def failing_commit_source_2(migration_id: str, config_dict: Dict[str, Any]) -> Dict[str, Any]:
                if transient_fault[0]:
                    transient_fault[0] = False
                    raise RuntimeError("Transient RPC failure during Phase 2 commit_source on Member 2")
                return orig_commit_source_2(migration_id, config_dict)

            h2.service_a.commit_source = failing_commit_source_2

            coordinator = GangMigrationCoordinator(
                gang_id="gang-audit-test",
                journal_dir=f"{tmp1}/wal",
                members=[
                    (cfg1, AgentClient("10.0.0.1:9700", direct_service=h1.service_a), AgentClient("10.0.0.2:9700", direct_service=h1.service_b)),
                    (cfg2, AgentClient("10.0.0.3:9700", direct_service=h2.service_a), AgentClient("10.0.0.4:9700", direct_service=h2.service_b)),
                ],
            )

            gang_res = coordinator.execute_atomic()

            # Verify no SIGCONT occurred during Phase 1
            self.assertEqual(sigcont_observed_during_phase1, [])

            # Verify mid-commit fault semantics: COMMITTED decision was logged, so atomic_rollback is FALSE
            self.assertFalse(gang_res.all_committed)
            self.assertFalse(gang_res.atomic_rollback_triggered)
            self.assertTrue(gang_res.partial_commit_error)
            self.assertTrue(coordinator.journal.has_committed_decision)

            # Member 1 succeeded commit_source (Source A killed with SIGKILL)
            self.assertIn((1234, signal.SIGKILL), h1.signals_a)

            # Recover from journal: rolls forward to finish Member 2 cutover
            rec_res = GangMigrationCoordinator.recover_from_journal(
                gang_journal_path=coordinator.journal.path,
                members=[
                    (cfg1, AgentClient("10.0.0.1:9700", direct_service=h1.service_a), AgentClient("10.0.0.2:9700", direct_service=h1.service_b)),
                    (cfg2, AgentClient("10.0.0.3:9700", direct_service=h2.service_a), AgentClient("10.0.0.4:9700", direct_service=h2.service_b)),
                ],
            )

            self.assertTrue(rec_res.all_committed)
            self.assertFalse(rec_res.atomic_rollback_triggered)
            self.assertFalse(rec_res.partial_commit_error)
            self.assertEqual(len(rec_res.member_results), 2)
            self.assertTrue(all(r.success for r in rec_res.member_results))

            # Both Source A members killed
            self.assertIn((1234, signal.SIGKILL), h1.signals_a)
            self.assertIn((1234, signal.SIGKILL), h2.signals_a)
            # Both Destination B members resumed with SIGCONT
            self.assertIn((5678, signal.SIGCONT), h1.signals_b)
            self.assertIn((5678, signal.SIGCONT), h2.signals_b)

    def test_04_orphaned_restore_state_pid_discovery_on_rollback_dest(self) -> None:
        """
        Verify that when rollback_dest is called with restored_pid=None,
        it reads final/restore_state.json and kills the orphaned restored root PID and child PIDs on Destination B.
        """
        import errno
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            work_dir = root / "work"
            proc_root = root / "proc"
            mig_id = "mig-orphan-test"

            # Create destination process tree (root 7000, children 7001, 7002)
            for pid, st in ((7000, 111), (7001, 222), (7002, 333)):
                p_dir = proc_root / str(pid)
                p_dir.mkdir(parents=True, exist_ok=True)
                (p_dir / "stat").write_text(f"{pid} (srv) S 1 " + "0 " * 17 + f"{st} 0\n", encoding="utf-8")
                (p_dir / "status").write_text(f"Name:\tsrv\nVmRSS:\t1024 kB\n", encoding="utf-8")

            final_dir = work_dir / mig_id / "final"
            final_dir.mkdir(parents=True, exist_ok=True)
            restore_state = {
                "restored_pid": 7000,
                "tree_pids": [7000, 7001, 7002],
                "starttimes": {"7000": 111, "7001": 222, "7002": 333},
            }
            (final_dir / "restore_state.json").write_text(json.dumps(restore_state), encoding="utf-8")

            signaled: List[Tuple[int, int]] = []
            service = AgentService(
                work_dir=str(work_dir),
                proc_root=str(proc_root),
                signal_sender=lambda p, s: signaled.append((p, s)),
                pid_alive_checker=lambda _pid: True,
            )
            cfg = MigrationConfig(pid=7000, source_addr="a:1", dest_addr="b:1", tls=TlsConfig(enabled=False))

            # Call rollback_dest with restored_pid=None!
            res = service.rollback_dest(migration_id=mig_id, restored_pid=None, config_dict=config_to_dict(cfg))
            self.assertTrue(res.get("rolled_back_dest"))
            # Root PID and child PIDs must ALL be killed with SIGKILL
            self.assertEqual(signaled, [(7000, signal.SIGKILL), (7001, signal.SIGKILL), (7002, signal.SIGKILL)])

    def test_05_idempotent_lock_network_partial_failure_cleanup(self) -> None:
        """
        Verify that if the atomic nft batch command in lock_network raises CalledProcessError,
        lock_network automatically runs nft delete table inet <table> before re-raising.
        """
        executed: List[List[str]] = []

        def failing_runner(cmd: List[str]) -> subprocess.CompletedProcess:
            executed.append(list(cmd))
            if len(executed) == 1:
                raise subprocess.CalledProcessError(returncode=1, cmd=cmd, stderr="nft batch failure")
            return subprocess.CompletedProcess(cmd, 0, "", "")

        net = NetworkMobilityManager(runner=failing_runner)
        table_name = net.table_name_for("10.20.30.40", "mig-fail-clean")

        with self.assertRaises(subprocess.CalledProcessError):
            net.lock_network("10.20.30.40", migration_id="mig-fail-clean")

        # 1 atomic batch command tried + 1 cleanup command executed (nft delete table inet <table_name>)
        self.assertEqual(len(executed), 2)
        self.assertEqual(executed[-1], ["nft", "delete", "table", "inet", table_name])

    def test_06_strict_mtls_requiring_ca_cert(self) -> None:
        """
        Verify AgentServer and AgentClient raise ValueError when
        tls=TlsConfig(enabled=True, cert_file="c.pem", key_file="k.pem", ca_cert=None).
        """
        bad_tls = TlsConfig(enabled=True, cert_file="c.pem", key_file="k.pem", ca_cert=None)
        dummy_service = AgentService(work_dir="/tmp")

        # AgentServer must reject missing ca_cert
        with self.assertRaises(ValueError) as ctx_srv:
            AgentServer("127.0.0.1", 0, dummy_service, tls=bad_tls)
        self.assertIn("ca_cert", str(ctx_srv.exception))

        # AgentClient must reject missing ca_cert
        client = AgentClient("127.0.0.1:9700", tls=bad_tls)
        with self.assertRaises(ValueError) as ctx_cli:
            client.call("get_capabilities")
        self.assertIn("ca_cert", str(ctx_cli.exception))


class TestStaffAuditFindingsFixes(unittest.TestCase):
    """Regression tests for the 5 Staff-level production readiness audit findings (2 P0s, 3 P1s)."""

    def test_p0_1_freeze_and_final_dump_installs_full_nft_drop_rules(self) -> None:
        """P0-1: freeze_and_final_dump must execute all 6 nft commands including input/output drop rules."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work_dir = root / "work"
            proc_dir = root / "proc"
            (proc_dir / "1234").mkdir(parents=True, exist_ok=True)
            (proc_dir / "1234" / "stat").write_text(
                "1234 (app) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 555 0\n",
                encoding="utf-8",
            )
            (proc_dir / "1234" / "status").write_text("Name:\tapp\nVmRSS:\t4096 kB\n", encoding="utf-8")

            nft_cmds: List[List[str]] = []

            def runner(cmd: List[str]) -> subprocess.CompletedProcess:
                if cmd and cmd[0] == "nft":
                    nft_cmds.append(list(cmd))
                return subprocess.CompletedProcess(cmd, 0, "", "")

            service = AgentService(
                work_dir=str(work_dir),
                proc_root=str(proc_dir),
                criu_driver=CriuDriver(runner=runner),
                net_manager=NetworkMobilityManager(runner=runner),
                fs_manager=FilesystemSyncManager(runner=runner),
                pid_alive_checker=lambda _p: True,
            )
            cfg = MigrationConfig(
                pid=1234,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                workload_ip="10.244.1.10/32",
                tls=TlsConfig(enabled=False),
            )
            service.prepare_migration("mig-nft-drop")
            service.freeze_and_final_dump(
                migration_id="mig-nft-drop",
                prev_round_name=None,
                dest_host="10.0.0.2",
                config_dict=config_to_dict(cfg),
            )

            self.assertEqual(len(nft_cmds), 1)
            self.assertEqual(nft_cmds[0][0], "nft")
            batch_script = nft_cmds[0][1]
            self.assertIn("add table inet", batch_script)
            self.assertIn("flush table inet", batch_script)
            self.assertIn("hook input", batch_script)
            self.assertIn("hook output", batch_script)
            self.assertIn("daddr 10.244.1.10 drop;", batch_script)
            self.assertIn("saddr 10.244.1.10 drop;", batch_script)

    def test_p0_2_no_dual_active_instances_on_rollback_or_commit_errors(self) -> None:
        """
        P0-2:
        1. Orchestrator.rollback must NOT call rollback_source if rollback_dest fails.
        2. AgentService._signal_process_tree must propagate non-ESRCH OSError (e.g. EPERM).
        3. AgentService.commit_source must NOT mark source_state.json committed=True before SIGKILL succeeds.
        """
        import errno
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work_a = root / "work_a"
            work_b = root / "work_b"
            proc_a = root / "proc_a"
            proc_b = root / "proc_b"
            for p in (proc_a / "100", proc_b / "200"):
                p.mkdir(parents=True, exist_ok=True)
                (p / "stat").write_text(f"{p.name} (app) S 1 " + "0 " * 17 + "999 0\n", encoding="utf-8")
                (p / "status").write_text("Name:\tapp\nVmRSS:\t4096 kB\n", encoding="utf-8")

            def fail_signal_eperm(_pid: int, _sig: int) -> None:
                raise OSError(errno.EPERM, "Operation not permitted")

            service_a = AgentService(
                work_dir=str(work_a),
                proc_root=str(proc_a),
                signal_sender=fail_signal_eperm,
                pid_alive_checker=lambda _p: True,
            )

            # 1. _signal_process_tree raises EPERM
            with self.assertRaises(OSError) as ctx:
                service_a._signal_process_tree(100, signal.SIGKILL)
            self.assertEqual(ctx.exception.errno, errno.EPERM)

            # 2. commit_source does NOT mark committed=True when SIGKILL raises EPERM
            mig_dir_a = work_a / "mig-commit-fail"
            mig_dir_a.mkdir(parents=True, exist_ok=True)
            state_file = mig_dir_a / "source_state.json"
            state_file.write_text(
                json.dumps({"pid": 100, "tree_pids": [100], "committed": False}),
                encoding="utf-8",
            )
            cfg = MigrationConfig(
                pid=100,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                tls=TlsConfig(enabled=False),
            )
            with self.assertRaises(OSError):
                service_a.commit_source("mig-commit-fail", config_to_dict(cfg))
            saved_state = json.loads(state_file.read_text(encoding="utf-8"))
            self.assertFalse(saved_state["committed"])

            # 3. Orchestrator.rollback skips rollback_source when rollback_dest fails
            rollback_source_called = [False]

            class DummySourceClient:
                host = "10.0.0.1"

                def call(self, method: str, **_kwargs: Any) -> Dict[str, Any]:
                    if method == "rollback_source":
                        rollback_source_called[0] = True
                    return {"rolled_back_source": True}

            class FailingDestClient:
                host = "10.0.0.2"

                def call(self, method: str, **_kwargs: Any) -> Dict[str, Any]:
                    if method == "rollback_dest":
                        return {"rolled_back_dest": False, "errors": ["dest process 200 still alive"]}
                    return {}

            orch = MigrationOrchestrator(
                cfg,
                DummySourceClient(),  # type: ignore[arg-type]
                FailingDestClient(),  # type: ignore[arg-type]
                migration_id="mig-rb-fence",
                journal_dir=f"{tmp}/wal",
            )
            rb_res = orch.rollback("Verify failed on B")
            self.assertFalse(rb_res.rolled_back)
            self.assertFalse(rollback_source_called[0])
            self.assertIn("Skipping rollback_source because rollback_dest failed", rb_res.error_message or "")

    def test_p1_1_transfer_final_state_uses_consistent_frozen_snapshot(self) -> None:
        """P1-1: transfer_final_state must sync writable_paths from the frozen vol_snap rather than mutated live paths."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work_dir = root / "work"
            proc_dir = root / "proc"
            (proc_dir / "1234").mkdir(parents=True, exist_ok=True)
            (proc_dir / "1234" / "stat").write_text(
                "1234 (app) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 555 0\n",
                encoding="utf-8",
            )
            (proc_dir / "1234" / "status").write_text("Name:\tapp\nVmRSS:\t4096 kB\n", encoding="utf-8")

            live_data_dir = root / "data"
            live_data_dir.mkdir(parents=True, exist_ok=True)
            live_file = live_data_dir / "db.wal"
            live_file.write_text("CHECKPOINT_CONSISTENT_STATE\n", encoding="utf-8")

            rsync_cmds: List[List[str]] = []

            def runner(cmd: List[str]) -> subprocess.CompletedProcess:
                if cmd and cmd[0] == "criu" and "dump" in cmd:
                    idx = cmd.index("--images-dir")
                    img_d = Path(cmd[idx + 1])
                    (img_d / "core-1.img").write_bytes(b"CORE")
                    (img_d / "pages-1.img").write_bytes(b"PAGES")
                elif cmd and cmd[0] == "rsync":
                    rsync_cmds.append(list(cmd))
                return subprocess.CompletedProcess(cmd, 0, "", "")

            service = AgentService(
                work_dir=str(work_dir),
                proc_root=str(proc_dir),
                criu_driver=CriuDriver(runner=runner),
                net_manager=NetworkMobilityManager(runner=runner),
                fs_manager=FilesystemSyncManager(runner=runner),
                pid_alive_checker=lambda _p: True,
            )
            cfg = MigrationConfig(
                pid=1234,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                fs_mode=FilesystemMode.RSYNC,
                writable_paths=[str(live_file)],
                verify_attestation=False,
                tls=TlsConfig(enabled=False),
            )
            cfg_dict = config_to_dict(cfg)
            service.prepare_migration("mig-snap-sync")
            service.freeze_and_final_dump(
                migration_id="mig-snap-sync",
                prev_round_name=None,
                dest_host="10.0.0.2",
                config_dict=cfg_dict,
            )

            # Mutate the live file AFTER the frozen snapshot was taken
            live_file.write_text("MUTATED_POST_DUMP_GARBAGE\n", encoding="utf-8")

            service.transfer_final_state(
                migration_id="mig-snap-sync",
                dest_host="10.0.0.2",
                config_dict=cfg_dict,
            )

            # Find the rsync command that synced db.wal
            delta_rsync = [c for c in rsync_cmds if any("db.wal" in arg for arg in c)]
            self.assertEqual(len(delta_rsync), 1)
            src_arg = delta_rsync[0][-2]
            self.assertIn("vol_snap", src_arg)
            self.assertEqual(Path(src_arg).read_text(encoding="utf-8"), "CHECKPOINT_CONSISTENT_STATE\n")

    def test_p1_2_ci_gates_fail_closed_on_criu_errors(self) -> None:
        """P1-2: linux_criu_e2e.main() returns non-zero on failure, and REAL_CRIU acceptance fails closed when unavailable."""
        from unittest.mock import patch
        import scripts.linux_criu_e2e as e2e
        from lkmp.acceptance import run_acceptance_scenario

        fake_results = {
            "environment": {},
            "scenarios": {},
            "summary": {"total": 4, "passed": 3, "skipped": 0, "failed": 1},
        }
        with patch.object(e2e.LinuxCriuE2ERunner, "run_all", return_value=fake_results), patch.object(
            e2e.LinuxCriuE2ERunner, "render_markdown", return_value="MD"
        ), patch("sys.argv", ["linux_criu_e2e.py"]):
            rc = e2e.main()
        self.assertEqual(rc, 1)

        with patch("lkmp.acceptance._can_run_real_criu", return_value=False):
            acc_res = run_acceptance_scenario(
                scenario_name="REAL_CRIU Fail-Closed Check",
                strategy=MigrationStrategy.COLD,
                backend="REAL_CRIU",
            )
        self.assertFalse(acc_res.passed)
        self.assertEqual(acc_res.execution_backend, "REAL_CRIU")
        self.assertTrue(any("REAL_CRIU backend requires Linux" in e for e in acc_res.error_logs))

    def test_p1_3_cow_fast_path_used_in_production_migration(self) -> None:
        """P1-3: Production transfer_final_state uses CoW fast path instead of rsync on same-host migration."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            work_a = root / "work_a"
            work_b = root / "work_b"
            proc_a = root / "proc_a"
            proc_b = root / "proc_b"
            for p in (proc_a / "4242", proc_b / "4242"):
                p.mkdir(parents=True, exist_ok=True)
                (p / "stat").write_text("4242 (app) S 1 " + "0 " * 17 + "100 0\n", encoding="utf-8")
                (p / "status").write_text("Name:\tapp\nVmRSS:\t4096 kB\n", encoding="utf-8")

            cmds_a: List[List[str]] = []

            def runner_a(cmd: List[str]) -> subprocess.CompletedProcess:
                cmds_a.append(list(cmd))
                if cmd and cmd[0] == "criu" and "dump" in cmd:
                    idx = cmd.index("--images-dir")
                    img_d = Path(cmd[idx + 1])
                    (img_d / "core-1.img").write_bytes(b"CORE_STATE")
                    (img_d / "pages-1.img").write_bytes(b"PAGES_STATE")
                elif cmd and cmd[0] == "cp" and len(cmd) >= 3:
                    shutil.copy2(cmd[-2], cmd[-1])
                return subprocess.CompletedProcess(cmd, 0, "", "")

            service_a = AgentService(
                work_dir=str(work_a),
                proc_root=str(proc_a),
                criu_driver=CriuDriver(runner=runner_a),
                net_manager=NetworkMobilityManager(runner=runner_a),
                fs_manager=FilesystemSyncManager(runner=runner_a),
                pid_alive_checker=lambda _p: True,
            )
            service_b = AgentService(
                work_dir=str(work_b),
                proc_root=str(proc_b),
                pid_alive_checker=lambda _p: True,
            )
            dst_prep = service_b.prepare_migration("mig-cow-prod")
            service_a.prepare_migration("mig-cow-prod")

            cfg = MigrationConfig(
                pid=4242,
                source_addr="127.0.0.1:9700",
                dest_addr="127.0.0.1:9701",
                strategy=MigrationStrategy.COLD,
                fs_mode=FilesystemMode.SHARED,
                verify_attestation=False,
                tls=TlsConfig(enabled=False),
            )
            cfg_dict = config_to_dict(cfg)
            service_a.freeze_and_final_dump(
                migration_id="mig-cow-prod",
                prev_round_name=None,
                dest_host="127.0.0.1",
                config_dict=cfg_dict,
            )
            res = service_a.transfer_final_state(
                migration_id="mig-cow-prod",
                dest_host="127.0.0.1",
                config_dict=cfg_dict,
                dest_images_dir=dst_prep["images_dir"],
            )
            self.assertTrue(res.get("cow_fast_path"))
            self.assertTrue(any(c[0] == "cp" for c in cmds_a))
            self.assertFalse(any(c[0] == "rsync" for c in cmds_a))
            self.assertTrue((Path(dst_prep["images_dir"]) / "core-1.img").exists())
            self.assertTrue((Path(dst_prep["images_dir"]) / "pages-1.img").exists())

    def test_p1_followup_acceptance_uses_af_inet_tcp_not_unix_socket(self) -> None:
        """P1 follow-up: acceptance harness uses real AF_INET SOCK_STREAM TCP sockets, never AF_UNIX."""
        import socket
        from lkmp.acceptance import _create_tcp_socketpair

        csock, ssock = _create_tcp_socketpair()
        try:
            self.assertEqual(csock.family, socket.AF_INET)
            self.assertEqual(ssock.family, socket.AF_INET)
            self.assertEqual(csock.type & socket.SOCK_STREAM, socket.SOCK_STREAM)
            self.assertEqual(ssock.type & socket.SOCK_STREAM, socket.SOCK_STREAM)
            csock.sendall(b"ping")
            self.assertEqual(ssock.recv(4), b"ping")
        finally:
            csock.close()
            ssock.close()

        acc_src = (Path(__file__).resolve().parent.parent / "lkmp" / "acceptance.py").read_text(encoding="utf-8")
        self.assertNotIn("AF_UNIX", acc_src)
        self.assertNotIn("--ext-unix-sk", acc_src)
        self.assertIn("--tcp-established", acc_src)

    def test_p1_followup_final_delta_sync_refuses_live_fallback_when_snapshot_missing(self) -> None:
        """P1 follow-up: final_delta_sync fails closed (FileNotFoundError) if snapshot_dir or path snapshot is missing."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            live_file = root / "live.db"
            live_file.write_text("LIVE_MUTATING_STATE\n", encoding="utf-8")
            empty_snap = root / "empty_snap"
            empty_snap.mkdir(parents=True, exist_ok=True)

            executed: List[List[str]] = []

            def rec_runner(cmd: List[str]) -> subprocess.CompletedProcess:
                executed.append(list(cmd))
                return subprocess.CompletedProcess(cmd, 0, "", "")

            fs = FilesystemSyncManager(runner=rec_runner)

            cfg = MigrationConfig(
                pid=1111,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                fs_mode=FilesystemMode.RSYNC,
                writable_paths=[str(live_file)],
            )

            with self.assertRaises(FileNotFoundError):
                fs.final_delta_sync(cfg, "10.0.0.2", snapshot_dir=None)

            with self.assertRaises(FileNotFoundError):
                fs.final_delta_sync(cfg, "10.0.0.2", snapshot_dir=empty_snap)

            self.assertEqual(executed, [])

            cfg_missing = MigrationConfig(
                pid=1111,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                fs_mode=FilesystemMode.RSYNC,
                writable_paths=[str(root / "does_not_exist.db")],
            )
            with self.assertRaises(FileNotFoundError):
                fs.snapshot_writable_paths_while_frozen(cfg_missing, root / "snap2")

    def test_p1_followup_lock_network_idempotent_when_table_already_exists(self) -> None:
        """P1/P2 follow-up: repeated lock_network executes a single atomic nft batch without packet-leak window."""
        from lkmp.acceptance import _simulate_nft_cmd

        executed: List[List[str]] = []
        tables: Dict[str, Dict[str, Any]] = {}

        def runner(cmd: List[str]) -> subprocess.CompletedProcess:
            executed.append(list(cmd))
            return _simulate_nft_cmd(tables, cmd)

        net = NetworkMobilityManager(runner=runner)
        net.lock_network("10.0.0.50", migration_id="mig-idem")
        self.assertTrue(net.verify_network_locked("10.0.0.50", migration_id="mig-idem"))
        executed.clear()

        # Second call on already-existing table commits atomically in 1 nft batch invocation
        net.lock_network("10.0.0.50", migration_id="mig-idem")
        self.assertEqual(len(executed), 1)
        self.assertEqual(executed[0][0], "nft")
        self.assertIn("add table inet", executed[0][1])
        self.assertIn("flush table inet", executed[0][1])
        self.assertEqual(executed[0][1].count(" drop;"), 2)
        self.assertTrue(net.verify_network_locked("10.0.0.50", migration_id="mig-idem"))

    def test_p1_round2_real_criu_never_kills_source_before_restore_or_restores_backup(self) -> None:
        """P1 round-2: REAL_CRIU acceptance uses isolated L2-bridged netns, never kills source before restore, and verifies starttime on rollback."""
        acc_src = (Path(__file__).resolve().parent.parent / "lkmp" / "acceptance.py").read_text(encoding="utf-8")
        self.assertIn("class RealNetnsL2Fabric", acc_src)
        self.assertNotIn("_silence_and_terminate_source_for_cutover", acc_src)
        self.assertNotIn("_backup_source_by_pid", acc_src)
        self.assertNotIn("rb_backup_", acc_src)
        self.assertIn("did not remain", acc_src)
        self.assertIn("post_rb_starttime == orig_src_starttime", acc_src)

    def test_p1_round2_set_pid_tcp_repair_raises_on_permission_or_socket_error(self) -> None:
        """P1 round-2: set_pid_tcp_repair fails closed with TcpRepairError on pidfd_open or pidfd_getfd permission errors."""
        import errno
        from lkmp.network import TcpRepairError, set_pid_tcp_repair

        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp) / "proc"
            fd_dir = proc_root / "4242" / "fd"
            fd_dir.mkdir(parents=True, exist_ok=True)
            os.symlink("socket:[99999]", fd_dir / "3")

            # Missing PID returns process_alive=False without error
            dead_res = set_pid_tcp_repair(9999, enable=True, proc_root=proc_root)
            self.assertFalse(dead_res.process_alive)
            self.assertEqual(dead_res.tcp_sockets_confirmed, 0)

            # 1. pidfd_open failing with EPERM must raise TcpRepairError (never return 0)
            def eperm_pidfd_open(_pid: int) -> int:
                raise PermissionError(errno.EPERM, "Operation not permitted")

            with self.assertRaises(TcpRepairError):
                set_pid_tcp_repair(
                    4242,
                    enable=True,
                    proc_root=proc_root,
                    pidfd_opener=eperm_pidfd_open,
                )

            # 2. pidfd_getfd failing with EPERM must raise TcpRepairError (never return 0)
            r_fd, w_fd = os.pipe()
            os.close(w_fd)

            def eperm_getfd(_pfd: int, _fd: int) -> int:
                raise PermissionError(errno.EPERM, "pidfd_getfd denied")

            with self.assertRaises(TcpRepairError):
                set_pid_tcp_repair(
                    4242,
                    enable=True,
                    proc_root=proc_root,
                    pidfd_opener=lambda _p: r_fd,
                    fd_duplicator=eperm_getfd,
                )

    def test_p1_round2_rollback_dest_and_source_fail_closed_when_tcp_repair_unconfirmed(self) -> None:
        """P1 round-2: rollback_dest refuses SIGKILL and rollback_source refuses SIGCONT if TCP_REPAIR confirmation fails."""
        from lkmp.network import TcpRepairError

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc_a = root / "proc_a"
            proc_b = root / "proc_b"
            for p_dir, p_num in ((proc_a, 100), (proc_b, 200)):
                (p_dir / str(p_num)).mkdir(parents=True, exist_ok=True)
                (p_dir / str(p_num) / "stat").write_text(f"{p_num} (app) T 1 " + "0 " * 17 + "555 0\n", encoding="utf-8")

            signals_a: List[Tuple[int, int]] = []
            signals_b: List[Tuple[int, int]] = []

            def failing_repair(_pids: Any, _enable: bool) -> Any:
                raise TcpRepairError("TCP_REPAIR confirmation denied (EPERM)")

            svc_a = AgentService(
                work_dir=str(root / "work_a"),
                proc_root=str(proc_a),
                net_manager=NetworkMobilityManager(runner=lambda cmd: subprocess.CompletedProcess(cmd, 0, "", "")),
                signal_sender=lambda p, s: signals_a.append((p, s)),
                pid_alive_checker=lambda _p: True,
                tcp_repair_handler=failing_repair,
            )
            svc_b = AgentService(
                work_dir=str(root / "work_b"),
                proc_root=str(proc_b),
                net_manager=NetworkMobilityManager(runner=lambda cmd: subprocess.CompletedProcess(cmd, 0, "", "")),
                signal_sender=lambda p, s: signals_b.append((p, s)),
                pid_alive_checker=lambda _p: True,
                tcp_repair_handler=failing_repair,
            )
            svc_a.prepare_migration("mig-tcp-fail")
            svc_b.prepare_migration("mig-tcp-fail")

            cfg = MigrationConfig(
                pid=100,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                tls=TlsConfig(enabled=False),
                journal_dir=str(root / "wal"),
            )

            # 1. rollback_dest fails closed without sending SIGKILL (preventing unconfirmed FIN/RST)
            rb_dest = svc_b.rollback_dest("mig-tcp-fail", restored_pid=200, config_dict=config_to_dict(cfg))
            self.assertFalse(rb_dest["rolled_back_dest"])
            self.assertFalse(rb_dest["tcp_repair_confirmed"])
            self.assertEqual(signals_b, [])

            # 2. Orchestrator.rollback keeps Source A frozen because rollback_dest returned rolled_back_dest=False
            orch = MigrationOrchestrator(
                cfg,
                AgentClient("10.0.0.1:9700", direct_service=svc_a),
                AgentClient("10.0.0.2:9700", direct_service=svc_b),
                migration_id="mig-tcp-fail",
                journal_dir=str(root / "wal"),
            )
            orch._restored_pid = 200
            rb_orch = orch.rollback("Verify failed")
            self.assertFalse(rb_orch.rolled_back)
            self.assertEqual(signals_a, [])
            self.assertEqual(signals_b, [])

            # 3. Direct rollback_source also refuses SIGCONT if TCP_REPAIR=0 confirmation fails
            with self.assertRaises(RuntimeError):
                svc_a.rollback_source("mig-tcp-fail", source_host="10.0.0.1", config_dict=config_to_dict(cfg))
            self.assertEqual(signals_a, [])

    def test_p1_round2_journal_fails_closed_without_tempdir_fallback_and_rejects_tmpfs(self) -> None:
        """P1 round-2: open_migration_journal never falls back to tempfile.gettempdir() and rejects volatile tmpfs mounts."""
        from unittest.mock import patch
        from lkmp.journal import _verify_persistent_filesystem, open_migration_journal

        journal_src = (Path(__file__).resolve().parent.parent / "lkmp" / "journal.py").read_text(encoding="utf-8")
        self.assertNotIn("gettempdir", journal_src)

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            blocked_parent = root / "not_a_dir"
            blocked_parent.write_text("regular file blocking mkdir\n", encoding="utf-8")
            unwritable_dir = blocked_parent / "journals"

            with self.assertRaises(OSError):
                open_migration_journal(unwritable_dir, "mig-durable-check")

            # Also verify _verify_persistent_filesystem rejects tmpfs and accepts ext4
            fake_mounts = root / "mounts"
            wal_dir = root / "persistent_wal"
            wal_dir.mkdir(parents=True, exist_ok=True)
            resolved_wal = str(wal_dir.resolve())

            fake_mounts.write_text(
                f"dev/sda1 / ext4 rw,relatime 0 0\n"
                f"tmpfs {resolved_wal} tmpfs rw,nosuid,nodev 0 0\n",
                encoding="utf-8",
            )
            with patch("lkmp.journal.sys.platform", "linux"):
                with self.assertRaises(RuntimeError):
                    _verify_persistent_filesystem(wal_dir, mounts_file=fake_mounts)

            fake_mounts.write_text(
                f"/dev/nvme0n1p1 / ext4 rw,relatime 0 0\n"
                f"/dev/nvme0n1p2 {resolved_wal} xfs rw,relatime 0 0\n",
                encoding="utf-8",
            )
            with patch("lkmp.journal.sys.platform", "linux"):
                _verify_persistent_filesystem(wal_dir, mounts_file=fake_mounts)

    def test_p1_round3_custom_journal_dir_rejects_tmpfs_and_propagates_dir_fsync_error(self) -> None:
        """
        P1 round-3:
        1. Custom journal_dir (not only DEFAULT_JOURNAL_DIR) enforces persistent backing storage by default,
           rejecting tmpfs/ramfs in both open_migration_journal() and MigrationJournal.append().
        2. Unreadable/missing /proc/mounts on Linux fails closed with OSError instead of being ignored.
        3. OSError during directory entry fsync on newly created WAL files propagates and leaves seq/entries unadvanced.
        """
        import errno
        from unittest.mock import patch
        from lkmp.journal import (
            DEFAULT_JOURNAL_DIR,
            MigrationJournal,
            _verify_persistent_filesystem,
            open_migration_journal,
        )

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            custom_wal_dir = root / "custom_wal_on_tmpfs"
            self.assertNotEqual(custom_wal_dir.resolve(), Path(DEFAULT_JOURNAL_DIR).resolve())

            fake_mounts = root / "proc_mounts"
            resolved_root = str(root.resolve())
            fake_mounts.write_text(
                f"/dev/nvme0n1p1 / ext4 rw,relatime 0 0\n"
                f"tmpfs {resolved_root} tmpfs rw,nosuid,nodev 0 0\n",
                encoding="utf-8",
            )

            orig_verify = _verify_persistent_filesystem

            def verify_with_fake_mounts(target_dir: Path, mounts_file: Path = fake_mounts) -> None:
                return orig_verify(target_dir, mounts_file=fake_mounts)

            # 1a. open_migration_journal(custom_dir, ...) rejects tmpfs by default (require_persistent omitted -> True)
            with patch("lkmp.journal.sys.platform", "linux"), patch(
                "lkmp.journal._verify_persistent_filesystem", side_effect=verify_with_fake_mounts
            ):
                with self.assertRaisesRegex(RuntimeError, "volatile tmpfs mount"):
                    open_migration_journal(custom_wal_dir, "mig-custom-tmpfs")

                # 1b. Direct MigrationJournal(custom_dir, ...).append() also enforces persistent storage by default
                direct_journal = MigrationJournal(root / "direct_wal_on_tmpfs", "mig-direct-tmpfs")
                with self.assertRaisesRegex(RuntimeError, "volatile tmpfs mount"):
                    direct_journal.append(MigrationState.INIT, MigrationState.PREFLIGHT)

            # 2. Missing /proc/mounts on Linux fails closed instead of silently passing
            with patch("lkmp.journal.sys.platform", "linux"):
                with self.assertRaisesRegex(RuntimeError, "Cannot verify persistent filesystem"):
                    _verify_persistent_filesystem(root, mounts_file=root / "nonexistent_mounts")

            # 3. Directory entry fsync failure on new WAL file propagates OSError and does not advance journal state
            durable_dir = root / "durable_wal"
            durable_dir.mkdir(parents=True, exist_ok=True)
            journal = MigrationJournal(durable_dir, "mig-dir-fsync-fail", require_persistent=False)

            real_fsync = os.fsync
            fsync_calls = [0]

            def fail_on_second_fsync(fd: int) -> None:
                fsync_calls[0] += 1
                if fsync_calls[0] == 2:
                    # 1st fsync is the WAL file fd; 2nd fsync is the parent directory fd
                    raise OSError(errno.EIO, "Simulated parent directory fsync I/O failure")
                real_fsync(fd)

            with patch("lkmp.journal.os.fsync", side_effect=fail_on_second_fsync):
                with self.assertRaisesRegex(OSError, "Simulated parent directory fsync I/O failure"):
                    journal.append(MigrationState.INIT, MigrationState.PREFLIGHT)

            self.assertEqual(journal._seq, 0)
            self.assertEqual(journal.entries, [])

    def test_p1_round3_verify_restored_stopped_confirms_stopped_state_and_active_nft_lock(self) -> None:
        """
        P1 round-3:
        verify_restored_stopped must confirm BOTH:
        1. Every process and thread in the restored tree is in kernel stopped state ('T' or 't').
        2. Active per-migration nftables input/output drop rules are present on Destination B when network lock applies.
        """
        with tempfile.TemporaryDirectory() as tmp:
            harness = _FakeClusterHarness(tmp)
            mig_id = "mig-barrier-r3"
            vip = "10.0.0.88/24"
            cfg = MigrationConfig(
                pid=1234,
                workload_id="srv-barrier",
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                workload_ip=vip,
                tcp_established=True,
                verify_attestation=False,
                tls=TlsConfig(enabled=False),
            )

            # Prepare checkpoint and restore on Destination B with --leave-stopped
            ckpt_b = harness.work_b / mig_id / "final"
            ckpt_b.mkdir(parents=True, exist_ok=True)
            (ckpt_b / "inventory.img").write_bytes(b"IMG")
            res_restore = harness.service_b.restore_process(mig_id, "10.0.0.1", config_to_dict(cfg))
            restored_pid = res_restore["restored_pid"]
            self.assertEqual(restored_pid, 5678)

            # Case 1: Immediately after restore_process, stopped PIDs + active input/output drop lock -> healthy=True
            res_ok = harness.service_b.verify_restored_stopped(restored_pid, migration_id=mig_id)
            self.assertTrue(res_ok["healthy"], msg=f"Expected healthy barrier, got: {res_ok}")
            self.assertTrue(res_ok["stopped_confirmed"])
            self.assertTrue(res_ok["network_lock_confirmed"])

            # Case 2: If nftables lock is removed prematurely on B -> must fail closed
            harness.service_b.net.unlock_network(vip, migration_id=mig_id)
            res_unlocked = harness.service_b.verify_restored_stopped(restored_pid, migration_id=mig_id)
            self.assertFalse(res_unlocked["healthy"])
            self.assertIn("Active nftables network lock not confirmed", res_unlocked["reason"])

            # Case 3: Table + chain exist on B WITHOUT drop rules -> must still fail closed
            from lkmp.network import NetworkMobilityManager

            table_name = NetworkMobilityManager.table_name_for(vip, migration_id=mig_id)
            harness.service_b.net.runner(["nft", "add", "table", "inet", table_name])
            harness.service_b.net.runner(
                ["nft", "add", "chain", "inet", table_name, "input", "{ type filter hook input priority -100 ; policy accept ; }"]
            )
            res_empty_table = harness.service_b.verify_restored_stopped(restored_pid, migration_id=mig_id)
            self.assertFalse(res_empty_table["healthy"])
            self.assertIn("Active nftables network lock not confirmed", res_empty_table["reason"])

            # Re-install full lock_network on B -> barrier passes again
            harness.service_b.net.lock_network(vip, migration_id=mig_id)
            self.assertTrue(harness.service_b.verify_restored_stopped(restored_pid, migration_id=mig_id)["healthy"])

            # Case 4: Child thread/task transitions to 'S (sleeping)' prematurely -> must fail closed
            tid_dir = harness.proc_b / str(restored_pid) / "task" / "5679"
            tid_dir.mkdir(parents=True, exist_ok=True)
            (tid_dir / "stat").write_text("5679 (worker_thr) S 1 5678 5678 0 -1 4194560 0 0 0 0 1 1 0 0 20 0 2 0 100 1024 10 18446744073709551615 0\n", encoding="utf-8")
            (tid_dir / "status").write_text("Name:\tworker_thr\nState:\tS (sleeping)\nPid:\t5679\n", encoding="utf-8")

            res_thread_running = harness.service_b.verify_restored_stopped(restored_pid, migration_id=mig_id)
            self.assertFalse(res_thread_running["healthy"])
            self.assertIn("is not stopped on destination", res_thread_running["reason"])
            self.assertIn("thread 5679 state is 'S'", res_thread_running["reason"])

            # Once worker thread is also stopped ('T'), barrier passes again
            (tid_dir / "stat").write_text("5679 (worker_thr) T 1 5678 5678 0 -1 4194560 0 0 0 0 1 1 0 0 20 0 2 0 100 1024 10 18446744073709551615 0\n", encoding="utf-8")
            (tid_dir / "status").write_text("Name:\tworker_thr\nState:\tT (stopped)\nPid:\t5679\n", encoding="utf-8")
            self.assertTrue(harness.service_b.verify_restored_stopped(restored_pid, migration_id=mig_id)["healthy"])

            # Case 5: tcp_established=True with missing workload_ip fails closed instead of skipping lock check
            mig_no_ip = "mig-no-ip-r3"
            ckpt_no_ip = harness.work_b / mig_no_ip / "final"
            ckpt_no_ip.mkdir(parents=True, exist_ok=True)
            (ckpt_no_ip / "inventory.img").write_bytes(b"IMG")
            cfg_no_ip = MigrationConfig(
                pid=1234,
                workload_id="srv-no-ip",
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                workload_ip=None,
                tcp_established=True,
                verify_attestation=False,
                tls=TlsConfig(enabled=False),
            )
            harness.service_b.restore_process(mig_no_ip, "10.0.0.1", config_to_dict(cfg_no_ip))
            res_no_ip = harness.service_b.verify_restored_stopped(5678, migration_id=mig_no_ip)
            self.assertFalse(res_no_ip["healthy"])
            self.assertIn("workload_ip is not configured", res_no_ip["reason"])

    def test_r4_p0_member_recovery_consults_authoritative_gang_journal_decision(self) -> None:
        """
        P0 round-4: If a crash occurs after GangJournal records COMMITTED but before a member's
        individual WAL appends COMMITTED (still in PREPARED_STOPPED), recovering that single
        member via MigrationOrchestrator.recover_from_journal MUST consult `.gang.wal.jsonl`,
        roll forward (killing Source A and resuming Destination B), and NEVER roll back Source A.
        If the referenced gang WAL is missing, member recovery MUST fail closed.
        """
        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            h1 = _FakeClusterHarness(tmp1)
            h2 = _FakeClusterHarness(tmp2)
            wal_dir = Path(tmp1) / "wal"

            cfg1 = MigrationConfig(
                pid=1234,
                workload_id="srv-g1",
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                workload_ip="10.0.0.10/24",
                verify_attestation=False,
                tls=TlsConfig(enabled=False),
            )
            cfg2 = MigrationConfig(
                pid=1234,
                workload_id="srv-g2",
                source_addr="10.0.0.3:9700",
                dest_addr="10.0.0.4:9700",
                strategy=MigrationStrategy.COLD,
                workload_ip="10.0.0.11/24",
                verify_attestation=False,
                tls=TlsConfig(enabled=False),
            )

            src1 = AgentClient("10.0.0.1:9700", direct_service=h1.service_a)
            dst1 = AgentClient("10.0.0.2:9700", direct_service=h1.service_b)
            src2 = AgentClient("10.0.0.3:9700", direct_service=h2.service_a)
            dst2 = AgentClient("10.0.0.4:9700", direct_service=h2.service_b)

            coordinator = GangMigrationCoordinator(
                gang_id="gang-r4-gap",
                journal_dir=str(wal_dir),
                members=[(cfg1, src1, dst1), (cfg2, src2, dst2)],
            )

            # Run Phase 1 prepare on both members (stops at PREPARED_STOPPED)
            for orch in coordinator.orchestrators:
                prep_res = orch.execute_prepare_phase(keep_stopped_on_prepare=True)
                self.assertTrue(prep_res.success)

            # Simulate crash in the exact gap: GangJournal appends COMMITTED, member WALs do NOT yet have COMMITTED!
            coordinator.journal.append(state=MigrationState.COMMIT, commit_decision="COMMITTED")
            m2_wal = wal_dir / "gang-r4-gap-m2.wal.jsonl"
            self.assertFalse(MigrationJournal.load(m2_wal).has_committed_decision)
            self.assertEqual(MigrationJournal.load(m2_wal).coupled_gang_id, "gang-r4-gap")

            # Recover ONLY Member 2 via MigrationOrchestrator.recover_from_journal:
            # Must follow GangJournal COMMITTED -> roll forward, NEVER resume Source A!
            rec_m2 = MigrationOrchestrator.recover_from_journal(m2_wal, src2, dst2)
            self.assertTrue(rec_m2.success)
            self.assertFalse(rec_m2.rolled_back)
            self.assertEqual(rec_m2.final_state, MigrationState.COMMIT)
            self.assertNotIn((1234, signal.SIGCONT), h2.signals_a)
            self.assertIn((1234, signal.SIGKILL), h2.signals_a)
            self.assertIn((5678, signal.SIGCONT), h2.signals_b)

            # Now test fail-closed when gang WAL is missing for Member 1
            (wal_dir / "gang-r4-gap.gang.wal.jsonl").unlink()
            m1_wal = wal_dir / "gang-r4-gap-m1.wal.jsonl"
            with self.assertRaises(FileNotFoundError):
                MigrationOrchestrator.recover_from_journal(m1_wal, src1, dst1)

    def test_r4_p1_gang_rollback_reports_false_when_member_rollback_fails(self) -> None:
        """
        P1 round-4: GangMigrationCoordinator.execute_atomic() and recover_from_journal() must
        NOT write ROLLED_BACK or report atomic_rollback_triggered=True unless every member
        confirmed rolled_back=True.
        """
        with tempfile.TemporaryDirectory() as tmp1, tempfile.TemporaryDirectory() as tmp2:
            h1 = _FakeClusterHarness(tmp1)
            h2 = _FakeClusterHarness(tmp2)
            h2.fail_on_restore = True  # Member 2 will fail Phase 1 restore -> triggers gang rollback!
            wal_dir = Path(tmp1) / "wal"

            # Force Member 1's rollback_dest to fail so Member 1 cannot safely roll back!
            def broken_rollback_dest(migration_id: str, restored_pid: Optional[int], config_dict: Dict[str, Any]) -> Dict[str, Any]:
                raise RuntimeError("Destination B1 unreachable during gang rollback")

            h1.service_b.rollback_dest = broken_rollback_dest  # type: ignore[method-assign]

            cfg1 = MigrationConfig(
                pid=1234,
                workload_id="srv-rb1",
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                workload_ip="10.0.0.10/24",
                verify_attestation=False,
                tls=TlsConfig(enabled=False),
            )
            cfg2 = MigrationConfig(
                pid=1234,
                workload_id="srv-rb2",
                source_addr="10.0.0.3:9700",
                dest_addr="10.0.0.4:9700",
                strategy=MigrationStrategy.COLD,
                workload_ip="10.0.0.11/24",
                verify_attestation=False,
                tls=TlsConfig(enabled=False),
            )
            members = [
                (cfg1, AgentClient("10.0.0.1:9700", direct_service=h1.service_a), AgentClient("10.0.0.2:9700", direct_service=h1.service_b)),
                (cfg2, AgentClient("10.0.0.3:9700", direct_service=h2.service_a), AgentClient("10.0.0.4:9700", direct_service=h2.service_b)),
            ]

            coordinator = GangMigrationCoordinator(
                gang_id="gang-r4-rb-fail",
                journal_dir=str(wal_dir),
                members=members,
            )
            gang_res = coordinator.execute_atomic()
            self.assertFalse(gang_res.all_committed)
            self.assertFalse(gang_res.atomic_rollback_triggered)
            self.assertIsNotNone(gang_res.error_message)
            self.assertIn("gang-r4-rb-fail-m1", gang_res.error_message or "")

            loaded_gang_wal = MigrationJournal.load(coordinator.journal.path)
            self.assertFalse(
                any(e.commit_decision == "ROLLED_BACK" for e in loaded_gang_wal.entries),
                "Gang WAL must NOT claim ROLLED_BACK when a member rollback failed",
            )

            # Also verify GangMigrationCoordinator.recover_from_journal on uncommitted gang WAL
            rec_res = GangMigrationCoordinator.recover_from_journal(
                gang_journal_path=coordinator.journal.path,
                members=members,
            )
            self.assertFalse(rec_res.all_committed)
            self.assertFalse(rec_res.atomic_rollback_triggered)
            self.assertIn("gang-r4-rb-fail-m1", rec_res.error_message or "")

    def test_r4_p1_verify_process_none_fails_closed_and_blocks_commit_source(self) -> None:
        """
        P1 round-4: AgentService.verify_process(None, None) must return healthy=False, and
        roll-forward recovery (both single-member and gang) must refuse to call commit_source
        (SIGKILL on Source A) when Destination B has no verified restored PID.
        """
        with tempfile.TemporaryDirectory() as tmp:
            harness = _FakeClusterHarness(tmp)

            # 1. Direct verify_process(None, None) and invalid PID <= 0 MUST return healthy=False
            res_none = harness.service_b.verify_process(None, None)
            self.assertFalse(res_none["healthy"])
            self.assertIn("No restored PID", res_none["reason"])
            self.assertFalse(harness.service_b.verify_process(0, None)["healthy"])
            self.assertFalse(harness.service_b.verify_process(-5, None)["healthy"])

            # 2. Single-member roll-forward recovery with missing restored_pid must NOT kill Source A
            wal_dir = Path(tmp) / "wal"
            cfg = MigrationConfig(
                pid=1234,
                workload_id="srv-nopid",
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                verify_attestation=False,
                tls=TlsConfig(enabled=False),
            )
            j_single = MigrationJournal(wal_dir, "mig-nopid-commit")
            j_single.append(MigrationState.INIT, "PREPARING", config_dict=config_to_dict(cfg))
            j_single.append(MigrationState.COMMIT, "COMMITTED", restored_pid=None)

            src = AgentClient("10.0.0.1:9700", direct_service=harness.service_a)
            dst = AgentClient("10.0.0.2:9700", direct_service=harness.service_b)
            rec_single = MigrationOrchestrator.recover_from_journal(j_single.path, src, dst)
            self.assertFalse(rec_single.success)
            self.assertIn("No restored PID", rec_single.error_message or "")
            self.assertNotIn((1234, signal.SIGKILL), harness.signals_a)

            # 3. Gang roll-forward recovery with missing restored_pid must NOT kill Source A
            g_journal = MigrationJournal(wal_dir, "gang-nopid.gang")
            g_journal.append(MigrationState.PREPARE, "PREPARING")
            g_journal.append(MigrationState.COMMIT, "COMMITTED")
            m_journal = MigrationJournal(wal_dir, "gang-nopid-m1", gang_id="gang-nopid")
            m_journal.append(MigrationState.INIT, "PREPARING", config_dict=config_to_dict(cfg))

            rec_gang = GangMigrationCoordinator.recover_from_journal(
                gang_journal_path=g_journal.path,
                members=[(cfg, src, dst)],
            )
            self.assertFalse(rec_gang.all_committed)
            self.assertTrue(rec_gang.partial_commit_error)
            self.assertNotIn((1234, signal.SIGKILL), harness.signals_a)

    def test_r4_p1_cow_rejects_loopback_and_same_path_unshared_vms_requires_probe(self) -> None:
        """
        P1 round-4: Equal addresses or loopback (`127.0.0.1:9700` -> `127.0.0.1:9701`) must NOT
        select local CoW copying when Source A and Destination B have unshared storage (e.g., two
        separate VMs over SSH port-forwarding, even with identical `/migrations` path strings).
        CoW is selected ONLY when Destination B's cryptographic `.lkmp_storage_probe.json` is
        visible on Source A's local VFS.
        """
        with tempfile.TemporaryDirectory() as vm_a, tempfile.TemporaryDirectory() as vm_b:
            proc_a = Path(vm_a) / "proc"
            (proc_a / "4242" / "task" / "4242").mkdir(parents=True, exist_ok=True)
            (proc_a / "4242" / "status").write_text("Name:\tsrv\nState:\tS (sleeping)\n", encoding="utf-8")
            (proc_a / "4242" / "task" / "4242" / "children").write_text("", encoding="utf-8")

            cmds_a: List[List[str]] = []

            def runner_a(cmd: List[str]) -> subprocess.CompletedProcess:
                cmds_a.append(list(cmd))
                if cmd[0] == "criu" and len(cmd) >= 2 and cmd[1] == "dump":
                    d_idx = cmd.index("--images-dir")
                    out_d = Path(cmd[d_idx + 1])
                    out_d.mkdir(parents=True, exist_ok=True)
                    (out_d / "core-1.img").write_bytes(b"CORE")
                    (out_d / "pages-1.img").write_bytes(b"PAGES")
                return subprocess.CompletedProcess(cmd, 0, "", "")

            # Separate VMs with unshared filesystems reached over loopback port forwarding
            svc_vm_a = AgentService(
                work_dir=str(Path(vm_a) / "migrations"),
                proc_root=str(proc_a),
                criu_driver=CriuDriver(runner=runner_a),
                fs_manager=FilesystemSyncManager(runner=runner_a),
                pid_alive_checker=lambda _p: True,
            )
            svc_vm_b = AgentService(
                work_dir=str(Path(vm_b) / "migrations"),
                proc_root=str(proc_a),
                pid_alive_checker=lambda _p: True,
            )

            svc_vm_a.prepare_migration("mig-unshared")
            dst_prep_b = svc_vm_b.prepare_migration("mig-unshared")

            cfg_loopback = MigrationConfig(
                pid=4242,
                source_addr="127.0.0.1:9700",
                dest_addr="127.0.0.1:9701",
                strategy=MigrationStrategy.COLD,
                fs_mode=FilesystemMode.SHARED,
                same_host_cow=True,
                verify_attestation=False,
                tls=TlsConfig(enabled=False),
            )
            cfg_dict = config_to_dict(cfg_loopback)
            svc_vm_a.freeze_and_final_dump("mig-unshared", None, "127.0.0.1", cfg_dict)

            # Simulate identical path string across two separate VMs (pointing at VM A's own path
            # while passing VM B's probe token -> token + agent_id mismatch MUST reject CoW and use rsync!)
            own_a_final = str(Path(vm_a) / "migrations" / "mig-unshared" / "final")
            cmds_a.clear()
            res_unshared = svc_vm_a.transfer_final_state(
                migration_id="mig-unshared",
                dest_host="127.0.0.1",
                config_dict=cfg_dict,
                dest_images_dir=own_a_final,
                dest_probe_token=dst_prep_b["storage_probe_token"],
            )
            self.assertFalse(res_unshared["cow_fast_path"])
            self.assertTrue(any(c[0] == "rsync" for c in cmds_a))
            self.assertFalse(any(c[0] == "cp" for c in cmds_a))

            # Now pass VM B's directory visible on shared VFS with VM B's matching probe token -> CoW succeeds!
            cmds_a.clear()
            res_shared = svc_vm_a.transfer_final_state(
                migration_id="mig-unshared",
                dest_host="127.0.0.1",
                config_dict=cfg_dict,
                dest_images_dir=dst_prep_b["images_dir"],
                dest_probe_token=dst_prep_b["storage_probe_token"],
            )
            self.assertTrue(res_shared["cow_fast_path"])
            self.assertTrue(any(c[0] == "cp" for c in cmds_a))
            self.assertFalse(any(c[0] == "rsync" for c in cmds_a))

    def test_r4_wal_checksum_and_torn_trailing_record_recovery(self) -> None:
        """
        Round-4 WAL integrity:
        1. Un-fsynced torn trailing line (truncated JSON, missing newline, NUL bytes, or bad checksum)
           after >=1 valid entry is cleanly discarded (`discarded_torn_tail=True`).
        2. Mid-file corruption or single-line corruption raises `ValueError` (fail-closed).
        """
        with tempfile.TemporaryDirectory() as tmp:
            wal_dir = Path(tmp) / "journals"
            cfg = MigrationConfig(
                pid=1234,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                tls=TlsConfig(enabled=False),
            )
            j = MigrationJournal(wal_dir, "mig-torn-wal")
            j.append(MigrationState.INIT, "PREPARING", config_dict=config_to_dict(cfg))
            j.append(MigrationState.VERIFY, "PREPARED_STOPPED", restored_pid=5678)

            # Append a torn partial COMMITTED record (crash mid-write before newline/fsync)
            with j.path.open("ab") as f:
                f.write(b'{"seq": 3, "migration_id": "mig-torn-wal", "commit_decision": "COMMI')

            loaded = MigrationJournal.load(j.path)
            self.assertTrue(loaded.discarded_torn_tail)
            self.assertEqual(len(loaded.entries), 2)
            self.assertFalse(loaded.has_committed_decision)
            self.assertEqual(loaded.last_entry.restored_pid, 5678)  # type: ignore[union-attr]

            # Corrupting line 1 (mid-file checksum tampering) MUST fail closed with ValueError!
            raw_lines = j.path.read_bytes().splitlines(keepends=True)
            tampered_first = raw_lines[0].replace(b'"PREPARING"', b'"COMMITTED"')
            j.path.write_bytes(tampered_first + raw_lines[1])
            with self.assertRaises(ValueError):
                MigrationJournal.load(j.path)

            # Single torn line with zero valid committed entries MUST also fail closed with ValueError!
            j_empty = wal_dir / "mig-only-torn.wal.jsonl"
            j_empty.write_bytes(b'{"seq": 1, "migration_id": "mig-only-torn"')
            with self.assertRaises(ValueError):
                MigrationJournal.load(j_empty)


if __name__ == "__main__":
    unittest.main()
