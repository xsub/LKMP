"""Comprehensive test suite for LKMP v0.2 enhancements (mTLS PKI, IPv6, CLI, metrics, concurrency, hygiene)."""

from __future__ import annotations

import io
import json
import os
import signal
import socket
import struct
import subprocess
import tempfile
import unittest
import urllib.request
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any, Dict, List
from unittest import mock

import lkmp
import lkmp.agent
from lkmp.agent import AgentClient, AgentServer, AgentService, config_to_dict
from lkmp.cli import _build_migration_config, build_parser, main as cli_main
from lkmp.config import (
    EnvelopeConfig,
    FilesystemMode,
    IpMobilityMode,
    MigrationConfig,
    MigrationStrategy,
    TlsConfig,
)
from lkmp.convergence import PreCopyConvergenceTracker
from lkmp.criu_driver import CriuDriver
from lkmp.envelope import EnvelopeManager
from lkmp.fs_sync import FilesystemSyncManager, format_rsync_remote
from lkmp.journal import inspect_journal_file
from lkmp.models import HostCapabilities, ProcessSnapshotInfo, ResourceClassification
from lkmp.network import NetworkMobilityManager, format_host_port, parse_host_port
from lkmp.pagemap import (
    PAGE_SIZE,
    PTE_PRESENT_BIT,
    PTE_SOFT_DIRTY_BIT,
    sample_process_dirty_rate,
)
from lkmp.pki import generate_mtls_pki
from lkmp.preflight import evaluate_portability
from tests.test_orchestrator_fsm import _FakeClusterHarness

CommandResult = subprocess.CompletedProcess


def _loopback_tcp_allowed() -> bool:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        s.close()
        return True
    except OSError:
        return False


def _loopback_ipv6_allowed() -> bool:
    if not socket.has_ipv6:
        return False
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.bind(("::1", 0))
        s.close()
        return True
    except OSError:
        return False


class ComprehensiveEnhancementsTests(unittest.TestCase):
    def test_01_public_sdk_exports_and_version(self) -> None:
        self.assertEqual(lkmp.__version__, "0.3.0")
        self.assertTrue((Path(lkmp.__file__).parent / "py.typed").exists())
        for sym in (
            "AgentClient",
            "AgentServer",
            "AgentService",
            "GangMigrationCoordinator",
            "MigrationOrchestrator",
            "generate_mtls_pki",
            "inspect_journal_file",
        ):
            self.assertTrue(hasattr(lkmp, sym), f"Missing public symbol {sym}")

    def test_02_mtls_pki_bootstrap_and_real_rpc_handshake(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pki_dir = Path(tmp) / "pki"
            rogue_dir = Path(tmp) / "rogue"
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = cli_main(
                    [
                        "tls-init",
                        "--out-dir",
                        str(pki_dir),
                        "--host",
                        "127.0.0.1",
                        "--host",
                        "localhost",
                        "--node",
                        "node-a",
                        "--node",
                        "node-b",
                        "--json",
                    ]
                )
            self.assertEqual(rc, 0)
            pki_info = json.loads(buf.getvalue())
            self.assertTrue(Path(pki_info["ca_cert"]).exists())
            self.assertTrue(Path(pki_info["named_nodes"]["node-a"]["cert"]).exists())
            key_mode = Path(pki_info["node_key"]).stat().st_mode & 0o777
            self.assertEqual(key_mode, 0o600)

            generate_mtls_pki(rogue_dir, hosts=["127.0.0.1"])

            if not _loopback_tcp_allowed():
                return

            svc = AgentService(work_dir=str(Path(tmp) / "work"))
            server_tls = TlsConfig(
                enabled=True,
                ca_cert=pki_info["ca_cert"],
                cert_file=pki_info["named_nodes"]["node-a"]["cert"],
                key_file=pki_info["named_nodes"]["node-a"]["key"],
            )
            srv = AgentServer("127.0.0.1", 0, svc, tls=server_tls)
            srv.start_background()
            try:
                _, port = srv.bound_address
                client_tls = TlsConfig(
                    enabled=True,
                    ca_cert=pki_info["ca_cert"],
                    cert_file=pki_info["named_nodes"]["node-b"]["cert"],
                    key_file=pki_info["named_nodes"]["node-b"]["key"],
                )
                client = AgentClient(f"127.0.0.1:{port}", tls=client_tls)
                res1 = client.call("health_check")
                res2 = client.call("health_check")
                self.assertEqual(res1["status"], "ok")
                self.assertEqual(res2["agent_id"], res1["agent_id"])

                # Rogue client signed by a different CA must fail strict mTLS handshake
                rogue_tls = TlsConfig(
                    enabled=True,
                    ca_cert=pki_info["ca_cert"],
                    cert_file=str(rogue_dir / "node.crt"),
                    key_file=str(rogue_dir / "node.key"),
                )
                rogue_client = AgentClient(f"127.0.0.1:{port}", tls=rogue_tls, max_retries=0)
                with self.assertRaises(Exception):
                    rogue_client.call("health_check")
            finally:
                srv.shutdown()

    def test_03_ipv6_parsing_dual_stack_rpc_rsync_and_ip6ip6_tunnel(self) -> None:
        self.assertEqual(parse_host_port("[::1]:9700"), ("::1", 9700))
        self.assertEqual(parse_host_port("[2001:db8::2]"), ("2001:db8::2", 9700))
        self.assertEqual(parse_host_port("2001:db8::2"), ("2001:db8::2", 9700))
        self.assertEqual(parse_host_port("10.0.0.2:9800"), ("10.0.0.2", 9800))
        self.assertEqual(format_host_port("2001:db8::2", 9700), "[2001:db8::2]:9700")
        self.assertEqual(format_rsync_remote("2001:db8::2", "/var/data/"), "[2001:db8::2]:/var/data/")
        self.assertEqual(format_rsync_remote("10.0.0.2", "/var/data/"), "10.0.0.2:/var/data/")

        recorded: List[List[str]] = []

        def fake_runner(cmd: List[str]) -> CommandResult:
            recorded.append(list(cmd))
            return CommandResult(cmd, 0, "", "")

        net = NetworkMobilityManager(runner=fake_runner)
        cfg_v6 = MigrationConfig(
            pid=500,
            source_addr="[2001:db8::1]:9700",
            dest_addr="[2001:db8::2]:9700",
            ip_mobility=IpMobilityMode.TUNNEL,
            workload_ip="2001:db8::50/64",
        )
        net.release_ip_on_host(cfg_v6, migration_id="mig-v6")
        self.assertIn(
            ["ip", "-6", "tunnel", "add", "lkmpmigv6", "mode", "ip6ip6", "remote", "2001:db8::2"],
            recorded,
        )
        self.assertIn(
            ["ip", "-6", "route", "replace", "2001:db8::50/128", "dev", "lkmpmigv6"],
            recorded,
        )
        net.teardown_tunnel(cfg_v6, migration_id="mig-v6")
        self.assertEqual(recorded[-1], ["ip", "link", "del", "lkmpmigv6"])

        fs_cmds: List[List[str]] = []
        fs = FilesystemSyncManager(
            runner=lambda c: (fs_cmds.append(list(c)), CommandResult(c, 0, "", ""))[1]
        )
        cfg_rsync = MigrationConfig(
            pid=500,
            source_addr="[2001:db8::1]:9700",
            dest_addr="[2001:db8::2]:9700",
            fs_mode=FilesystemMode.RSYNC,
            writable_paths=["/srv/state"],
        )
        fs.pre_sync_writable_paths(cfg_rsync, dest_host="[2001:db8::2]")
        self.assertEqual(fs_cmds[0][-1], "[2001:db8::2]:/srv/state/")

        if _loopback_ipv6_allowed():
            with tempfile.TemporaryDirectory() as tmp:
                svc = AgentService(work_dir=tmp)
                srv = AgentServer("::1", 0, svc, tls=TlsConfig(enabled=False))
                srv.start_background()
                try:
                    _, port = srv.bound_address
                    cli = AgentClient(f"[::1]:{port}", tls=TlsConfig(enabled=False))
                    self.assertEqual(cli.host, "::1")
                    self.assertEqual(cli.port, port)
                    res = cli.call("health_check")
                    self.assertEqual(res["status"], "ok")
                finally:
                    srv.shutdown()

    def test_04_custom_bgp_daemon_cmd_template(self) -> None:
        cmds: List[List[str]] = []
        net = NetworkMobilityManager(
            runner=lambda c: (cmds.append(list(c)), CommandResult(c, 0, "", ""))[1]
        )
        cfg = MigrationConfig(
            pid=101,
            source_addr="10.0.0.1:9700",
            dest_addr="10.0.0.2:9700",
            ip_mobility=IpMobilityMode.BGP,
            workload_ip="192.0.2.55/24",
            bgp_daemon_cmd="frr-ctl --op {action} --prefix {prefix} --af {af} --nh {host}",
        )
        net.release_ip_on_host(cfg)
        net.announce_ip_on_host(cfg, target_host="10.0.0.2")
        self.assertIn(
            ["frr-ctl", "--op", "del", "--prefix", "192.0.2.55/32", "--af", "ipv4", "--nh", "10.0.0.1"],
            cmds,
        )
        self.assertIn(
            ["frr-ctl", "--op", "add", "--prefix", "192.0.2.55/32", "--af", "ipv4", "--nh", "10.0.0.2"],
            cmds,
        )

    def test_05_agent_http_metrics_healthz_and_cli_status(self) -> None:
        if not _loopback_tcp_allowed():
            return
        with tempfile.TemporaryDirectory() as tmp:
            svc = AgentService(work_dir=tmp)
            srv = AgentServer("127.0.0.1", 0, svc, tls=TlsConfig(enabled=False), metrics_port=0)
            srv.start_background()
            try:
                _, rpc_port = srv.bound_address
                assert srv.bound_metrics_address is not None
                _, m_port = srv.bound_metrics_address

                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = cli_main(
                        ["status", "--agent", f"127.0.0.1:{rpc_port}", "--no-tls", "--prometheus"]
                    )
                self.assertEqual(rc, 0)
                self.assertIn("LKMP AGENT NODE HEALTH", buf.getvalue())
                self.assertIn("lkmp_rpc_requests_total", buf.getvalue())

                with urllib.request.urlopen(f"http://127.0.0.1:{m_port}/healthz", timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    h_json = json.loads(resp.read().decode("utf-8"))
                    self.assertEqual(h_json["status"], "ok")

                with urllib.request.urlopen(f"http://127.0.0.1:{m_port}/metrics", timeout=5) as resp:
                    self.assertEqual(resp.status, 200)
                    prom_body = resp.read().decode("utf-8")
                    self.assertIn('lkmp_rpc_requests_total{method="health_check"}', prom_body)
                    self.assertIn("lkmp_active_migrations 0", prom_body)
            finally:
                srv.shutdown()

    def test_06_bounded_rpc_frame_rejects_oversized_payload(self) -> None:
        if not _loopback_tcp_allowed():
            return
        with tempfile.TemporaryDirectory() as tmp:
            svc = AgentService(work_dir=tmp)
            srv = AgentServer("127.0.0.1", 0, svc, tls=TlsConfig(enabled=False))
            srv.start_background()
            try:
                _, port = srv.bound_address
                with mock.patch.object(lkmp.agent, "MAX_RPC_MESSAGE_BYTES", 1024):
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
                        huge = (json.dumps({"method": "health_check", "pad": "x" * 4096}) + "\n").encode()
                        sock.sendall(huge)
                        line = sock.makefile("rb").readline()
                    resp = json.loads(line.decode("utf-8"))
                    self.assertFalse(resp["ok"])
                    self.assertIn("exceeds maximum allowed frame size", resp["error"])

                # Server remains healthy immediately after rejecting oversized frame
                cli = AgentClient(f"127.0.0.1:{port}", tls=TlsConfig(enabled=False))
                self.assertEqual(cli.call("health_check")["status"], "ok")
            finally:
                srv.shutdown()

    def test_07_concurrent_same_pid_freeze_guard_and_lifecycle_hygiene(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp) / "proc"
            (proc_root / "4242").mkdir(parents=True)
            (proc_root / "4242" / "stat").write_text("4242 (app) S 1 4242 4242 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 99999 1000 10\n")

            cgroup_root = Path(tmp) / "cgroup"
            wl_cg = cgroup_root / "wl-1"
            wl_cg.mkdir(parents=True)
            freeze_file = wl_cg / "cgroup.freeze"
            freeze_file.write_text("0\n")

            net_cmds: List[List[str]] = []
            net = NetworkMobilityManager(
                runner=lambda c: (net_cmds.append(list(c)), CommandResult(c, 0, "", ""))[1]
            )
            criu = CriuDriver(runner=lambda c: CommandResult(c, 0, "", ""))
            env = EnvelopeManager(
                cgroup_root=str(cgroup_root),
                state_dir=str(Path(tmp) / "envelopes"),
            )
            signals_sent: List[tuple[int, int]] = []
            svc = AgentService(
                work_dir=str(Path(tmp) / "work"),
                proc_root=str(proc_root),
                criu_driver=criu,
                net_manager=net,
                envelope_manager=env,
                signal_sender=lambda p, s: signals_sent.append((p, s)),
                pid_alive_checker=lambda p: p == 4242,
            )

            cfg = MigrationConfig(
                pid=4242,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                workload_id="wl-1",
                strategy=MigrationStrategy.COLD,
                ip_mobility=IpMobilityMode.TUNNEL,
                workload_ip="10.200.0.5/24",
                tls=TlsConfig(enabled=False),
            )
            cfg_dict = config_to_dict(cfg)

            svc.freeze_and_final_dump("mig-1", None, "10.0.0.2", cfg_dict)
            self.assertEqual(freeze_file.read_text().strip(), "1")
            self.assertEqual(svc.health_check()["active_migrations"], 1)

            # Second concurrent migration of the same PID must fail closed
            with self.assertRaisesRegex(RuntimeError, "already locked by active migration"):
                svc.freeze_and_final_dump("mig-2", None, "10.0.0.2", cfg_dict)

            # Rollback tears down tunnel, unfreezes cgroup, and releases active PID lock
            svc.rollback_source("mig-1", "10.0.0.1", cfg_dict)
            self.assertEqual(freeze_file.read_text().strip(), "0")
            self.assertEqual(svc.health_check()["active_migrations"], 0)
            self.assertIn(["ip", "link", "del", "lkmpmig1"], net_cmds)

            # Re-freeze under mig-3, then commit_source must ALSO unfreeze cgroup and release lock
            svc.freeze_and_final_dump("mig-3", None, "10.0.0.2", cfg_dict)
            self.assertEqual(freeze_file.read_text().strip(), "1")
            svc.commit_source("mig-3", cfg_dict)
            self.assertEqual(freeze_file.read_text().strip(), "0")
            self.assertEqual(svc.health_check()["active_migrations"], 0)
            self.assertIn((4242, signal.SIGKILL), signals_sent)

    def test_08_daemon_fd_hygiene_and_cross_restart_orphan_stop(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = Path(tmp) / "lazy-pages.pid"
            driver1 = CriuDriver()
            fds_before = len(os.listdir("/dev/fd")) if Path("/dev/fd").exists() else None
            pid = driver1.run_background_daemon(
                ["python3", "-c", "import time; time.sleep(60)"],
                pidfile=pidfile,
            )
            proc = driver1._daemons[str(pidfile)]
            try:
                if fds_before is not None:
                    fds_after = len(os.listdir("/dev/fd"))
                    self.assertLessEqual(fds_after, fds_before + 1)

                # Simulate agent restart: fresh CriuDriver without proc in _daemons
                fake_proc = Path(tmp) / "fake_proc"
                (fake_proc / str(pid)).mkdir(parents=True)

                # 1. If /proc/<pid>/cmdline belongs to an unrelated daemon (PID reuse), refuse to kill!
                (fake_proc / str(pid) / "cmdline").write_bytes(b"nginx\x00-g\x00daemon off;\x00")
                driver2 = CriuDriver()
                driver2.stop_daemon(pidfile, proc_root=str(fake_proc))
                self.assertIsNone(proc.poll(), "Unrelated PID must NOT be killed on PID reuse!")

                # 2. When /proc/<pid>/cmdline is verified CRIU daemon, stop_daemon terminates it cleanly
                pidfile.write_text(f"{pid}\n", encoding="utf-8")
                (fake_proc / str(pid) / "cmdline").write_bytes(
                    b"/usr/sbin/criu\x00lazy-pages\x00--images-dir\x00/tmp\x00"
                )
                driver2.stop_daemon(pidfile, proc_root=str(fake_proc))
                proc.wait(timeout=3.0)
                self.assertIsNotNone(proc.poll())
                self.assertFalse(pidfile.exists())
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=2.0)

    def test_09_multiprocess_tree_pagemap_dirty_rate_aggregation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp) / "proc"
            page_size = PAGE_SIZE
            entry_dirty = struct.pack("<Q", PTE_PRESENT_BIT | PTE_SOFT_DIRTY_BIT)

            # Build root 200 -> child 201 -> grandchild 202, each with 4 dirty writable pages
            hierarchy = {200: [201], 201: [202], 202: []}
            for pid, children in hierarchy.items():
                t_dir = proc_root / str(pid) / "task" / str(pid)
                t_dir.mkdir(parents=True)
                (t_dir / "children").write_text(" ".join(str(c) for c in children))
                start_addr = 0x10000000
                end_addr = start_addr + 4 * page_size
                (proc_root / str(pid) / "maps").write_text(
                    f"{start_addr:x}-{end_addr:x} rw-p 00000000 00:00 0 [heap]\n"
                )
                (proc_root / str(pid) / "clear_refs").write_text("")
                pm_path = proc_root / str(pid) / "pagemap"
                with open(pm_path, "wb") as f:
                    f.seek((start_addr // page_size) * 8)
                    f.write(entry_dirty * 4)

            tree_sample = sample_process_dirty_rate(
                200, sample_ms=10, proc_root=str(proc_root), include_children=True
            )
            root_only = sample_process_dirty_rate(
                200, sample_ms=10, proc_root=str(proc_root), include_children=False
            )
            self.assertEqual(root_only.dirty_bytes, 4 * page_size)
            self.assertEqual(tree_sample.dirty_bytes, 12 * page_size)
            self.assertEqual(len(tree_sample.vma_profiles), 3)

    def test_10_destination_disk_space_preflight_blocker(self) -> None:
        src_caps = HostCapabilities(
            arch="x86_64",
            kernel_release="6.8.0",
            cpu_vendor="GenuineIntel",
            criu_available=True,
        )
        dst_low_disk = HostCapabilities(
            arch="x86_64",
            kernel_release="6.8.0",
            cpu_vendor="GenuineIntel",
            criu_available=True,
            has_userfaultfd=True,
            work_dir_free_bytes=10 * 1024 * 1024,  # 10 MiB free
        )
        snap = ProcessSnapshotInfo(
            root_pid=1000,
            rss_bytes=128 * 1024 * 1024,  # 128 MiB RSS
            in_envelope=True,
        )
        cfg_precopy = MigrationConfig(
            pid=1000,
            source_addr="10.0.0.1:9700",
            dest_addr="10.0.0.2:9700",
            strategy=MigrationStrategy.PRE_COPY,
        )
        rep_blocked = evaluate_portability(cfg_precopy, src_caps, dst_low_disk, snap)
        self.assertFalse(rep_blocked.compatible)
        self.assertTrue(
            any(
                f.resource_type == "disk" and f.classification == ResourceClassification.BLOCKER
                for f in rep_blocked.findings
            )
        )

        # LAZY streams pages via userfaultfd rather than dumping full RSS to disk upfront
        cfg_lazy = MigrationConfig(
            pid=1000,
            source_addr="10.0.0.1:9700",
            dest_addr="10.0.0.2:9700",
            strategy=MigrationStrategy.LAZY,
        )
        rep_lazy = evaluate_portability(cfg_lazy, src_caps, dst_low_disk, snap)
        self.assertTrue(rep_lazy.compatible)

    def test_11_cli_gang_migrate_and_wal_inspect_diagnostics(self) -> None:
        if not _loopback_tcp_allowed():
            return
        with tempfile.TemporaryDirectory() as tmp:
            h1 = _FakeClusterHarness(str(Path(tmp) / "h1"))
            h2 = _FakeClusterHarness(str(Path(tmp) / "h2"))
            srv_a1 = AgentServer("127.0.0.1", 0, h1.service_a, tls=TlsConfig(enabled=False))
            srv_b1 = AgentServer("127.0.0.1", 0, h1.service_b, tls=TlsConfig(enabled=False))
            srv_a2 = AgentServer("127.0.0.1", 0, h2.service_a, tls=TlsConfig(enabled=False))
            srv_b2 = AgentServer("127.0.0.1", 0, h2.service_b, tls=TlsConfig(enabled=False))
            for s in (srv_a1, srv_b1, srv_a2, srv_b2):
                s.start_background()
            try:
                addr_a1 = f"127.0.0.1:{srv_a1.bound_address[1]}"
                addr_b1 = f"127.0.0.1:{srv_b1.bound_address[1]}"
                addr_a2 = f"127.0.0.1:{srv_a2.bound_address[1]}"
                addr_b2 = f"127.0.0.1:{srv_b2.bound_address[1]}"
                j_dir = Path(tmp) / "journals"

                buf = io.StringIO()
                with redirect_stdout(buf):
                    rc = cli_main(
                        [
                            "gang-migrate",
                            "--gang-id",
                            "gang-cli-01",
                            "--member",
                            f"pid=1234,source={addr_a1},dest={addr_b1},strategy=cold,ip_mobility=garp,workload_ip=10.0.0.91/24,same_host_cow=false",
                            "--member",
                            f"pid=1234,source={addr_a2},dest={addr_b2},strategy=cold,ip_mobility=garp,workload_ip=10.0.0.92/24,same_host_cow=false",
                            "--journal-dir",
                            str(j_dir),
                            "--allow-volatile-journal",
                            "--no-tls",
                            "--json",
                        ]
                    )
                self.assertEqual(rc, 0)
                gang_out = json.loads(buf.getvalue())
                self.assertTrue(gang_out["all_committed"])
                self.assertEqual(len(gang_out["member_results"]), 2)

                gang_wal = j_dir / "gang-cli-01.gang.wal.jsonl"
                m1_wal = j_dir / "gang-cli-01-m1.wal.jsonl"

                # Inspect valid gang WAL via CLI
                buf_wal = io.StringIO()
                with redirect_stdout(buf_wal):
                    rc_wal = cli_main(["wal-inspect", str(gang_wal), "--json"])
                self.assertEqual(rc_wal, 0)
                wal_rep = json.loads(buf_wal.getvalue())
                self.assertTrue(wal_rep["valid"])
                self.assertTrue(wal_rep["has_committed_decision"])
                self.assertEqual(wal_rep["expected_member_ids"], ["gang-cli-01-m1", "gang-cli-01-m2"])

                # Remove one member WAL -> inspect_journal_file flags missing member WAL non-destructively
                m1_wal.unlink()
                rep_missing = inspect_journal_file(gang_wal)
                self.assertFalse(rep_missing.valid)
                self.assertEqual(len(rep_missing.missing_member_wals), 1)
            finally:
                for s in (srv_a1, srv_b1, srv_a2, srv_b2):
                    s.shutdown()

    def test_12_envelope_hostname_bind_mounts_and_workload_pid_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mgr = EnvelopeManager(
                cgroup_root=str(Path(tmp) / "cg"),
                state_dir=str(Path(tmp) / "state"),
            )
            env_cfg = EnvelopeConfig(
                workload_id="svc-alpha",
                command=["/usr/bin/python3", "app.py"],
                hostname="alpha-node",
                bind_mounts=["/host/data:/mnt/data", "/host/my dir:/mnt/my dir"],
                ip_address="10.50.0.2/24",
            )
            unshare_cmd = mgr.build_unshare_command(env_cfg)
            shell_script = unshare_cmd[-1]
            self.assertIn("hostname alpha-node", shell_script)
            self.assertIn("mount --bind /host/data /mnt/data", shell_script)
            self.assertIn("mount --bind '/host/my dir' '/mnt/my dir'", shell_script)

            # Persist synthetic envelope metadata and test list_envelopes + CLI auto-PID lookup
            state_path = Path(tmp) / "state" / "svc-alpha.json"
            state_path.parent.mkdir(parents=True, exist_ok=True)
            state_path.write_text(
                json.dumps(
                    {
                        "workload_id": "svc-alpha",
                        "host_pid": 7788,
                        "ip_address": "10.50.0.2/24",
                        "net_interface": "veth0",
                    }
                ),
                encoding="utf-8",
            )
            listed = mgr.list_envelopes()
            self.assertEqual(len(listed), 1)
            self.assertEqual(listed[0]["host_pid"], 7788)

            parser = build_parser()
            args = parser.parse_args(
                [
                    "migrate",
                    "--workload-id",
                    "svc-alpha",
                    "--source",
                    "10.0.0.1:9700",
                    "--dest",
                    "10.0.0.2:9700",
                    "--ip-mobility",
                    "garp",
                    "--no-tls",
                ]
            )
            with mock.patch("lkmp.cli.EnvelopeManager", return_value=mgr):
                resolved_cfg = _build_migration_config(args)
            self.assertEqual(resolved_cfg.pid, 7788)
            self.assertEqual(resolved_cfg.workload_ip, "10.50.0.2/24")
            self.assertEqual(resolved_cfg.net_interface, "veth0")
            self.assertEqual(resolved_cfg.ip_mobility, IpMobilityMode.GARP)

    def test_13_convergence_observed_bandwidth_and_idempotent_rpc_retry(self) -> None:
        tracker = PreCopyConvergenceTracker(bandwidth_mbps=1000.0, target_downtime_ms=200)
        dec = tracker.evaluate(iteration=1, dirty_bytes=50 * 1024 * 1024, duration_ms=400.0)
        self.assertIsNotNone(dec.observed_bandwidth_mbps)
        assert dec.observed_bandwidth_mbps is not None
        self.assertGreater(dec.observed_bandwidth_mbps, 900.0)

        # Verify AgentClient retries transient ConnectionResetError ONLY on idempotent read methods
        call_count = [0]

        def flaky_once(self_cli: AgentClient, method: str, req_bytes: bytes, params: Dict[str, Any]) -> Any:
            call_count[0] += 1
            if call_count[0] == 1:
                raise ConnectionResetError("transient reset")
            return {"status": "ok"}

        cli = AgentClient("10.0.0.1:9700", tls=TlsConfig(enabled=False), max_retries=2)
        with mock.patch.object(AgentClient, "_call_once", flaky_once):
            res = cli.call("health_check")
            self.assertEqual(res["status"], "ok")
            self.assertEqual(call_count[0], 2)

            # Non-idempotent mutating method must NOT auto-retry after partial socket write/read
            call_count[0] = 0
            with self.assertRaises(ConnectionResetError):
                cli.call("freeze_and_final_dump", migration_id="m1")
            self.assertEqual(call_count[0], 1)


if __name__ == "__main__":
    unittest.main()
