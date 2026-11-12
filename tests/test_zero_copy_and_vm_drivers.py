"""Unit tests for v0.3.0 Real-Time Zero-Copy Hot Path, Clean Logging, and VM/Container Drivers."""

from __future__ import annotations

import io
import json
import os
import socket
import subprocess
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from lkmp.agent import AgentClient, AgentServer, AgentService, config_to_dict
from lkmp.cli import main as cli_main
from lkmp.config import EnvelopeConfig, MigrationConfig, MigrationStrategy, TlsConfig
from lkmp.drivers import (
    MicroVmDriver,
    OciContainerDriver,
    QemuQmpDriver,
    QmpClient,
    WorkloadKind,
    build_migratable_qemu_command,
    build_standby_qemu_cmdline,
    detect_workload_profile,
    diagnose_workload_porting,
)
from lkmp.drivers.microvm import unix_http_request
from lkmp.envelope import EnvelopeManager
from lkmp.fs_sync import FilesystemSyncManager, native_reflink_or_copy_file
from lkmp.gang import GangMigrationCoordinator
from lkmp.logging_utils import JsonLogFormatter, configure_logging, get_logger, migration_log_context
from lkmp.models import HostCapabilities
from lkmp.network import NetworkMobilityManager, build_gratuitous_arp_frame
from lkmp.orchestrator import MigrationOrchestrator
from lkmp.realtime import apply_realtime_agent_tuning, read_timens_offsets, resolve_tmpfs_work_dir


def _make_fake_proc(
    proc_root: Path,
    pid: int,
    *,
    comm: str = "worker",
    cmdline: Optional[List[str]] = None,
    exe_target: Optional[str] = None,
    cgroup: str = "0::/user.slice/app.service\n",
    mountinfo: str = "",
    fds: Optional[Dict[str, str]] = None,
    unix_net: str = "",
    starttime: int = 123456,
    state_char: str = "S",
) -> Path:
    """Populate a realistic synthetic `/proc/<pid>` tree for cross-platform unit testing."""
    pdir = proc_root / str(pid)
    (pdir / "fd").mkdir(parents=True, exist_ok=True)
    (pdir / "net").mkdir(parents=True, exist_ok=True)
    (pdir / "comm").write_text(f"{comm}\n", encoding="utf-8")
    argv = cmdline if cmdline is not None else [f"/usr/bin/{comm}"]
    (pdir / "cmdline").write_bytes(b"\x00".join(a.encode("utf-8") for a in argv) + b"\x00")
    (pdir / "cgroup").write_text(cgroup, encoding="utf-8")
    (pdir / "stat").write_text(
        f"{pid} ({comm}) {state_char} 1 {pid} {pid} 0 -1 4194304 "
        + "0 " * 10
        + f"1 0 {starttime} 4096000 1000\n",
        encoding="utf-8",
    )
    (pdir / "status").write_text(
        f"Name:\t{comm}\nState:\t{state_char}\nPid:\t{pid}\nVmRSS:\t16384 kB\n",
        encoding="utf-8",
    )
    if exe_target:
        try:
            (pdir / "exe").symlink_to(exe_target)
        except OSError:
            pass
    if mountinfo:
        (pdir / "mountinfo").write_text(mountinfo, encoding="utf-8")
    if unix_net:
        (pdir / "net" / "unix").write_text(unix_net, encoding="utf-8")
    if fds:
        for fd_num, target in fds.items():
            try:
                (pdir / "fd" / fd_num).symlink_to(target)
            except OSError:
                pass
    return pdir


class TestStructuredLoggingAndRealtime(unittest.TestCase):
    """Phase 1 & 2: ContextVar structured JSON logging and real-time OS tuning helpers."""

    def test_json_log_formatter_injects_context_vars(self) -> None:
        buf = io.StringIO()
        configure_logging(level="INFO", json_logs=True, stream=buf)
        try:
            log = get_logger("orchestrator")
            with migration_log_context(
                migration_id="mig-ctx-01",
                gang_id="gang-99",
                pid=4242,
                driver="qemu",
            ):
                log.info("switchover completed")

            lines = [ln for ln in buf.getvalue().splitlines() if ln.strip()]
            self.assertEqual(len(lines), 1)
            rec = json.loads(lines[0])
            self.assertEqual(rec["level"], "INFO")
            self.assertEqual(rec["logger"], "lkmp.orchestrator")
            self.assertEqual(rec["msg"], "switchover completed")
            self.assertEqual(rec["migration_id"], "mig-ctx-01")
            self.assertEqual(rec["gang_id"], "gang-99")
            self.assertEqual(rec["target_pid"], 4242)
            self.assertEqual(rec["driver"], "qemu")
            self.assertIsInstance(JsonLogFormatter(), JsonLogFormatter)
        finally:
            configure_logging(level="WARNING", json_logs=False)

    def test_realtime_tuning_and_timens_offsets(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp) / "proc"
            pdir = _make_fake_proc(proc_root, 777)
            (pdir / "timens_offsets").write_text(
                "monotonic        42         500000000\nboottime        120                 0\n",
                encoding="utf-8",
            )
            offsets = read_timens_offsets(777, proc_root=str(proc_root))
            self.assertEqual(len(offsets), 2)
            self.assertEqual(offsets[0].clock_id, "monotonic")
            self.assertEqual(offsets[0].offset_sec, 42)
            self.assertEqual(offsets[0].offset_nsec, 500_000_000)
            self.assertEqual(offsets[1].clock_id, "boottime")
            self.assertEqual(offsets[1].offset_sec, 120)

            # Graceful non-fatal execution when unprivileged or on macOS/Linux
            status = apply_realtime_agent_tuning(rt_priority=10, lock_memory=True, cpu_affinity=[0])
            self.assertIsInstance(status.to_dict(), dict)

            resolved, used_tmpfs = resolve_tmpfs_work_dir(Path(tmp) / "work", prefer_tmpfs=False)
            self.assertFalse(used_tmpfs)
            self.assertEqual(resolved, Path(tmp) / "work")


class TestZeroCopyHotPathPrimitives(unittest.TestCase):
    """Phase 2: Raw AF_PACKET GARP, native FICLONE/copy_file_range, keep-alive RPC, in-band transfer."""

    def test_build_gratuitous_arp_frame_rfc5227_layout(self) -> None:
        frame = build_gratuitous_arp_frame(bytes.fromhex("0242ac100009"), "172.16.0.9")
        self.assertEqual(len(frame), 42)
        # Destination MAC: broadcast ff:ff:ff:ff:ff:ff
        self.assertEqual(frame[0:6], b"\xff\xff\xff\xff\xff\xff")
        # Source MAC: 02:42:ac:10:00:09
        self.assertEqual(frame[6:12], bytes.fromhex("0242ac100009"))
        # EtherType: ARP 0x0806
        self.assertEqual(frame[12:14], b"\x08\x06")
        # ARP Request opcode = 0x0001
        self.assertEqual(frame[20:22], b"\x00\x01")
        # Sender IP == Target IP == 172.16.0.9
        ip_bytes = socket.inet_aton("172.16.0.9")
        self.assertEqual(frame[28:32], ip_bytes)
        self.assertEqual(frame[38:42], ip_bytes)

    def test_native_reflink_or_copy_file_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "pages-1.img"
            dst = Path(tmp) / "dest" / "pages-1.img"
            payload = os.urandom(128 * 1024)
            src.write_bytes(payload)
            method = native_reflink_or_copy_file(src, dst)
            self.assertIn(method, ("ficlone", "clonefile", "copy_file_range", "copy2"))
            self.assertEqual(dst.read_bytes(), payload)

    def test_persistent_keepalive_rpc_reuses_single_socket_and_reconnects(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            svc = AgentService(work_dir=str(Path(tmp) / "agent"))
            srv = AgentServer("127.0.0.1", 0, service=svc, tls=TlsConfig(enabled=False))
            srv.start_background()
            try:
                addr = f"127.0.0.1:{srv.bound_address[1]}"
                with AgentClient(addr, tls=TlsConfig(enabled=False)) as client:
                    for _i in range(10):
                        hc = client.call("health_check")
                        self.assertEqual(hc["status"], "ok")
                    # All 10 sequential RPCs reused the exact same persistent TCP connection!
                    self.assertEqual(client.connections_opened, 1)

                    # Simulate OS-level peer socket disconnect and prove transparent automatic reconnect
                    assert client._sock is not None
                    client._sock.shutdown(socket.SHUT_RDWR)
                    hc_after = client.call("health_check")
                    self.assertEqual(hc_after["status"], "ok")
                    self.assertEqual(client.connections_opened, 2)
            finally:
                srv.shutdown()

    def test_zero_fork_inband_metadata_transfer_over_rpc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work_a = Path(tmp) / "work_a"
            work_b = Path(tmp) / "work_b"
            svc_a = AgentService(work_dir=str(work_a))
            svc_b = AgentService(work_dir=str(work_b))
            mig_a = Path(svc_a.prepare_migration("mig-inband")["migration_dir"])
            svc_b.prepare_migration("mig-inband")

            (mig_a / "final" / "core-1.img").write_bytes(b"CORE_PROTOBUF_BYTES")
            (mig_a / "final" / "inventory.img").write_bytes(b"INVENTORY_BYTES")

            cfg = MigrationConfig(
                pid=4242,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                same_host_cow=False,
                attestation_key_hex="aa" * 32,
            )
            bundle = svc_a.export_inband_metadata("mig-inband", "10.0.0.2", config_to_dict(cfg))
            self.assertTrue(bundle["eligible"])
            self.assertEqual(len(bundle["files_b64"]), 3)  # core-1.img + inventory.img + manifest.sig.json

            up = svc_b.upload_checkpoint_files("mig-inband", "final", bundle["files_b64"])
            self.assertEqual(up["uploaded_files"], 3)
            mig_b = work_b / "mig-inband" / "final"
            self.assertEqual((mig_b / "core-1.img").read_bytes(), b"CORE_PROTOBUF_BYTES")
            self.assertEqual((mig_b / "inventory.img").read_bytes(), b"INVENTORY_BYTES")
            self.assertTrue((mig_b / "manifest.sig.json").exists())


class TestWorkloadFingerprinterAndDoctor(unittest.TestCase):
    """Phase 3: Automatic VM/MicroVM/OCI process-tree fingerprinter and `lkmp doctor`."""

    def test_detect_qemu_kvm_memfd_migratable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp) / "proc"
            _make_fake_proc(
                proc_root,
                1001,
                comm="qemu-system-x86",
                exe_target="/usr/bin/qemu-system-x86_64",
                cmdline=[
                    "/usr/bin/qemu-system-x86_64",
                    "-accel",
                    "kvm",
                    "-cpu",
                    "Cascadelake-Server",
                    "-m",
                    "2048M",
                    "-object",
                    "memory-backend-memfd,id=mem0,size=2048M,share=on",
                    "-qmp",
                    "unix:/run/qemu/vm1.qmp,server=on,wait=off",
                    "-drive",
                    "file=/mnt/shared/vm1.qcow2,if=virtio,format=qcow2",
                ],
                fds={
                    "3": "/dev/kvm",
                    "4": "/dev/vhost-net",
                    "5": "socket:[9911]",
                },
            )
            prof = detect_workload_profile(1001, proc_root=str(proc_root))
            self.assertEqual(prof.kind, WorkloadKind.QEMU_VM)
            self.assertEqual(prof.subkind, "qemu-kvm")
            self.assertTrue(prof.uses_kvm)
            self.assertTrue(prof.uses_vhost)
            self.assertEqual(prof.control_socket, "/run/qemu/vm1.qmp")
            self.assertEqual(prof.memory_backend, "memfd-shared")
            self.assertEqual(prof.cpu_model, "Cascadelake-Server")
            self.assertEqual(prof.disk_paths, ["/mnt/shared/vm1.qcow2"])
            self.assertTrue(prof.migratable_ready)

            diag = diagnose_workload_porting(1001, proc_root=str(proc_root))
            self.assertTrue(diag["zero_copy_capable"])
            self.assertEqual(diag["driver_key"], "qemu")

    def test_detect_qemu_blockers_without_qmp_or_with_vfio(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp) / "proc"
            _make_fake_proc(
                proc_root,
                1002,
                comm="qemu-system-x86",
                cmdline=["qemu-system-x86_64", "-cpu", "host", "-m", "512M"],
                fds={"7": "/dev/vfio/12"},
            )
            prof = detect_workload_profile(1002, proc_root=str(proc_root))
            self.assertEqual(prof.kind, WorkloadKind.QEMU_VM)
            self.assertFalse(prof.migratable_ready)
            self.assertTrue(prof.uses_vfio)
            self.assertEqual(len(prof.blockers), 2)  # missing QMP + active VFIO

    def test_detect_podman_oci_container_and_overlayfs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp) / "proc"
            cid = "a1b2c3d4e5f60718293a4b5c6d7e8f9011223344556677889900aabbccddeeff"
            mountinfo = (
                "412 390 0:55 / / rw,relatime - overlay overlay "
                "rw,lowerdir=/var/lib/containers/l/base,upperdir=/var/lib/containers/diff,workdir=/var/lib/containers/work\n"
            )
            _make_fake_proc(
                proc_root,
                2001,
                comm="redis-server",
                cmdline=["/usr/local/bin/redis-server", "*:6379"],
                cgroup=f"0::/machine.slice/libpod-{cid}.scope/container\n",
                mountinfo=mountinfo,
            )
            prof = detect_workload_profile(2001, proc_root=str(proc_root))
            self.assertEqual(prof.kind, WorkloadKind.OCI_CONTAINER)
            self.assertEqual(prof.container_engine, "podman")
            self.assertEqual(prof.container_id, cid)
            self.assertEqual(prof.overlay_upperdir, "/var/lib/containers/diff")
            self.assertEqual(prof.overlay_lowerdir, "/var/lib/containers/l/base")
            self.assertTrue(prof.migratable_ready)

    def test_detect_firecracker_microvm(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp) / "proc"
            _make_fake_proc(
                proc_root,
                3001,
                comm="firecracker",
                exe_target="/usr/local/bin/firecracker",
                cmdline=["/usr/local/bin/firecracker", "--api-sock", "/run/fc/vm42.sock"],
                fds={"3": "/dev/kvm"},
            )
            prof = detect_workload_profile(3001, proc_root=str(proc_root))
            self.assertEqual(prof.kind, WorkloadKind.MICROVM)
            self.assertEqual(prof.subkind, "firecracker")
            self.assertEqual(prof.control_socket, "/run/fc/vm42.sock")
            self.assertTrue(prof.migratable_ready)


class TestQmpClientAndQemu2PCDriver(unittest.TestCase):
    """Phase 3: QMP protocol client, standby argv builder, and QEMU 2PC Commit & Rollback."""

    def test_qmp_client_handles_greeting_and_skips_async_events(self) -> None:
        sock_path = f"/tmp/lkmp-qmp-ut-{uuid.uuid4().hex[:8]}.sock"
        ready = threading.Event()

        def fake_qemu_server() -> None:
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(sock_path)
            srv.listen(1)
            ready.set()
            conn, _ = srv.accept()
            with conn:
                rfile = conn.makefile("rb")
                conn.sendall(b'{"QMP": {"version": {"qemu": {"major": 8, "minor": 2}}}}\n')
                # Command 1: qmp_capabilities
                cmd1 = json.loads(rfile.readline().decode("utf-8"))
                assert cmd1["execute"] == "qmp_capabilities"
                conn.sendall(b'{"return": {}}\n')
                # Command 2: query-status -> emit interleaved async event BEFORE return!
                cmd2 = json.loads(rfile.readline().decode("utf-8"))
                assert cmd2["execute"] == "query-status"
                conn.sendall(b'{"timestamp": {"seconds": 1}, "event": "MIGRATION", "data": {"status": "active"}}\n')
                conn.sendall(b'{"return": {"running": false, "status": "prelaunch"}}\n')
            srv.close()

        t = threading.Thread(target=fake_qemu_server, daemon=True)
        t.start()
        ready.wait(timeout=3.0)
        try:
            with QmpClient(f"unix:{sock_path}") as qmp:
                st = qmp.execute("query-status")
                self.assertEqual(st, {"running": False, "status": "prelaunch"})
        finally:
            t.join(timeout=3.0)
            if os.path.exists(sock_path):
                os.unlink(sock_path)

    def test_build_standby_and_migratable_qemu_commands(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src_cmd, src_qmp = build_migratable_qemu_command(
                workload_id="vm-prod-01",
                qmp_sock_dir=tmp,
                memory_mb=1024,
                vcpus=4,
            )
            self.assertIn("memory-backend-memfd,id=mem0,size=1024M,share=on", src_cmd)
            self.assertTrue(src_qmp.endswith("vm-prod-01.qmp"))

            standby = build_standby_qemu_cmdline(
                src_cmd + ["-daemonize", "-pidfile", "/tmp/old.pid"],
                dest_qmp_sock="/tmp/dest.qmp",
                dest_pidfile="/tmp/dest.pid",
            )
            self.assertIn("-S", standby)
            self.assertIn("-incoming", standby)
            self.assertIn("defer", standby)
            self.assertNotIn(f"unix:{src_qmp},server=on,wait=off", standby)
            self.assertIn("unix:/tmp/dest.qmp,server=on,wait=off", standby)

            mgr = EnvelopeManager(state_dir=str(Path(tmp) / "envelopes"))
            envelope_cmd = mgr.build_launch_command(
                EnvelopeConfig(
                    workload_id="vm-env",
                    command=["--serial", "stdio"],
                    profile="qemu",
                )
            )
            self.assertEqual(envelope_cmd[0], "qemu-system-x86_64")
            self.assertIn("--serial", envelope_cmd)

    def test_qemu_driver_2pc_orchestrator_commit_and_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc_a = root / "proc_a"
            proc_b = root / "proc_b"
            src_cmd = [
                "/usr/bin/qemu-system-x86_64",
                "-accel",
                "kvm",
                "-m",
                "512M",
                "-object",
                "memory-backend-memfd,id=mem0,size=512M,share=on",
                "-qmp",
                "unix:/tmp/src-vm.qmp,server=on,wait=off",
            ]
            _make_fake_proc(
                proc_a,
                5001,
                comm="qemu-system-x86",
                exe_target="/usr/bin/qemu-system-x86_64",
                cmdline=src_cmd,
                fds={"3": "/dev/kvm"},
                starttime=70001,
            )
            _make_fake_proc(
                proc_b,
                6001,
                comm="qemu-system-x86",
                exe_target="/usr/bin/qemu-system-x86_64",
                cmdline=src_cmd,
                starttime=80001,
            )

            qmp_log: List[Tuple[str, str]] = []
            vm_state = {
                "src_mig_polls": 0,
                "continued": False,
                "src_status": "running",
                "dst_status": "inmigrate",
                "dst_running": False,
            }
            created_socks: List[Path] = []

            def fake_spawn(cmd: List[str]) -> subprocess.CompletedProcess:
                pidx = cmd.index("-pidfile")
                Path(cmd[pidx + 1]).write_text("6001\n", encoding="utf-8")
                qidx = cmd.index("-qmp")
                qspec = cmd[qidx + 1]
                spath = Path(qspec.split("unix:", 1)[1].split(",", 1)[0])
                spath.write_text("", encoding="utf-8")
                created_socks.append(spath)
                return subprocess.CompletedProcess(cmd, 0, "", "")

            def fake_qmp(ep: str, command: str, args: Optional[Dict[str, Any]] = None) -> Any:
                _ = args
                qmp_log.append((ep, command))
                is_src = "src-vm.qmp" in ep
                if command == "query-migrate-capabilities":
                    return [
                        {"capability": "pause-before-switchover", "state": False},
                        {"capability": "late-block-activate", "state": False},
                        {"capability": "auto-converge", "state": False},
                        {"capability": "multifd", "state": False},
                        {"capability": "zero-copy-send", "state": False},
                    ]
                if command in ("migrate-set-capabilities", "migrate-set-parameters", "migrate-incoming", "migrate"):
                    return {}
                if command == "query-migrate":
                    vm_state["src_mig_polls"] += 1
                    if vm_state["continued"]:
                        return {"status": "completed", "downtime": 6, "ram": {"remaining": 0}}
                    if vm_state["src_mig_polls"] <= 2:
                        return {"status": "active", "ram": {"remaining": 4096}}
                    return {"status": "pre-switchover", "ram": {"remaining": 0}}
                if command == "migrate-continue":
                    vm_state["continued"] = True
                    vm_state["src_status"] = "postmigrate"
                    vm_state["dst_status"] = "paused"
                    vm_state["dst_running"] = False
                    return {}
                if command == "query-status":
                    if is_src:
                        return {"running": vm_state["src_status"] == "running", "status": vm_state["src_status"]}
                    return {"running": vm_state["dst_running"], "status": vm_state["dst_status"]}
                if command == "cont":
                    if is_src:
                        vm_state["src_status"] = "running"
                    else:
                        vm_state["dst_status"] = "running"
                        vm_state["dst_running"] = True
                    return {}
                if command == "quit":
                    if is_src:
                        vm_state["src_status"] = "shutdown"
                    else:
                        vm_state["dst_status"] = "shutdown"
                    return {}
                return {}

            caps = HostCapabilities(
                arch="x86_64",
                kernel_release="6.8.0",
                cpu_vendor="GenuineIntel",
                cpu_flags={"avx2"},
                has_soft_dirty=True,
                criu_available=True,
                qemu_available=True,
            )
            noop_runner = lambda cmd: subprocess.CompletedProcess(cmd, 0, "", "")  # noqa: E731

            try:
                drv_a = QemuQmpDriver(proc_root=str(proc_a), qmp_caller=fake_qmp, spawner=fake_spawn)
                drv_b = QemuQmpDriver(proc_root=str(proc_b), qmp_caller=fake_qmp, spawner=fake_spawn)
                svc_a = AgentService(
                    work_dir=str(root / "work_a"),
                    proc_root=str(proc_a),
                    qemu_driver=drv_a,
                    net_manager=NetworkMobilityManager(runner=noop_runner),
                    fs_manager=FilesystemSyncManager(runner=noop_runner),
                    capabilities_override=caps,
                    pid_alive_checker=lambda _p: True,
                )
                svc_b = AgentService(
                    work_dir=str(root / "work_b"),
                    proc_root=str(proc_b),
                    qemu_driver=drv_b,
                    net_manager=NetworkMobilityManager(runner=noop_runner),
                    fs_manager=FilesystemSyncManager(runner=noop_runner),
                    capabilities_override=caps,
                    pid_alive_checker=lambda _p: True,
                )

                # 1. Full 2PC QEMU Commit (explicit plaintext when tls.enabled=False)
                cfg = MigrationConfig(
                    pid=5001,
                    source_addr="10.0.0.1:9440",
                    dest_addr="10.0.0.2:9440",
                    strategy=MigrationStrategy.PRE_COPY,
                    unsafe_bare=True,
                    journal_dir=str(root / "journals"),
                    tls=TlsConfig(enabled=False),
                )
                orch = MigrationOrchestrator(
                    cfg,
                    AgentClient("10.0.0.1:9440", direct_service=svc_a),
                    AgentClient("10.0.0.2:9440", direct_service=svc_b),
                    migration_id="mig-qemu-commit",
                )
                res = orch.execute()
                self.assertTrue(res.success, msg=f"QEMU migration failed: {res.error_message}")
                self.assertEqual(res.restored_pid, 6001)
                self.assertTrue(vm_state["dst_running"])
                self.assertEqual(vm_state["src_status"], "shutdown")
                self.assertIn(("/tmp/src-vm.qmp", "migrate-continue"), qmp_log)

                # 2. Full 2PC QEMU Atomic Rollback (inject failure on destination post-restore health check)
                vm_state.update(
                    {
                        "src_mig_polls": 0,
                        "continued": False,
                        "src_status": "running",
                        "dst_status": "inmigrate",
                        "dst_running": False,
                    }
                )
                cfg_rb = MigrationConfig(
                    pid=5001,
                    source_addr="10.0.0.1:9440",
                    dest_addr="10.0.0.2:9440",
                    strategy=MigrationStrategy.PRE_COPY,
                    unsafe_bare=True,
                    journal_dir=str(root / "journals"),
                    health_check_cmd="false",
                    tls=TlsConfig(enabled=False),
                )
                svc_b_fail = AgentService(
                    work_dir=str(root / "work_b2"),
                    proc_root=str(proc_b),
                    qemu_driver=drv_b,
                    net_manager=NetworkMobilityManager(runner=noop_runner),
                    fs_manager=FilesystemSyncManager(runner=noop_runner),
                    capabilities_override=caps,
                    pid_alive_checker=lambda _p: True,
                )
                orch_rb = MigrationOrchestrator(
                    cfg_rb,
                    AgentClient("10.0.0.1:9440", direct_service=svc_a),
                    AgentClient("10.0.0.2:9440", direct_service=svc_b_fail),
                    migration_id="mig-qemu-rollback",
                )
                res_rb = orch_rb.execute()
                self.assertFalse(res_rb.success)
                self.assertTrue(res_rb.rolled_back)
                # Source QEMU VM resumed (`cont`) and running with zero guest state loss!
                self.assertEqual(vm_state["src_status"], "running")
            finally:
                for sp in created_socks:
                    if sp.exists():
                        sp.unlink()


class TestOciAndMicroVm2PCDrivers(unittest.TestCase):
    """Phase 3: OCI Container (`podman` restart fencing + 2PC) and MicroVM (`firecracker` 2PC)."""

    def test_oci_driver_fences_restart_policy_and_restores_on_rollback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc_a = root / "proc_a"
            proc_b = root / "proc_b"
            cid = "deadbeefcafe00112233445566778899aabbccddeeff00112233445566778899"
            _make_fake_proc(
                proc_a,
                7100,
                comm="nginx",
                cgroup=f"0::/machine.slice/libpod-{cid}.scope/container\n",
            )
            _make_fake_proc(proc_b, 8100, comm="nginx")

            cmds: List[List[str]] = []
            container_paused = {"paused": False}

            def fake_oci_runner(cmd: List[str]) -> subprocess.CompletedProcess:
                cmds.append(list(cmd))
                if cmd[:2] == ["podman", "inspect"]:
                    payload = [
                        {
                            "HostConfig": {"RestartPolicy": {"Name": "always"}},
                            "State": {
                                "Pid": 8100,
                                "Paused": container_paused["paused"],
                                "Status": "paused" if container_paused["paused"] else "running",
                            },
                        }
                    ]
                    return subprocess.CompletedProcess(cmd, 0, json.dumps(payload), "")
                if "--export" in cmd:
                    exp_idx = cmd.index("--export")
                    Path(cmd[exp_idx + 1]).write_bytes(b"OCI_CKPT_TAR")
                if cmd[:2] == ["podman", "pause"]:
                    container_paused["paused"] = True
                if cmd[:2] == ["podman", "unpause"]:
                    container_paused["paused"] = False
                return subprocess.CompletedProcess(cmd, 0, "", "")

            caps = HostCapabilities(
                arch="x86_64",
                kernel_release="6.8.0",
                cpu_vendor="GenuineIntel",
                cpu_flags={"avx2"},
                has_soft_dirty=True,
                criu_available=True,
                podman_available=True,
            )
            noop_runner = lambda cmd: subprocess.CompletedProcess(cmd, 0, "", "")  # noqa: E731
            oci_a = OciContainerDriver(proc_root=str(proc_a), runner=fake_oci_runner)
            oci_b = OciContainerDriver(proc_root=str(proc_b), runner=fake_oci_runner)

            svc_a = AgentService(
                work_dir=str(root / "work_a"),
                proc_root=str(proc_a),
                oci_driver=oci_a,
                net_manager=NetworkMobilityManager(runner=noop_runner),
                capabilities_override=caps,
                pid_alive_checker=lambda _p: True,
            )
            svc_b = AgentService(
                work_dir=str(root / "work_b"),
                proc_root=str(proc_b),
                oci_driver=oci_b,
                net_manager=NetworkMobilityManager(runner=noop_runner),
                capabilities_override=caps,
                pid_alive_checker=lambda _p: True,
            )

            cfg = MigrationConfig(
                pid=7100,
                source_addr="10.0.0.1:9440",
                dest_addr="10.0.0.2:9440",
                strategy=MigrationStrategy.PRE_COPY,
                unsafe_bare=True,
                journal_dir=str(root / "journals"),
            )
            orch = MigrationOrchestrator(
                cfg,
                AgentClient("10.0.0.1:9440", direct_service=svc_a),
                AgentClient("10.0.0.2:9440", direct_service=svc_b),
                migration_id="mig-oci-commit",
            )
            res = orch.execute()
            self.assertTrue(res.success, msg=f"OCI commit failed: {res.error_message}")
            self.assertEqual(res.restored_pid, 8100)
            # Proves split-brain restart policy was fenced BEFORE checkpointing!
            self.assertIn(["podman", "update", "--restart=no", cid], cmds)
            self.assertIn(["podman", "unpause", cid], cmds)
            self.assertIn(["podman", "rm", "-f", cid], cmds)

            # Verify rollback restores original `--restart=always` policy!
            cmds.clear()
            mig_rb = root / "work_a" / "mig-oci-rb"
            mig_rb.mkdir(parents=True, exist_ok=True)
            oci_a.freeze_and_dump_source("mig-oci-rb", mig_rb, None, "10.0.0.2", cfg)
            oci_a.rollback_source("mig-oci-rb", mig_rb, "10.0.0.1", cfg)
            self.assertIn(["podman", "update", "--restart=always", cid], cmds)

    def test_firecracker_microvm_unix_http_and_2pc_driver(self) -> None:
        # 1. Verify real UNIX HTTP/1.1 client against AF_UNIX server
        sock_path = f"/tmp/lkmp-fc-ut-{uuid.uuid4().hex[:8]}.sock"
        ready = threading.Event()

        def fake_fc_http() -> None:
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            srv.bind(sock_path)
            srv.listen(1)
            ready.set()
            conn, _ = srv.accept()
            with conn:
                data = conn.recv(4096).decode("utf-8")
                assert "PATCH /vm HTTP/1.1" in data
                conn.sendall(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            srv.close()

        t = threading.Thread(target=fake_fc_http, daemon=True)
        t.start()
        ready.wait(timeout=3.0)
        try:
            code, _body = unix_http_request(sock_path, "PATCH", "/vm", {"state": "Paused"})
            self.assertEqual(code, 204)
        finally:
            t.join(timeout=3.0)
            if os.path.exists(sock_path):
                os.unlink(sock_path)

        # 2. Verify Firecracker 2PC Orchestrator flow (`resume_vm: False` -> `Resumed` on commit)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc_a = root / "proc_a"
            proc_b = root / "proc_b"
            _make_fake_proc(
                proc_a,
                9100,
                comm="firecracker",
                cmdline=["/usr/bin/firecracker", "--api-sock", "/run/fc/src.sock"],
                fds={"3": "/dev/kvm"},
            )
            _make_fake_proc(proc_b, 9200, comm="firecracker")

            http_calls: List[Tuple[str, str, str, Optional[Dict[str, Any]]]] = []

            def fake_http(
                sock: str,
                method: str,
                path: str,
                body: Optional[Dict[str, Any]] = None,
            ) -> Tuple[int, str]:
                http_calls.append((sock, method, path, body))
                if path == "/snapshot/create" and body:
                    Path(body["snapshot_path"]).write_bytes(b"FC_VMSTATE")
                    Path(body["mem_file_path"]).write_bytes(b"FC_MEM")
                return 204, ""

            caps = HostCapabilities(
                arch="x86_64",
                kernel_release="6.8.0",
                cpu_vendor="GenuineIntel",
                cpu_flags={"avx2"},
                has_soft_dirty=True,
                criu_available=True,
            )
            noop_runner = lambda cmd: subprocess.CompletedProcess(cmd, 0, "", "")  # noqa: E731
            mvm_a = MicroVmDriver(proc_root=str(proc_a), http_caller=fake_http)
            mvm_b = MicroVmDriver(proc_root=str(proc_b), http_caller=fake_http)

            svc_a = AgentService(
                work_dir=str(root / "work_a"),
                proc_root=str(proc_a),
                microvm_driver=mvm_a,
                net_manager=NetworkMobilityManager(runner=noop_runner),
                capabilities_override=caps,
                pid_alive_checker=lambda _p: True,
            )
            svc_b = AgentService(
                work_dir=str(root / "work_b"),
                proc_root=str(proc_b),
                microvm_driver=mvm_b,
                net_manager=NetworkMobilityManager(runner=noop_runner),
                capabilities_override=caps,
                pid_alive_checker=lambda _p: True,
            )

            cfg = MigrationConfig(
                pid=9100,
                source_addr="10.0.0.1:9440",
                dest_addr="10.0.0.2:9440",
                strategy=MigrationStrategy.PRE_COPY,
                unsafe_bare=True,
                journal_dir=str(root / "journals"),
                runtime_metadata={
                    "subkind": "firecracker",
                    "control_socket": "/run/fc/src.sock",
                    "dest_control_socket": "/run/fc/dst.sock",
                    "standby_pid": 9200,
                },
            )
            orch = MigrationOrchestrator(
                cfg,
                AgentClient("10.0.0.1:9440", direct_service=svc_a),
                AgentClient("10.0.0.2:9440", direct_service=svc_b),
                migration_id="mig-fc-commit",
            )
            res = orch.execute()
            self.assertTrue(res.success, msg=f"Firecracker commit failed: {res.error_message}")
            load_calls = [c for c in http_calls if c[2] == "/snapshot/load"]
            self.assertEqual(len(load_calls), 1)
            # Crucial 2PC invariant: loaded paused (`resume_vm: False`), then resumed ONLY on commit!
            self.assertFalse(load_calls[0][3]["resume_vm"])
            self.assertIn(("/run/fc/dst.sock", "PATCH", "/vm", {"state": "Resumed"}), http_calls)


class TestParallel2PCGangAndDoctorCli(unittest.TestCase):
    """Phase 2 & 3: Parallel `ThreadPoolExecutor` 2PC Gang Coordinator + `lkmp doctor` CLI."""

    def test_parallel_gang_2pc_commit(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            proc_a = root / "proc_a"
            proc_b = root / "proc_b"
            for pid in (4101, 4102):
                _make_fake_proc(proc_a, pid, comm="worker", starttime=555)
                _make_fake_proc(proc_b, pid, comm="worker", state_char="T", starttime=555)

            caps = HostCapabilities(
                arch="x86_64",
                kernel_release="6.8.0",
                cpu_vendor="GenuineIntel",
                cpu_flags={"avx2"},
                has_soft_dirty=True,
                criu_available=True,
            )

            def fake_criu_runner(cmd: List[str]) -> subprocess.CompletedProcess:
                if cmd and cmd[0] == "criu" and "dump" in cmd:
                    idx = cmd.index("--images-dir")
                    img_d = Path(cmd[idx + 1])
                    (img_d / "core-1.img").write_bytes(b"CORE")
                if cmd[:3] == ["nft", "list", "table"]:
                    return subprocess.CompletedProcess(cmd, 0, "chain input { policy drop; }\n", "")
                return subprocess.CompletedProcess(cmd, 0, "", "")

            from lkmp.criu_driver import CriuDriver

            svc_a = AgentService(
                work_dir=str(root / "work_a"),
                proc_root=str(proc_a),
                criu_driver=CriuDriver(runner=fake_criu_runner),
                net_manager=NetworkMobilityManager(runner=fake_criu_runner),
                fs_manager=FilesystemSyncManager(runner=fake_criu_runner),
                capabilities_override=caps,
                signal_sender=lambda _p, _s: None,
                pid_alive_checker=lambda _p: True,
            )
            svc_b = AgentService(
                work_dir=str(root / "work_b"),
                proc_root=str(proc_b),
                criu_driver=CriuDriver(runner=fake_criu_runner),
                net_manager=NetworkMobilityManager(runner=fake_criu_runner),
                fs_manager=FilesystemSyncManager(runner=fake_criu_runner),
                capabilities_override=caps,
                signal_sender=lambda _p, _s: None,
                pid_alive_checker=lambda _p: True,
            )

            members = [
                (
                    MigrationConfig(
                        pid=pid,
                        source_addr="10.0.0.1:9440",
                        dest_addr="10.0.0.2:9440",
                        strategy=MigrationStrategy.COLD,
                        tcp_established=False,
                        unsafe_bare=True,
                        attestation_key_hex="bb" * 32,
                        journal_dir=str(root / "journals"),
                    ),
                    AgentClient("10.0.0.1:9440", direct_service=svc_a),
                    AgentClient("10.0.0.2:9440", direct_service=svc_b),
                )
                for pid in (4101, 4102)
            ]
            coord = GangMigrationCoordinator(
                "gang-parallel-ut",
                members,
                journal_dir=str(root / "journals"),
                parallel=True,
            )
            res = coord.execute()
            self.assertTrue(res.all_committed, msg=f"Parallel gang commit failed: {res.error_message}")
            self.assertEqual(len(res.member_results), 2)

    def test_cli_doctor_and_run_profile_qemu_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp) / "proc"
            _make_fake_proc(
                proc_root,
                8888,
                comm="qemu-system-x86",
                exe_target="/usr/bin/qemu-system-x86_64",
                cmdline=[
                    "qemu-system-x86_64",
                    "-object",
                    "memory-backend-memfd,id=m0,size=512M,share=on",
                    "-qmp",
                    "unix:/tmp/vm8888.qmp,server=on,wait=off",
                ],
            )
            svc = AgentService(work_dir=str(Path(tmp) / "agent"), proc_root=str(proc_root))
            srv = AgentServer("127.0.0.1", 0, service=svc, tls=TlsConfig(enabled=False))
            srv.start_background()
            try:
                import contextlib

                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    rc = cli_main(
                        [
                            "doctor",
                            "--pid",
                            "8888",
                            "--agent",
                            f"127.0.0.1:{srv.bound_address[1]}",
                            "--no-tls",
                            "--json",
                        ]
                    )
                self.assertEqual(rc, 0)
                parsed = json.loads(out.getvalue())
                self.assertTrue(parsed["ready"])
                self.assertEqual(parsed["profile"]["kind"], "qemu")

                out_run = io.StringIO()
                with contextlib.redirect_stdout(out_run):
                    rc_run = cli_main(["run", "--profile", "qemu", "--dry-run", "--id", "vm-cli-test"])
                self.assertEqual(rc_run, 0)
                self.assertTrue(out_run.getvalue().strip().startswith("qemu-system-x86_64 "))
                self.assertIn("memory-backend-memfd", out_run.getvalue())
            finally:
                srv.shutdown()

    def test_kvm_anon_inode_maps_do_not_fail_preflight(self) -> None:
        from lkmp.config import FilesystemMode, IpMobilityMode
        from lkmp.models import HostCapabilities
        from lkmp.preflight import evaluate_compatibility, inspect_process_tree

        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp) / "proc"
            pdir = _make_fake_proc(
                proc_root,
                8901,
                comm="qemu-system-x86",
                exe_target="/usr/bin/qemu-system-x86_64",
                cmdline=[
                    "qemu-system-x86_64",
                    "-accel",
                    "kvm",
                    "-object",
                    "memory-backend-memfd,id=m0,size=256M,share=on",
                    "-qmp",
                    "unix:/tmp/kvm8901.qmp,server=on,wait=off",
                ],
                fds={
                    "3": "/dev/kvm",
                    "4": "anon_inode:kvm-vm",
                    "5": "anon_inode:kvm-vcpu:0",
                    "6": "/memfd:m0 (deleted)",
                },
            )
            (pdir / "maps").write_text(
                "7f0000000000-7f0000003000 rw-s 00000000 00:0f 12345 anon_inode:kvm-vcpu:0\n"
                "7f0010000000-7f0020000000 rw-s 00000000 00:01 12346 /memfd:m0 (deleted)\n",
                encoding="utf-8",
            )
            snap = inspect_process_tree(8901, proc_root=str(proc_root))
            self.assertEqual(snap.files, [])
            caps = HostCapabilities(
                arch="x86_64",
                kernel_release="7.0.0",
                cpu_vendor="GenuineIntel",
                cpu_flags={"avx2"},
                criu_available=True,
                work_dir_free_bytes=10 * 1024**3,
            )
            cfg = MigrationConfig(
                pid=8901,
                source_addr="127.0.0.1:9700",
                dest_addr="127.0.0.1:9701",
                fs_mode=FilesystemMode.SHARED,
                ip_mobility=IpMobilityMode.NONE,
            )
            report = evaluate_compatibility(cfg, caps, caps, snap, dest_files={})
            self.assertTrue(report.compatible, msg=f"Unexpected blockers: {report.findings}")


if __name__ == "__main__":
    unittest.main()
