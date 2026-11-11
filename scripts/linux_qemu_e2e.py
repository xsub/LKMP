#!/usr/bin/env python3
"""Linux Real QEMU/KVM-TCG & Heterogeneous [QEMU VM + CRIU Process] 2PC E2E Suite.

Executes end-to-end hypervisor and heterogeneous 2PC gang live migrations on Linux:
1. Scenario 1: Real `qemu-system-x86_64` live QMP 2PC migration (`PRE_COPY`, `memory-backend-memfd,share=on`,
   `pause-before-switchover`, `late-block-activate`, `-S -incoming defer`) over persistent keep-alive mTLS
   between two isolated host namespaces (`Host A -> Host B`) + `lkmp doctor` readiness check.
2. Scenario 2: Multi-hop reverse live migration (`Host B -> Host A`) of the already-migrated QEMU VM,
   proving post-commit QMP control socket preservation and automatic re-fingerprinting.
3. Scenario 3: Heterogeneous 2PC Gang Migration (`[Real QEMU VM + Real Linux CRIU Stateful Process]`)
   under parallel `GangMigrationCoordinator`:
   - Part A: Injected destination fault triggers atomic 2PC rollback across both hypervisor & CRIU process;
     both workloads resume seamlessly on Host A with zero state loss.
   - Part B: Clean parallel 2PC gang commit migrates both workloads atomically onto Host B with continuous
     xorshift64* PRNG sequence integrity and live QMP `status="running"`.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from lkmp.agent import AgentClient  # noqa: E402
from lkmp.config import (  # noqa: E402
    FilesystemMode,
    IpMobilityMode,
    MigrationConfig,
    MigrationStrategy,
    TlsConfig,
)
from lkmp.drivers.qemu_qmp import build_migratable_qemu_command, qmp_call  # noqa: E402
from lkmp.gang import GangMigrationCoordinator  # noqa: E402
from lkmp.orchestrator import MigrationOrchestrator  # noqa: E402

DEFAULT_PRNG_SEED = 0xCAFEBABE12345678


def step_xorshift64star(state: int) -> int:
    x = state & 0xFFFFFFFFFFFFFFFF
    x ^= (x >> 12) & 0xFFFFFFFFFFFFFFFF
    x ^= (x << 25) & 0xFFFFFFFFFFFFFFFF
    x ^= (x >> 27) & 0xFFFFFFFFFFFFFFFF
    return (x * 0x2545F4914F6CDD1D) & 0xFFFFFFFFFFFFFFFF


def run_stateful_criu_worker(work_dir: Path) -> None:
    """Minimal daemonized stateful worker with deterministic xorshift64* counter for CRIU."""
    work_dir.mkdir(parents=True, exist_ok=True)
    if os.fork() > 0:
        os._exit(0)
    os.setsid()
    os.chdir("/")
    devnull = os.open("/dev/null", os.O_RDWR)
    for target_fd in (0, 1, 2):
        try:
            os.dup2(devnull, target_fd)
        except OSError:
            pass
    try:
        os.closerange(3, 1024)
    except OSError:
        pass

    pid = os.getpid()
    (work_dir / "worker.pid").write_text(f"{pid}\n", encoding="utf-8")
    log_path = work_dir / "state.log"
    fd = os.open(str(log_path), os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o644)

    running = True

    def _stop(_sig: int, _frame: Any) -> None:
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    counter = 0
    prng = DEFAULT_PRNG_SEED
    (work_dir / "ready.txt").write_text(f"READY {pid}\n", encoding="utf-8")

    try:
        while running:
            counter += 1
            prng = step_xorshift64star(prng)
            line = f"{counter} {prng:016x} pid={os.getpid()}\n".encode("utf-8")
            os.write(fd, line)
            os.fsync(fd)
            time.sleep(0.05)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        os._exit(0)


def get_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def generate_mtls_pki(pki_dir: Path) -> TlsConfig:
    """Generate ephemeral X.509 CA and localhost mTLS certificate/key pair using `openssl`."""
    pki_dir.mkdir(parents=True, exist_ok=True)
    ca_key = pki_dir / "ca.key"
    ca_crt = pki_dir / "ca.crt"
    node_key = pki_dir / "node.key"
    node_csr = pki_dir / "node.csr"
    node_crt = pki_dir / "node.crt"
    ext_cfg = pki_dir / "ext.cnf"
    ext_cfg.write_text(
        "subjectAltName = IP:127.0.0.1,DNS:localhost\nextendedKeyUsage = serverAuth,clientAuth\n",
        encoding="utf-8",
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(ca_key),
            "-out",
            str(ca_crt),
            "-days",
            "1",
            "-subj",
            "/CN=lkmp-e2e-ca",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            str(node_key),
            "-out",
            str(node_csr),
            "-subj",
            "/CN=localhost",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(node_csr),
            "-CA",
            str(ca_crt),
            "-CAkey",
            str(ca_key),
            "-CAcreateserial",
            "-out",
            str(node_crt),
            "-days",
            "1",
            "-extfile",
            str(ext_cfg),
        ],
        check=True,
        capture_output=True,
    )
    return TlsConfig(
        enabled=True,
        ca_cert=str(ca_crt),
        cert_file=str(node_crt),
        key_file=str(node_key),
    )


class IsolatedHostAgent:
    """
    Runs an `lkmp agent` daemon inside an isolated Linux PID + Mount namespace (`unshare --pid --fork --mount-proc`).
    Killing `unshare_proc` causes the Linux kernel to terminate PID 1 of the namespace, reaping every
    child QEMU VM, CRIU restored worker, and page-server inside that simulated host with zero orphans.
    """

    def __init__(self, name: str, base_dir: Path, tls: TlsConfig) -> None:
        self.name = name
        self.host_dir = base_dir / name
        self.work_dir = self.host_dir / "work"
        self.log_file = self.host_dir / "agent.log"
        self.host_dir.mkdir(parents=True, exist_ok=True)
        self.port = get_free_port()
        self.address = f"127.0.0.1:{self.port}"
        self.tls = tls
        self.proc: Optional[subprocess.Popen] = None
        self.ns_init_host_pid: Optional[int] = None

    def start(self) -> None:
        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO_ROOT)
        cmd = [
            "unshare",
            "--pid",
            "--fork",
            "--mount-proc",
            "--mount",
            "--",
            sys.executable,
            "-m",
            "lkmp.cli",
            "agent",
            "--host",
            "127.0.0.1",
            "--port",
            str(self.port),
            "--work-dir",
            str(self.work_dir),
            "--prefer-tmpfs",
            "--rt-priority",
            "10",
            "--mlockall",
            "--tls-ca",
            str(self.tls.ca_cert),
            "--tls-cert",
            str(self.tls.cert_file),
            "--tls-key",
            str(self.tls.key_file),
        ]
        log_fh = open(self.log_file, "w", encoding="utf-8")
        self.proc = subprocess.Popen(
            cmd,
            stdout=log_fh,
            stderr=log_fh,
            env=env,
            start_new_session=True,
        )

        # Wait for agent mTLS health_check and resolve namespace init PID in root /proc
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            children_file = Path(f"/proc/{self.proc.pid}/task/{self.proc.pid}/children")
            if children_file.exists():
                raw = children_file.read_text(encoding="utf-8").strip().split()
                if raw:
                    self.ns_init_host_pid = int(raw[0])
            try:
                with AgentClient(self.address, tls=self.tls, timeout_sec=2.0) as cli:
                    hc = cli.call("health_check")
                    if hc.get("status") == "ok" and self.ns_init_host_pid is not None:
                        return
            except Exception:
                pass
            time.sleep(0.05)

        excerpt = self.log_file.read_text(encoding="utf-8", errors="ignore")[-800:]
        raise RuntimeError(f"Agent {self.name} failed to start on {self.address}: {excerpt}")

    def ns_exec_daemon(self, cmd: List[str]) -> subprocess.CompletedProcess:
        """Execute `cmd` inside this host's PID & mount namespace via `nsenter`."""
        assert self.ns_init_host_pid is not None
        full = [
            "nsenter",
            "-t",
            str(self.ns_init_host_pid),
            "--pid",
            "--mount",
            "--",
            *cmd,
        ]
        return subprocess.run(full, check=True, text=True, capture_output=True)

    def is_ns_pid_alive(self, ns_pid: int) -> bool:
        """Check inside this host's `/proc` whether `ns_pid` exists and is not a zombie."""
        assert self.ns_init_host_pid is not None
        res = subprocess.run(
            [
                "nsenter",
                "-t",
                str(self.ns_init_host_pid),
                "--pid",
                "--mount",
                "--",
                "sh",
                "-c",
                f"test -d /proc/{int(ns_pid)} && ! grep -q '^State:.*Z' /proc/{int(ns_pid)}/status",
            ],
            capture_output=True,
        )
        return res.returncode == 0

    def stop(self) -> None:
        if self.ns_init_host_pid is not None:
            try:
                os.kill(self.ns_init_host_pid, signal.SIGKILL)
            except OSError:
                pass
        if self.proc is not None:
            try:
                self.proc.kill()
                self.proc.wait(timeout=3.0)
            except Exception:
                pass


@dataclass
class E2EScenarioResult:
    name: str
    passed: bool
    duration_ms: float
    metrics: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None


def spawn_qemu_vm_in_host(
    host: IsolatedHostAgent,
    vm_id: str,
    vm_dir: Path,
    qemu_bin: str,
    memory_mb: int = 256,
) -> Tuple[int, str]:
    """Launch a zero-copy-ready QEMU VM inside `host`'s namespace and return `(ns_pid, qmp_sock)`."""
    vm_dir.mkdir(parents=True, exist_ok=True)
    # Keep UNIX socket path short (< 104 bytes sun_path limit)
    qmp_sock = f"/tmp/lkmp-e2e-{vm_id}-{os.getpid()}.qmp"
    pidfile = vm_dir / f"{vm_id}.pid"
    if os.path.exists(qmp_sock):
        os.unlink(qmp_sock)

    cmd, _ = build_migratable_qemu_command(
        workload_id=vm_id,
        qmp_socket=qmp_sock,
        qemu_bin=qemu_bin,
        memory_mb=memory_mb,
        vcpus=1,
        accel="kvm:tcg",
        extra_args=["-daemonize", "-pidfile", str(pidfile)],
    )
    host.ns_exec_daemon(cmd)

    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if pidfile.exists() and os.path.exists(qmp_sock):
            try:
                st = qmp_call(qmp_sock, "query-status", timeout_sec=2.0)
                if st.get("running") is True:
                    ns_pid = int(pidfile.read_text(encoding="utf-8").strip())
                    return ns_pid, qmp_sock
            except Exception:
                pass
        time.sleep(0.05)
    raise RuntimeError(f"QEMU VM {vm_id} did not reach running state on {qmp_sock}")


def spawn_criu_worker_in_host(host: IsolatedHostAgent, worker_dir: Path) -> int:
    """Launch the stateful xorshift64* Python worker inside `host`'s PID namespace."""
    worker_dir.mkdir(parents=True, exist_ok=True)
    assert host.ns_init_host_pid is not None
    subprocess.run(
        [
            "nsenter",
            "-t",
            str(host.ns_init_host_pid),
            "--pid",
            "--mount",
            "--",
            sys.executable,
            str(Path(__file__).resolve()),
            "--criu-worker-dir",
            str(worker_dir),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    ready_file = worker_dir / "ready.txt"
    pid_file = worker_dir / "worker.pid"
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if ready_file.exists() and pid_file.exists():
            return int(pid_file.read_text(encoding="utf-8").strip())
        time.sleep(0.05)
    raise RuntimeError("Stateful CRIU worker failed to start inside Host A namespace")


def verify_prng_chain(log_path: Path, min_entries: int = 4) -> Tuple[int, Set[int]]:
    lines = [ln.strip() for ln in log_path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    if len(lines) < min_entries:
        raise AssertionError(f"Expected >= {min_entries} PRNG log lines, got {len(lines)}")
    expected_state = DEFAULT_PRNG_SEED
    seen_pids = set()
    for idx, line in enumerate(lines, start=1):
        parts = line.split()
        seq = int(parts[0])
        hex_state = parts[1]
        pid_val = int(parts[2].split("=", 1)[1])
        expected_state = step_xorshift64star(expected_state)
        if seq != idx:
            raise AssertionError(f"Broken sequence monotonicity at line {idx}: got seq={seq}")
        if hex_state != f"{expected_state:016x}":
            raise AssertionError(
                f"Corrupted xorshift64* PRNG RAM state at seq={seq}: got {hex_state}, expected {expected_state:016x}"
            )
        seen_pids.add(pid_val)
    return len(lines), seen_pids


def run_suite() -> Dict[str, Any]:
    if platform.system().lower() != "linux":
        return {"skipped": True, "reason": "linux_qemu_e2e.py requires Linux"}
    if os.geteuid() != 0:
        return {"skipped": True, "reason": "linux_qemu_e2e.py requires root (CAP_SYS_ADMIN for PID/mount namespaces & CRIU)"}

    qemu_bin = shutil.which("qemu-system-x86_64") or shutil.which("qemu-system-aarch64")
    criu_bin = shutil.which("criu") or "/usr/local/sbin/criu"
    if not qemu_bin:
        raise RuntimeError("qemu-system-x86_64/aarch64 not found in PATH")
    if not os.path.exists(criu_bin):
        raise RuntimeError("criu binary not found")

    os.environ["PATH"] = f"/usr/local/sbin:/usr/local/bin:{os.environ.get('PATH', '')}"
    kvm_present = os.path.exists("/dev/kvm")
    qemu_ver = subprocess.run([qemu_bin, "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    criu_ver = subprocess.run([criu_bin, "--version"], capture_output=True, text=True).stdout.splitlines()[0]

    results: List[E2EScenarioResult] = []
    cleanup_globs: List[str] = []

    with tempfile.TemporaryDirectory(prefix="lkmp-qemu-e2e-") as tmp:
        base_dir = Path(tmp)
        tls = generate_mtls_pki(base_dir / "pki")
        attest_key = "ab" * 32
        host_a = IsolatedHostAgent("host_a", base_dir, tls)
        host_b = IsolatedHostAgent("host_b", base_dir, tls)

        try:
            host_a.start()
            host_b.start()

            # ------------------------------------------------------------------
            # SCENARIO 1: Real QEMU Live Migration (Host A -> Host B) + Doctor
            # ------------------------------------------------------------------
            t0 = time.monotonic()
            vm1_pid, vm1_qmp_a = spawn_qemu_vm_in_host(
                host_a, "vm1", base_dir / "vm1", qemu_bin=qemu_bin, memory_mb=256
            )
            cleanup_globs.append(vm1_qmp_a)

            with (
                AgentClient(host_a.address, tls=tls) as cli_a,
                AgentClient(host_b.address, tls=tls) as cli_b,
            ):
                doctor = cli_a.call("diagnose_workload", pid=vm1_pid)
                assert doctor["kind"] == "qemu", f"Expected kind=qemu, got {doctor}"
                assert doctor["ready"] is True, f"Expected ready=True, got {doctor}"
                assert doctor["zero_copy_capable"] is True, f"Expected zero_copy_capable=True, got {doctor}"
                assert doctor["memory_backend"] == "memfd-shared"

                mig1_port = get_free_port()
                cfg1 = MigrationConfig(
                    pid=vm1_pid,
                    source_addr=host_a.address,
                    dest_addr=host_b.address,
                    strategy=MigrationStrategy.PRE_COPY,
                    fs_mode=FilesystemMode.SHARED,
                    ip_mobility=IpMobilityMode.NONE,
                    tcp_established=False,
                    unsafe_bare=True,
                    prefer_tmpfs_work_dir=True,
                    qemu_multifd_channels=2,
                    qemu_zero_copy_send=True,
                    page_server_port=mig1_port,
                    attestation_key_hex=attest_key,
                    journal_dir=str(base_dir / "journals"),
                    tls=tls,
                )
                orch1 = MigrationOrchestrator(cfg1, cli_a, cli_b, migration_id="e2e-qemu-hop1")
                res1 = orch1.execute()
                if not res1.success:
                    raise RuntimeError(f"Scenario 1 QEMU live migration failed: {res1.error_message}")

                assert res1.restored_pid is not None
                assert host_b.is_ns_pid_alive(res1.restored_pid), "Destination QEMU PID not alive in Host B"
                assert not host_a.is_ns_pid_alive(vm1_pid), "Source QEMU PID still alive in Host A after commit"

                # Verify persistent keep-alive mTLS connection reuse across all 10 phases!
                assert cli_a.connections_opened == 1, f"Expected 1 socket to Host A, opened {cli_a.connections_opened}"
                assert cli_b.connections_opened == 1, f"Expected 1 socket to Host B, opened {cli_b.connections_opened}"

                dest_qmp_b = "/tmp/lkmp-qmp-e2e-qemu-hop1.sock"
                cleanup_globs.append(dest_qmp_b)
                st_b = qmp_call(dest_qmp_b, "query-status", timeout_sec=3.0)
                assert st_b.get("running") is True and st_b.get("status") == "running", f"Bad QMP status on B: {st_b}"

                results.append(
                    E2EScenarioResult(
                        name="Scenario 1: Real QEMU Live QMP 2PC Migration (Host A -> Host B)",
                        passed=True,
                        duration_ms=round((time.monotonic() - t0) * 1000.0, 2),
                        metrics={
                            "source_pid": vm1_pid,
                            "restored_pid": res1.restored_pid,
                            "freeze_downtime_ms": res1.freeze_downtime_ms,
                            "total_duration_ms": res1.total_duration_ms,
                            "mtls_connections_opened_per_agent": cli_a.connections_opened,
                            "dest_qmp_status": st_b,
                        },
                    )
                )

                # ------------------------------------------------------------------
                # SCENARIO 2: Multi-Hop Reverse Live Migration (Host B -> Host A)
                # ------------------------------------------------------------------
                t1 = time.monotonic()
                mig2_port = get_free_port()
                cfg2 = MigrationConfig(
                    pid=res1.restored_pid,
                    source_addr=host_b.address,
                    dest_addr=host_a.address,
                    strategy=MigrationStrategy.PRE_COPY,
                    fs_mode=FilesystemMode.SHARED,
                    ip_mobility=IpMobilityMode.NONE,
                    tcp_established=False,
                    unsafe_bare=True,
                    prefer_tmpfs_work_dir=True,
                    qemu_multifd_channels=2,
                    page_server_port=mig2_port,
                    attestation_key_hex=attest_key,
                    journal_dir=str(base_dir / "journals"),
                    tls=tls,
                )
                orch2 = MigrationOrchestrator(cfg2, cli_b, cli_a, migration_id="e2e-qemu-hop2")
                res2 = orch2.execute()
                if not res2.success:
                    raise RuntimeError(f"Scenario 2 Multi-Hop QEMU migration failed: {res2.error_message}")

                assert res2.restored_pid is not None
                assert host_a.is_ns_pid_alive(res2.restored_pid), "Hop-2 QEMU PID not alive on Host A"
                assert not host_b.is_ns_pid_alive(res1.restored_pid), "Hop-1 QEMU PID still alive on Host B"
                dest_qmp_hop2 = "/tmp/lkmp-qmp-e2e-qemu-hop2.sock"
                cleanup_globs.append(dest_qmp_hop2)
                st_hop2 = qmp_call(dest_qmp_hop2, "query-status", timeout_sec=3.0)
                assert st_hop2.get("running") is True

                # Cleanly quit hop-2 VM before Scenario 3
                try:
                    qmp_call(dest_qmp_hop2, "quit", timeout_sec=2.0)
                except Exception:
                    pass

                results.append(
                    E2EScenarioResult(
                        name="Scenario 2: Multi-Hop Reverse Live QEMU Migration (Host B -> Host A)",
                        passed=True,
                        duration_ms=round((time.monotonic() - t1) * 1000.0, 2),
                        metrics={
                            "hop1_pid_on_b": res1.restored_pid,
                            "hop2_pid_on_a": res2.restored_pid,
                            "freeze_downtime_ms": res2.freeze_downtime_ms,
                            "dest_qmp_status": st_hop2,
                        },
                    )
                )

            # ------------------------------------------------------------------
            # SCENARIO 3: Heterogeneous 2PC Gang [Real QEMU VM + Real CRIU Process]
            #             Part A: Atomic Rollback -> Part B: Atomic Commit
            # ------------------------------------------------------------------
            t2 = time.monotonic()
            vm3_pid, vm3_qmp_a = spawn_qemu_vm_in_host(
                host_a, "vm3", base_dir / "vm3", qemu_bin=qemu_bin, memory_mb=256
            )
            cleanup_globs.append(vm3_qmp_a)
            criu_work_dir = base_dir / "criu_gang_member"
            criu_pid_a = spawn_criu_worker_in_host(host_a, criu_work_dir)
            time.sleep(0.35)
            pre_rb_count, _ = verify_prng_chain(criu_work_dir / "state.log", min_entries=3)

            # Part A: Inject destination failure on CRIU Member 2 -> prove atomic rollback of BOTH!
            gang_rb_port = get_free_port()
            cleanup_globs.append("/tmp/lkmp-qmp-gang-hetero-rb-m1.sock")
            members_rb = [
                (
                    MigrationConfig(
                        pid=vm3_pid,
                        source_addr=host_a.address,
                        dest_addr=host_b.address,
                        strategy=MigrationStrategy.PRE_COPY,
                        fs_mode=FilesystemMode.SHARED,
                        ip_mobility=IpMobilityMode.NONE,
                        tcp_established=False,
                        unsafe_bare=True,
                        prefer_tmpfs_work_dir=True,
                        page_server_port=gang_rb_port,
                        attestation_key_hex=attest_key,
                        journal_dir=str(base_dir / "journals"),
                        tls=tls,
                    ),
                    AgentClient(host_a.address, tls=tls),
                    AgentClient(host_b.address, tls=tls),
                ),
                (
                    MigrationConfig(
                        pid=criu_pid_a,
                        source_addr=host_a.address,
                        dest_addr=host_b.address,
                        strategy=MigrationStrategy.COLD,
                        fs_mode=FilesystemMode.SHARED,
                        writable_paths=[str(criu_work_dir)],
                        ip_mobility=IpMobilityMode.NONE,
                        tcp_established=False,
                        unsafe_bare=True,
                        prefer_tmpfs_work_dir=True,
                        volume_restore_cmd="false",  # Injected failure on Host B!
                        attestation_key_hex=attest_key,
                        journal_dir=str(base_dir / "journals"),
                        tls=tls,
                    ),
                    AgentClient(host_a.address, tls=tls),
                    AgentClient(host_b.address, tls=tls),
                ),
            ]
            coord_rb = GangMigrationCoordinator(
                "gang-hetero-rb",
                members_rb,
                journal_dir=str(base_dir / "journals"),
                parallel=True,
            )
            rb_res = coord_rb.execute()
            for _c, ca, cb in members_rb:
                ca.close()
                cb.close()

            assert not rb_res.all_committed, f"Expected gang rollback on injected fault: {rb_res.to_dict()}"
            assert rb_res.atomic_rollback_triggered, f"Expected atomic_rollback_triggered=True: {rb_res.to_dict()}"

            # Prove QEMU VM resumed on Host A (`running=True`) and CRIU worker kept advancing on Host A!
            st_after_rb = qmp_call(vm3_qmp_a, "query-status", timeout_sec=3.0)
            assert st_after_rb.get("running") is True, f"Source QEMU not resumed after 2PC rollback: {st_after_rb}"
            time.sleep(0.30)
            post_rb_count, _ = verify_prng_chain(criu_work_dir / "state.log", min_entries=pre_rb_count + 2)

            # Part B: Clean Parallel 2PC Heterogeneous Gang Commit (Host A -> Host B)!
            gang_ok_port = get_free_port()
            dest_gang_qmp = "/tmp/lkmp-qmp-gang-hetero-ok-m1.sock"
            cleanup_globs.append(dest_gang_qmp)
            members_ok = [
                (
                    MigrationConfig(
                        pid=vm3_pid,
                        source_addr=host_a.address,
                        dest_addr=host_b.address,
                        strategy=MigrationStrategy.PRE_COPY,
                        fs_mode=FilesystemMode.SHARED,
                        ip_mobility=IpMobilityMode.NONE,
                        tcp_established=False,
                        unsafe_bare=True,
                        prefer_tmpfs_work_dir=True,
                        page_server_port=gang_ok_port,
                        attestation_key_hex=attest_key,
                        journal_dir=str(base_dir / "journals"),
                        tls=tls,
                    ),
                    AgentClient(host_a.address, tls=tls),
                    AgentClient(host_b.address, tls=tls),
                ),
                (
                    MigrationConfig(
                        pid=criu_pid_a,
                        source_addr=host_a.address,
                        dest_addr=host_b.address,
                        strategy=MigrationStrategy.COLD,
                        fs_mode=FilesystemMode.SHARED,
                        writable_paths=[str(criu_work_dir)],
                        ip_mobility=IpMobilityMode.NONE,
                        tcp_established=False,
                        unsafe_bare=True,
                        prefer_tmpfs_work_dir=True,
                        attestation_key_hex=attest_key,
                        journal_dir=str(base_dir / "journals"),
                        tls=tls,
                    ),
                    AgentClient(host_a.address, tls=tls),
                    AgentClient(host_b.address, tls=tls),
                ),
            ]
            coord_ok = GangMigrationCoordinator(
                "gang-hetero-ok",
                members_ok,
                journal_dir=str(base_dir / "journals"),
                parallel=True,
            )
            ok_res = coord_ok.execute()
            for _c, ca, cb in members_ok:
                ca.close()
                cb.close()

            if not ok_res.all_committed:
                raise RuntimeError(f"Scenario 3 Part B heterogeneous gang commit failed: {ok_res.to_dict()}")

            qemu_b_pid = ok_res.member_results[0].restored_pid
            criu_b_pid = ok_res.member_results[1].restored_pid
            assert qemu_b_pid is not None and host_b.is_ns_pid_alive(qemu_b_pid)
            assert criu_b_pid is not None and host_b.is_ns_pid_alive(criu_b_pid)
            assert not host_a.is_ns_pid_alive(vm3_pid)
            assert not host_a.is_ns_pid_alive(criu_pid_a)

            st_gang_b = qmp_call(dest_gang_qmp, "query-status", timeout_sec=3.0)
            assert st_gang_b.get("running") is True

            # Let migrated CRIU process write additional PRNG entries on Host B and verify unbroken chain!
            time.sleep(0.35)
            final_count, seen_pids = verify_prng_chain(
                criu_work_dir / "state.log", min_entries=post_rb_count + 2
            )

            results.append(
                E2EScenarioResult(
                    name="Scenario 3: Heterogeneous 2PC Gang [QEMU VM + CRIU Process] Rollback & Commit",
                    passed=True,
                    duration_ms=round((time.monotonic() - t2) * 1000.0, 2),
                    metrics={
                        "rollback_verified": True,
                        "commit_verified": True,
                        "qemu_restored_pid_on_b": qemu_b_pid,
                        "criu_restored_pid_on_b": criu_b_pid,
                        "prng_entries_verified": final_count,
                        "qemu_freeze_downtime_ms": ok_res.member_results[0].freeze_downtime_ms,
                        "criu_freeze_downtime_ms": ok_res.member_results[1].freeze_downtime_ms,
                        "seen_worker_pids": sorted(seen_pids),
                    },
                )
            )
        finally:
            host_a.stop()
            host_b.stop()
            cleanup_globs.extend(
                [
                    "/tmp/lkmp-qmp-qemu-e2e-hop1-dst.sock",
                    "/tmp/lkmp-qmp-qemu-e2e-hop2-dst.sock",
                    "/tmp/lkmp-qmp-gang-hetero-rb-m1-dst.sock",
                    "/tmp/lkmp-qmp-gang-hetero-ok-m1-dst.sock",
                ]
            )
            for sock_p in cleanup_globs:
                try:
                    if os.path.exists(sock_p):
                        os.unlink(sock_p)
                except OSError:
                    pass

    return {
        "skipped": False,
        "all_passed": all(r.passed for r in results),
        "environment": {
            "kernel": platform.release(),
            "arch": platform.machine(),
            "qemu_version": qemu_ver,
            "criu_version": criu_ver,
            "kvm_hardware_accel": kvm_present,
            "qemu_accel_mode": "kvm" if kvm_present else "tcg",
        },
        "scenarios": [asdict(r) for r in results],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="LKMP Real QEMU & Heterogeneous 2PC Gang E2E Suite")
    parser.add_argument("--criu-worker-dir", help=argparse.SUPPRESS)
    parser.add_argument("--json", action="store_true", help="Print JSON report only")
    args = parser.parse_args()

    if args.criu_worker_dir:
        run_stateful_criu_worker(Path(args.criu_worker_dir))
        return 0

    summary = run_suite()
    if args.json:
        print(json.dumps(summary, indent=2))
    else:
        print("=== LKMP REAL QEMU & HETEROGENEOUS 2PC GANG E2E SUITE ===")
        print(json.dumps(summary, indent=2))
    if summary.get("skipped"):
        return 0
    return 0 if summary.get("all_passed") else 1


if __name__ == "__main__":
    sys.exit(main())
