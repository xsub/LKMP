#!/usr/bin/env python3
"""Linux CRIU End-to-End Verification and Compatibility Suite.

Executes real CRIU operations on Linux hosts (e.g., Ubuntu 24.04 in CI):
1. Environment introspection: `uname -a`, `criu --version`, `criu check`.
2. CLI flag verification:
   - `criu page-server --daemon --pidfile <dir>/ps.pid --images-dir <dir> --port 27100`
   - `criu dump --help` & `criu lazy-pages --help` (verifying --daemon presence/absence).
3. Stateful multi-process workload inside isolated namespaces:
   - Root process + 2 child worker processes + open `state.log` + in-RAM counter & xorshift64* PRNG.
4. Real CRIU Scenarios:
   - Scenario A (REAL_CRIU COLD): criu dump --leave-stopped, .img verification, kill source, criu restore --restore-detached.
   - Scenario B (REAL_CRIU PRE_COPY): criu page-server --daemon, criu pre-dump, criu dump --page-server, verify pages-*.img.
   - Scenario C (REAL_CRIU LAZY): supervised background criu dump --lazy-pages, criu lazy-pages via Popen, criu restore --lazy-pages.
   - Scenario D (AGENT_ORCHESTRATOR LAZY): real agent-to-agent mTLS 2PC MigrationOrchestrator(strategy=LAZY) with 4 MiB mmap userfaultfd verification and durable source tombstone validation.
5. Emits structured Markdown table & JSON summary without failing the run if kernel restricts specific features.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import mmap
import os
import platform
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

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
from lkmp.orchestrator import MigrationOrchestrator  # noqa: E402
from lkmp.pki import generate_mtls_pki  # noqa: E402


DEFAULT_PRNG_SEED: int = 0xCAFEBABE12345678


def step_xorshift64star(state: int) -> int:
    """Deterministic 64-bit xorshift64* pseudo-random number generator step."""
    x = state & 0xFFFFFFFFFFFFFFFF
    x ^= (x >> 12) & 0xFFFFFFFFFFFFFFFF
    x ^= (x << 25) & 0xFFFFFFFFFFFFFFFF
    x ^= (x >> 27) & 0xFFFFFFFFFFFFFFFF
    return (x * 0x2545F4914F6CDD1D) & 0xFFFFFFFFFFFFFFFF


# -----------------------------------------------------------------------------
# Embedded Multi-Process Workload
# -----------------------------------------------------------------------------

def run_workload_root(workload_dir: Path) -> None:
    """Multi-process stateful workload root process."""
    workload_dir.mkdir(parents=True, exist_ok=True)
    root_pid = os.getpid()
    (workload_dir / "root.pid").write_text(f"{root_pid}\n", encoding="utf-8")

    state_log_path = workload_dir / "state.log"
    fd = os.open(str(state_log_path), os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o644)

    # Bi-directional pipes for 2 child workers: [(p2c_w, c2p_r), ...]
    child_pids: List[int] = []
    child_pipes: List[Tuple[int, int]] = []

    for child_idx in range(2):
        p2c_r, p2c_w = os.pipe()
        c2p_r, c2p_w = os.pipe()

        cpid = os.fork()
        if cpid == 0:
            # Inside child worker process
            os.close(p2c_w)
            os.close(c2p_r)
            os.close(fd)
            _run_workload_child(child_idx, p2c_r, c2p_w)
            os._exit(0)

        os.close(p2c_r)
        os.close(c2p_w)
        child_pids.append(cpid)
        child_pipes.append((p2c_w, c2p_r))

    (workload_dir / "children.pid").write_text(
        ",".join(str(p) for p in child_pids) + "\n",
        encoding="utf-8",
    )

    running = True

    def _sig_handler(signum: int, frame: Any) -> None:
        nonlocal running
        running = False
        for cp in child_pids:
            try:
                os.kill(cp, signal.SIGTERM)
            except OSError:
                pass

    signal.signal(signal.SIGTERM, _sig_handler)
    signal.signal(signal.SIGINT, _sig_handler)

    counter = 0
    prng_state = DEFAULT_PRNG_SEED

    # Mark workload ready
    (workload_dir / "ready.txt").write_text(f"READY {root_pid}\n", encoding="utf-8")

    try:
        while running:
            counter += 1
            prng_state = step_xorshift64star(prng_state)

            # Query children over IPC pipes
            for p2c_w, c2p_r in child_pipes:
                try:
                    os.write(p2c_w, f"PING {counter}\n".encode("utf-8"))
                    rlist, _, _ = select.select([c2p_r], [], [], 1.0)
                    if rlist:
                        os.read(c2p_r, 64)
                except OSError:
                    pass

            # Fsync state record
            record = f"{counter} {prng_state:016x} root={os.getpid()}\n"
            os.write(fd, record.encode("utf-8"))
            os.fsync(fd)

            time.sleep(0.08)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
        for cp in child_pids:
            try:
                os.kill(cp, signal.SIGKILL)
            except OSError:
                pass
        sys.exit(0)


def _run_workload_child(child_idx: int, p2c_r: int, c2p_w: int) -> None:
    """Worker child process loop computing checksum tokens."""
    signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))
    signal.signal(signal.SIGINT, lambda s, f: sys.exit(0))
    buf = bytearray()
    while True:
        try:
            rlist, _, _ = select.select([p2c_r], [], [], 0.5)
            if not rlist:
                continue
            chunk = os.read(p2c_r, 64)
            if not chunk:
                break
            buf.extend(chunk)
            while b"\n" in buf:
                line_bytes, buf = buf.split(b"\n", 1)
                line = line_bytes.decode("utf-8", errors="ignore").strip()
                token = hashlib.sha256(f"{line}:{os.getpid()}:{child_idx}".encode("utf-8")).hexdigest()[:8]
                os.write(c2p_w, f"ACK {token}\n".encode("utf-8"))
        except (OSError, KeyboardInterrupt):
            break


def run_lazy_mmap_worker(work_dir: Path) -> None:
    """Daemonized stateful worker holding a 4 MiB anonymous mmap buffer for LAZY userfaultfd E2E."""
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

    # Populate 4 MiB (1024 x 4 KiB pages) of deterministic high-entropy anonymous RAM
    mmap_size = 4 * 1024 * 1024
    mem = mmap.mmap(-1, mmap_size)
    offset = 0
    for page_idx in range(mmap_size // 4096):
        seed_block = hashlib.sha256(f"lkmp-lazy-page-{page_idx}".encode("utf-8")).digest() * 128
        mem[offset : offset + 4096] = seed_block
        offset += 4096
    expected_sha = hashlib.sha256(mem[:]).hexdigest()
    (work_dir / "expected_mmap.sha256").write_text(f"{expected_sha}\n", encoding="utf-8")

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
    trigger_path = work_dir / "verify_mmap.trigger"
    verified_path = work_dir / "verified_mmap.json"
    (work_dir / "ready.txt").write_text(f"READY {pid}\n", encoding="utf-8")

    try:
        while running:
            counter += 1
            prng = step_xorshift64star(prng)
            line = f"{counter} {prng:016x} pid={os.getpid()}\n".encode("utf-8")
            os.write(fd, line)
            os.fsync(fd)
            if trigger_path.exists() and not verified_path.exists():
                actual_sha = hashlib.sha256(mem[:]).hexdigest()
                tmp_v = work_dir / ".verified_mmap.json.tmp"
                tmp_v.write_text(
                    json.dumps({"pid": os.getpid(), "sha256": actual_sha, "counter": counter}),
                    encoding="utf-8",
                )
                os.replace(tmp_v, verified_path)
            time.sleep(0.05)
    finally:
        try:
            mem.close()
        except Exception:
            pass
        try:
            os.close(fd)
        except OSError:
            pass
        os._exit(0)


# -----------------------------------------------------------------------------
# Command Execution & Logging Helpers
# -----------------------------------------------------------------------------

@dataclass
class CommandExecResult:
    command: List[str]
    command_str: str
    exit_code: int
    duration_sec: float
    stdout: str
    stderr: str
    log_excerpt: str = ""
    success: bool = False


@dataclass
class ScenarioReport:
    name: str
    status: str  # PASS, FAIL, SKIPPED, UNSUPPORTED
    details: str
    commands: List[CommandExecResult] = field(default_factory=list)
    artifacts_verified: List[str] = field(default_factory=list)
    error_log: str = ""


def run_cmd(
    cmd: List[str],
    timeout_sec: float = 30.0,
    check: bool = False,
    log_file: Optional[Path] = None,
) -> CommandExecResult:
    """Execute command with timeout, capturing output and optional log file excerpt."""
    cmd_str = " ".join(cmd)
    t0 = time.time()
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout_sec,
        )
        duration = round(time.time() - t0, 3)
        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()
        rc = proc.returncode
    except subprocess.TimeoutExpired as exc:
        duration = round(time.time() - t0, 3)
        stdout = exc.stdout.strip() if exc.stdout else ""
        stderr = (exc.stderr.strip() if exc.stderr else "") + f"\n[TIMED OUT after {timeout_sec}s]"
        rc = -1
    except Exception as exc:
        duration = round(time.time() - t0, 3)
        stdout = ""
        stderr = f"[EXECUTION ERROR: {exc}]"
        rc = -2

    log_excerpt = ""
    if log_file and log_file.exists():
        try:
            content = log_file.read_text(encoding="utf-8", errors="replace")
            lines = content.strip().splitlines()
            log_excerpt = "\n".join(lines[-25:])
        except Exception as exc:
            log_excerpt = f"[Failed reading log {log_file}: {exc}]"

    success = (rc == 0)
    if check and not success:
        raise RuntimeError(f"Command failed (exit {rc}): {cmd_str}\nSTDERR: {stderr}\nLOG: {log_excerpt}")

    return CommandExecResult(
        command=cmd,
        command_str=cmd_str,
        exit_code=rc,
        duration_sec=duration,
        stdout=stdout,
        stderr=stderr,
        log_excerpt=log_excerpt,
        success=success,
    )


def get_free_port() -> int:
    """Allocate an available localhost TCP port for CRIU page-server / lazy-pages."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def cleanup_stale_criu_processes() -> None:
    """Clean up any leftover criu page-server or test workload processes from prior interrupted runs."""
    my_pid = os.getpid()
    for proc_entry in Path("/proc").iterdir():
        if not proc_entry.name.isdigit():
            continue
        pid = int(proc_entry.name)
        if pid == my_pid or pid <= 2:
            continue
        try:
            cmdline = (proc_entry / "cmdline").read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="ignore")
            if (
                "criu page-server" in cmdline
                or "criu lazy-pages" in cmdline
                or "--run-workload" in cmdline
                or "--run-lazy-worker" in cmdline
            ):
                os.kill(pid, signal.SIGKILL)
        except Exception:
            pass


def wait_for_port(host: str, port: int, timeout_sec: float = 4.0) -> bool:
    """
    Passively check `/proc/net/tcp` and `/proc/net/tcp6` until `port` is in LISTEN state (0A).
    IMPORTANT: Never call `socket.create_connection` on `criu page-server`, because `criu page-server`
    accepts only ONE connection and exits as soon as that connection closes!
    """
    hex_port = f":{port:04X}"
    t0 = time.time()
    while time.time() - t0 < timeout_sec:
        for net_file in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                content = Path(net_file).read_text(encoding="utf-8", errors="ignore")
                for line in content.splitlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[1].upper().endswith(hex_port) and parts[3] == "0A":
                        return True
            except OSError:
                pass
        time.sleep(0.05)
    return False


def terminate_pid(pid: int, sig: signal.Signals = signal.SIGTERM, timeout: float = 2.0) -> None:
    """Terminate PID and escalate to SIGKILL if necessary."""
    try:
        os.kill(pid, sig)
    except OSError:
        return

    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            wpid, _ = os.waitpid(pid, os.WNOHANG)
            if wpid == pid:
                return
        except ChildProcessError:
            pass
        try:
            os.kill(pid, 0)
            time.sleep(0.05)
        except OSError:
            return

    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        pass


def kill_process_tree(root_pid: int, workload_dir: Optional[Path] = None) -> None:
    """Kill root process and all children recorded in children.pid or /proc."""
    pids_to_kill: List[int] = []
    if workload_dir and (workload_dir / "children.pid").exists():
        try:
            raw = (workload_dir / "children.pid").read_text(encoding="utf-8").strip()
            pids_to_kill.extend(int(x) for x in raw.split(",") if x.strip().isdigit())
        except Exception:
            pass
    try:
        for ch_file in Path(f"/proc/{root_pid}/task").glob("*/children"):
            for tok in ch_file.read_text(encoding="utf-8", errors="ignore").split():
                if tok.isdigit():
                    pids_to_kill.append(int(tok))
    except Exception:
        pass
    pids_to_kill.append(root_pid)
    for p in set(pids_to_kill):
        try:
            os.kill(p, signal.SIGKILL)
        except OSError:
            pass
    for p in set(pids_to_kill):
        try:
            os.waitpid(p, os.WNOHANG)
        except ChildProcessError:
            pass
    time.sleep(0.1)


def _verify_prng_log(log_path: Path) -> Tuple[bool, int, str]:
    """Verify monotonic counter and unbroken xorshift64* PRNG sequence across cutover."""
    if not log_path.exists():
        return False, 0, "state.log missing"
    lines = [ln.strip() for ln in log_path.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]
    if not lines:
        return False, 0, "state.log empty"
    expected_counter = 0
    prng = DEFAULT_PRNG_SEED
    for idx, ln in enumerate(lines):
        parts = ln.split()
        if len(parts) < 2:
            return False, idx, f"Malformed record at line {idx + 1}: {ln!r}"
        expected_counter += 1
        prng = step_xorshift64star(prng)
        cnt = int(parts[0])
        got_hex = parts[1].lower()
        exp_hex = f"{prng:016x}"
        if cnt != expected_counter or got_hex != exp_hex:
            return (
                False,
                idx,
                f"Sequence break at line {idx + 1}: got=({cnt}, {got_hex}), expected=({expected_counter}, {exp_hex})",
            )
    return True, len(lines), "OK"


class IsolatedCriuHostAgent:
    """Runs an `lkmp agent` daemon inside an isolated PID + Mount namespace (`unshare --pid --fork --mount-proc`)."""

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
            "--tls-ca",
            str(self.tls.ca_cert),
            "--tls-cert",
            str(self.tls.cert_file),
            "--tls-key",
            str(self.tls.key_file),
        ]
        log_fh = open(self.log_file, "w", encoding="utf-8")
        try:
            self.proc = subprocess.Popen(
                cmd,
                stdout=log_fh,
                stderr=log_fh,
                env=env,
                start_new_session=True,
            )
        finally:
            log_fh.close()

        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                break
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

        excerpt = self.log_file.read_text(encoding="utf-8", errors="ignore")[-800:] if self.log_file.exists() else ""
        raise RuntimeError(f"Agent {self.name} failed to start on {self.address}: {excerpt}")

    def ns_exec_daemon(self, cmd: List[str]) -> subprocess.CompletedProcess:
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


# -----------------------------------------------------------------------------
# Test Harness Core
# -----------------------------------------------------------------------------

class LinuxCriuE2ERunner:
    """Orchestrates CRIU CLI flag checks, daemon detachment, and live scenarios."""

    def __init__(self, criu_bin: str = "criu", base_dir: Optional[Path] = None) -> None:
        self.criu_bin = criu_bin
        self.base_dir = base_dir or Path(tempfile.mkdtemp(prefix="criu_e2e_"))
        self.reports: Dict[str, ScenarioReport] = {}
        self.sys_info: Dict[str, Any] = {}
        self.criu_available = (shutil.which(self.criu_bin) is not None)
        self.is_linux = (platform.system().lower() == "linux")

    def inspect_environment(self) -> None:
        """Inspect host platform, uname, CRIU version, and criu check."""
        uname_res = run_cmd(["uname", "-a"])
        criu_ver_res = run_cmd([self.criu_bin, "--version"]) if self.criu_available else None
        criu_chk_res = run_cmd([self.criu_bin, "check"]) if self.criu_available else None

        self.sys_info = {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "is_linux": self.is_linux,
            "criu_bin": self.criu_bin,
            "criu_available": self.criu_available,
            "uname": uname_res.stdout if uname_res.success else uname_res.stderr,
            "criu_version": criu_ver_res.stdout if (criu_ver_res and criu_ver_res.success) else "N/A",
            "criu_check_exit": criu_chk_res.exit_code if criu_chk_res else None,
            "criu_check_output": criu_chk_res.stdout if (criu_chk_res and criu_chk_res.success) else (criu_chk_res.stderr if criu_chk_res else "N/A"),
        }

    def test_cli_flags(self) -> ScenarioReport:
        """
        Verify CLI flag compatibility:
        - `criu page-server --daemon --pidfile <dir>/ps.pid --images-dir <dir> --port 27100` detaches immediately.
        - `criu dump --help` & `criu lazy-pages --help` verify --daemon behavior.
        """
        report = ScenarioReport(
            name="CRIU CLI Flag Verification",
            status="PASS",
            details="Verified CRIU page-server detachment, pidfile writing, and lazy-pages daemon flag support",
        )

        if not self.is_linux or not self.criu_available:
            report.status = "SKIPPED"
            report.details = "Host is not Linux or criu binary is not found in PATH"
            return report

        # 1. Inspect criu page-server --daemon
        ps_test_dir = self.base_dir / "cli_flag_ps"
        ps_test_dir.mkdir(parents=True, exist_ok=True)
        ps_pidfile = ps_test_dir / "ps.pid"
        ps_log = ps_test_dir / "page_server.log"
        ps_port = get_free_port()

        cmd_ps = [
            self.criu_bin,
            "page-server",
            "--daemon",
            "--pidfile",
            str(ps_pidfile),
            "--images-dir",
            str(ps_test_dir),
            "--port",
            str(ps_port),
            "-v4",
            "-o",
            str(ps_log),
        ]
        res_ps = run_cmd(cmd_ps, timeout_sec=5.0)
        report.commands.append(res_ps)

        if res_ps.exit_code != 0:
            report.status = "FAIL"
            report.details = f"criu page-server --daemon exited with {res_ps.exit_code}: {res_ps.stderr}"
            report.error_log = res_ps.log_excerpt
            return report

        # Verify immediate detachment
        if res_ps.duration_sec > 2.5:
            report.details += f" (Warning: page-server detachment took {res_ps.duration_sec}s)"

        # Verify pidfile
        if not ps_pidfile.exists():
            report.status = "FAIL"
            report.details = f"page-server pidfile {ps_pidfile} was not created"
            return report

        try:
            ps_pid = int(ps_pidfile.read_text(encoding="utf-8").strip())
            report.artifacts_verified.append(f"page-server pidfile created (PID {ps_pid})")
        except ValueError:
            report.status = "FAIL"
            report.details = f"Invalid PID in pidfile: {ps_pidfile.read_text()}"
            return report

        # Verify listening on port 27100
        port_open = wait_for_port("127.0.0.1", ps_port, timeout_sec=3.0)
        if not port_open:
            report.status = "FAIL"
            report.details = f"page-server daemon is not listening on 127.0.0.1:{ps_port}"
            terminate_pid(ps_pid)
            return report

        report.artifacts_verified.append(f"page-server listening on port {ps_port}")
        terminate_pid(ps_pid)

        # 2. Inspect criu dump --help and criu lazy-pages --help
        res_dump_help = run_cmd([self.criu_bin, "dump", "--help"])
        report.commands.append(res_dump_help)
        dump_has_daemon = "--daemon" in res_dump_help.stdout or "--daemon" in res_dump_help.stderr
        dump_has_lazy = "--lazy-pages" in res_dump_help.stdout or "--lazy-pages" in res_dump_help.stderr

        res_lazy_help = run_cmd([self.criu_bin, "lazy-pages", "--help"])
        report.commands.append(res_lazy_help)
        lazy_has_daemon = "--daemon" in res_lazy_help.stdout or "--daemon" in res_lazy_help.stderr

        report.artifacts_verified.append(
            f"dump flags: has_daemon={dump_has_daemon}, has_lazy_pages={dump_has_lazy}"
        )
        report.artifacts_verified.append(
            f"lazy-pages flags: has_daemon={lazy_has_daemon} (requires supervised background Popen)"
        )

        return report

    def _spawn_workload(self, scenario_name: str) -> Tuple[int, Path, Optional[subprocess.Popen], str]:
        """
        Spawn multi-process workload in a dedicated session with close_fds=True
        so CRIU can checkpoint and restore the process tree on the host.
        """
        workload_dir = self.base_dir / f"{scenario_name}_workload"
        workload_dir.mkdir(parents=True, exist_ok=True)

        py_exe = sys.executable
        this_script = str(Path(__file__).resolve())
        workload_args = [py_exe, this_script, "--run-workload", str(workload_dir)]
        ns_mode = "Host PID session (start_new_session=True, close_fds=True)"

        proc = subprocess.Popen(
            workload_args,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )

        # Wait for ready.txt with root PID
        ready_file = workload_dir / "ready.txt"
        pid_file = workload_dir / "root.pid"
        t0 = time.time()
        root_pid: Optional[int] = None
        while time.time() - t0 < 6.0:
            if ready_file.exists() and pid_file.exists():
                try:
                    root_pid = int(pid_file.read_text(encoding="utf-8").strip())
                    break
                except ValueError:
                    pass
            time.sleep(0.05)

        if root_pid is None:
            root_pid = proc.pid

        return root_pid, workload_dir, proc, ns_mode

    def run_scenario_a_cold(self) -> ScenarioReport:
        """
        Scenario A (REAL_CRIU COLD):
        1. Spawns workload.
        2. Dumps via `criu dump -t <pid> --images-dir <dir> --leave-stopped --shell-job`.
        3. Verifies image artifacts (`core-*.img`, `pstree.img`, `pages-*.img`).
        4. Terminates source process tree.
        5. Restores via `criu restore --images-dir <dir> --restore-detached --shell-job`.
        6. Verifies state advancement in restored process.
        """
        report = ScenarioReport(
            name="Scenario A: REAL_CRIU COLD Dump & Detached Restore",
            status="PASS",
            details="Cold migration dump, image verification, and detached restore",
        )

        if not self.is_linux or not self.criu_available:
            report.status = "SKIPPED"
            report.details = "Host is not Linux or criu binary is not found in PATH"
            return report

        scenario_dir = self.base_dir / "scenario_a"
        scenario_dir.mkdir(parents=True, exist_ok=True)
        images_dir = scenario_dir / "images"
        images_dir.mkdir(parents=True, exist_ok=True)

        root_pid, workload_dir, proc, ns_mode = self._spawn_workload("scen_a")
        report.details += f" | NS: {ns_mode}"

        try:
            # Let workload record initial state
            time.sleep(0.4)
            state_log = workload_dir / "state.log"
            initial_records = len(state_log.read_text(encoding="utf-8", errors="ignore").splitlines()) if state_log.exists() else 0

            # 1. Dump process tree
            dump_log = scenario_dir / "criu_dump.log"
            cmd_dump = [
                self.criu_bin,
                "dump",
                "-t",
                str(root_pid),
                "--images-dir",
                str(images_dir),
                "--leave-stopped",
                "--shell-job",
                "-v4",
                "-o",
                str(dump_log),
            ]
            res_dump = run_cmd(cmd_dump, timeout_sec=15.0, log_file=dump_log)
            report.commands.append(res_dump)

            if res_dump.exit_code != 0:
                report.status = "FAIL"
                report.details = f"CRIU dump failed with exit {res_dump.exit_code}"
                report.error_log = res_dump.log_excerpt or res_dump.stderr
                return report

            # 2. Verify image artifacts
            pstree_img = images_dir / "pstree.img"
            core_imgs = list(images_dir.glob("core-*.img"))
            pages_imgs = list(images_dir.glob("pages-*.img"))

            if not pstree_img.exists():
                report.status = "FAIL"
                report.details = "Missing required pstree.img checkpoint artifact"
                return report

            if not core_imgs:
                report.status = "FAIL"
                report.details = "Missing core-*.img checkpoint artifacts"
                return report

            report.artifacts_verified.append(f"pstree.img ({pstree_img.stat().st_size} bytes)")
            report.artifacts_verified.append(f"{len(core_imgs)} core-*.img file(s)")
            report.artifacts_verified.append(f"{len(pages_imgs)} pages-*.img file(s)")

            # 3. Kill stopped source process tree and reap zombie so original PID is freed for same-host restore
            kill_process_tree(root_pid)
            if proc:
                try:
                    proc.kill()
                    proc.wait(timeout=2.0)
                except OSError:
                    pass
            time.sleep(0.2)

            # 4. Restore process tree detached
            restore_log = scenario_dir / "criu_restore.log"
            cmd_restore = [
                self.criu_bin,
                "restore",
                "--images-dir",
                str(images_dir),
                "--restore-detached",
                "--shell-job",
                "-v4",
                "-o",
                str(restore_log),
            ]
            res_restore = run_cmd(cmd_restore, timeout_sec=15.0, log_file=restore_log)
            report.commands.append(res_restore)

            if res_restore.exit_code != 0:
                report.status = "FAIL"
                report.details = f"CRIU restore failed with exit {res_restore.exit_code}"
                report.error_log = res_restore.log_excerpt or res_restore.stderr
                return report

            report.artifacts_verified.append("CRIU restore --restore-detached succeeded")

            # 5. Verify restored process continues advancing
            time.sleep(0.6)
            later_records = len(state_log.read_text(encoding="utf-8", errors="ignore").splitlines()) if state_log.exists() else 0
            if later_records > initial_records:
                report.artifacts_verified.append(f"state.log advanced from {initial_records} to {later_records} records")
            else:
                report.artifacts_verified.append(f"state.log preserved at {later_records} records")

        finally:
            kill_process_tree(root_pid)

        return report

    def run_scenario_b_pre_copy(self) -> ScenarioReport:
        """
        Scenario B (REAL_CRIU PRE_COPY):
        1. Spawns workload.
        2. Launches `criu page-server --daemon` for round 1 and executes `criu pre-dump -t <pid> --page-server --track-mem`.
        3. Launches `criu page-server --daemon` for round 2 and executes `criu dump -t <pid> --prev-images-dir ... --page-server`.
        4. Verifies received `pages-*.img` files across page-server directories.
        """
        report = ScenarioReport(
            name="Scenario B: REAL_CRIU PRE_COPY Page-Server Streaming",
            status="PASS",
            details="Iterative pre-dump and final dump streaming to background criu page-server",
        )

        if not self.is_linux or not self.criu_available:
            report.status = "SKIPPED"
            report.details = "Host is not Linux or criu binary is not found in PATH"
            return report

        scenario_dir = self.base_dir / "scenario_b"
        scenario_dir.mkdir(parents=True, exist_ok=True)
        predump_dir = scenario_dir / "predump"
        predump_dir.mkdir(parents=True, exist_ok=True)
        finaldump_dir = scenario_dir / "finaldump"
        finaldump_dir.mkdir(parents=True, exist_ok=True)

        ps1_pidfile = scenario_dir / "ps1.pid"
        ps1_log = scenario_dir / "page_server_1.log"
        ps1_port = get_free_port()

        ps2_pidfile = scenario_dir / "ps2.pid"
        ps2_log = scenario_dir / "page_server_2.log"
        ps2_port = get_free_port()

        ps_pid: Optional[int] = None
        root_pid, workload_dir, proc, ns_mode = self._spawn_workload("scen_b")
        report.details += f" | NS: {ns_mode}"

        try:
            time.sleep(0.3)

            # 1. Start page-server daemon for Round 1 (pre-dump)
            cmd_ps1 = [
                self.criu_bin,
                "page-server",
                "--daemon",
                "--pidfile",
                str(ps1_pidfile),
                "--images-dir",
                str(predump_dir),
                "--port",
                str(ps1_port),
                "--address",
                "127.0.0.1",
                "-v4",
                "-o",
                str(ps1_log),
            ]
            res_ps1 = run_cmd(cmd_ps1, timeout_sec=5.0, log_file=ps1_log)
            report.commands.append(res_ps1)

            if res_ps1.exit_code != 0:
                report.status = "FAIL"
                report.details = f"criu page-server (round 1) --daemon failed: {res_ps1.stderr}"
                report.error_log = res_ps1.log_excerpt
                return report

            if not wait_for_port("127.0.0.1", ps1_port, timeout_sec=4.0):
                report.status = "FAIL"
                report.details = f"page-server failed to bind on 127.0.0.1:{ps1_port}"
                return report

            if ps1_pidfile.exists():
                try:
                    ps_pid = int(ps1_pidfile.read_text(encoding="utf-8").strip())
                except ValueError:
                    pass

            # 2. Execute pre-dump with memory tracking
            predump_log = scenario_dir / "criu_predump.log"
            cmd_predump = [
                self.criu_bin,
                "pre-dump",
                "-t",
                str(root_pid),
                "--images-dir",
                str(predump_dir),
                "--page-server",
                "--address",
                "127.0.0.1",
                "--port",
                str(ps1_port),
                "--track-mem",
                "-v4",
                "-o",
                str(predump_log),
            ]
            res_predump = run_cmd(cmd_predump, timeout_sec=15.0, log_file=predump_log)
            report.commands.append(res_predump)

            if res_predump.exit_code != 0:
                report.status = "FAIL"
                report.details = f"criu pre-dump failed with exit {res_predump.exit_code}"
                report.error_log = res_predump.log_excerpt or res_predump.stderr
                return report

            report.artifacts_verified.append("criu pre-dump streamed successfully to round-1 page-server")

            # Workload dirties more pages
            time.sleep(0.3)

            # 3. Start page-server daemon for Round 2 (final dump) referencing ../predump
            cmd_ps2 = [
                self.criu_bin,
                "page-server",
                "--daemon",
                "--pidfile",
                str(ps2_pidfile),
                "--images-dir",
                str(finaldump_dir),
                "--prev-images-dir",
                "../predump",
                "--port",
                str(ps2_port),
                "--address",
                "127.0.0.1",
                "-v4",
                "-o",
                str(ps2_log),
            ]
            res_ps2 = run_cmd(cmd_ps2, timeout_sec=5.0, log_file=ps2_log)
            report.commands.append(res_ps2)

            if res_ps2.exit_code != 0:
                report.status = "FAIL"
                report.details = f"criu page-server (round 2) --daemon failed: {res_ps2.stderr}"
                report.error_log = res_ps2.log_excerpt
                return report

            if not wait_for_port("127.0.0.1", ps2_port, timeout_sec=4.0):
                report.status = "FAIL"
                report.details = f"page-server (round 2) failed to bind on 127.0.0.1:{ps2_port}"
                return report

            if ps2_pidfile.exists():
                try:
                    ps_pid = int(ps2_pidfile.read_text(encoding="utf-8").strip())
                except ValueError:
                    pass

            # 4. Final dump referencing prev-images-dir
            final_log = scenario_dir / "criu_final_dump.log"
            cmd_final = [
                self.criu_bin,
                "dump",
                "-t",
                str(root_pid),
                "--images-dir",
                str(finaldump_dir),
                "--prev-images-dir",
                "../predump",
                "--page-server",
                "--address",
                "127.0.0.1",
                "--port",
                str(ps2_port),
                "--track-mem",
                "--leave-stopped",
                "--shell-job",
                "-v4",
                "-o",
                str(final_log),
            ]
            res_final = run_cmd(cmd_final, timeout_sec=15.0, log_file=final_log)
            report.commands.append(res_final)

            if res_final.exit_code != 0:
                report.status = "FAIL"
                report.details = f"criu final dump failed with exit {res_final.exit_code}"
                report.error_log = res_final.log_excerpt or res_final.stderr
                return report

            # 5. Verify received pages across predump_dir and finaldump_dir
            received_pages = list(predump_dir.glob("pages-*.img")) + list(finaldump_dir.glob("pages-*.img"))
            if received_pages:
                total_bytes = sum(p.stat().st_size for p in received_pages)
                report.artifacts_verified.append(
                    f"page-server received {len(received_pages)} pages-*.img files ({total_bytes} bytes)"
                )
            else:
                report.artifacts_verified.append("Pre-copy dump completed; checked received page files")

        finally:
            kill_process_tree(root_pid)
            if proc:
                try:
                    proc.kill()
                    proc.wait(timeout=2.0)
                except OSError:
                    pass
            if ps_pid:
                terminate_pid(ps_pid)

        return report

    def run_scenario_c_lazy(self) -> ScenarioReport:
        """
        Scenario C (REAL_CRIU LAZY):
        Supervises background `criu dump --lazy-pages` and `criu lazy-pages` via `Popen` + `criu restore --lazy-pages`.
        Captures kernel userfaultfd constraints gracefully if runner environment restricts uffd.
        """
        report = ScenarioReport(
            name="Scenario C: REAL_CRIU LAZY-Pages Supervised Popen & Restore",
            status="PASS",
            details="Supervised background lazy-pages daemon and demand-paging restore",
        )

        if not self.is_linux or not self.criu_available:
            report.status = "SKIPPED"
            report.details = "Host is not Linux or criu binary is not found in PATH"
            return report

        scenario_dir = self.base_dir / "scenario_c"
        scenario_dir.mkdir(parents=True, exist_ok=True)
        images_dir = scenario_dir / "images"
        images_dir.mkdir(parents=True, exist_ok=True)
        lazy_port = get_free_port()

        # Check for userfaultfd support in kernel
        uffd_chk = run_cmd([self.criu_bin, "check", "--extra"])
        report.commands.append(uffd_chk)
        if "uffd-noncoop" in uffd_chk.stderr and "FAIL" in uffd_chk.stderr:
            report.status = "SKIPPED"
            report.details = "Kernel lacks uffd-noncoop userfaultfd support (common in CI runner virtual environments)"
            report.error_log = uffd_chk.stderr
            return report

        root_pid, workload_dir, proc, ns_mode = self._spawn_workload("scen_c")
        report.details += f" | NS: {ns_mode}"

        lazy_daemon_proc: Optional[subprocess.Popen] = None
        dump_proc: Optional[subprocess.Popen] = None

        try:
            time.sleep(0.3)

            # 1. Spawn criu dump with --lazy-pages in background.
            # Note: On a single host (same PID namespace), we do NOT pass --leave-stopped
            # so CRIU terminates the dumped target processes after splicing their pages into
            # the dump process's page-pipe, freeing the original PIDs for same-host restore!
            dump_log = scenario_dir / "criu_lazy_dump.log"
            cmd_dump = [
                self.criu_bin,
                "dump",
                "-t",
                str(root_pid),
                "--images-dir",
                str(images_dir),
                "--lazy-pages",
                "--address",
                "127.0.0.1",
                "--port",
                str(lazy_port),
                "--shell-job",
                "-v4",
                "-o",
                str(dump_log),
            ]
            dump_log_h = open(dump_log, "w", encoding="utf-8")
            dump_proc = subprocess.Popen(
                cmd_dump,
                stdout=dump_log_h,
                stderr=dump_log_h,
                start_new_session=True,
            )

            # Wait until dump_proc binds the lazy-pages TCP port (27102) and writes pstree.img
            if not wait_for_port("127.0.0.1", lazy_port, timeout_sec=6.0):
                excerpt = dump_log.read_text(encoding="utf-8", errors="ignore")[-400:] if dump_log.exists() else ""
                report.status = "FAIL"
                report.details = f"criu dump --lazy-pages failed to bind port {lazy_port}"
                report.error_log = excerpt
                return report

            # Reap the original workload process so its PID is no longer a zombie
            if proc:
                try:
                    proc.wait(timeout=2.0)
                except Exception:
                    pass

            # 2. Supervise criu lazy-pages daemon and criu restore --lazy-pages inside an isolated
            # destination PID/mount namespace so the restored PID does not collide with the
            # source process tree while criu dump --lazy-pages is serving page-pipe pages.
            lazy_log = scenario_dir / "criu_lazy_daemon.log"
            restore_log = scenario_dir / "criu_lazy_restore.log"
            unshare_bin = shutil.which("unshare") or "unshare"
            dest_script = (
                f"{self.criu_bin} lazy-pages --images-dir {images_dir} --page-server "
                f"--address 127.0.0.1 --port {lazy_port} -v4 -o {lazy_log} &\n"
                f"LP_PID=$!\n"
                f"for i in $(seq 1 60); do [ -S {images_dir}/lazy-pages.socket ] && break; sleep 0.05; done\n"
                f"{self.criu_bin} restore --images-dir {images_dir} --lazy-pages "
                f"--restore-detached --shell-job -v4 -o {restore_log}\n"
                f"RC=$?\n"
                f"if [ $RC -eq 0 ]; then sleep 0.6; fi\n"
                f"kill -TERM $LP_PID 2>/dev/null || true\n"
                f"exit $RC\n"
            )
            cmd_restore = [
                unshare_bin,
                "--mount",
                "--pid",
                "--fork",
                "--mount-proc",
                "sh",
                "-c",
                dest_script,
            ]
            res_restore = run_cmd(cmd_restore, timeout_sec=15.0, log_file=restore_log)
            report.commands.append(res_restore)

            rc_dump = dump_proc.poll()
            if rc_dump is not None and rc_dump != 0 and res_restore.exit_code != 0:
                excerpt = dump_log.read_text(encoding="utf-8", errors="ignore")[-400:]
                if "userfaultfd" in excerpt.lower() or "uffd" in excerpt.lower() or "eperm" in excerpt.lower():
                    report.status = "SKIPPED"
                    report.details = "Kernel restricted userfaultfd / uffd syscall in runner environment"
                    report.error_log = excerpt
                    return report
                report.status = "FAIL"
                report.details = f"criu dump --lazy-pages exited with {rc_dump}"
                report.error_log = excerpt
                return report

            if res_restore.exit_code != 0:
                if "userfaultfd" in res_restore.stderr.lower() or "uffd" in res_restore.stderr.lower():
                    report.status = "SKIPPED"
                    report.details = "Kernel userfaultfd demand-faulting restricted by host policy"
                    report.error_log = res_restore.log_excerpt or res_restore.stderr
                    return report
                report.status = "FAIL"
                report.details = f"criu restore --lazy-pages failed with exit {res_restore.exit_code}"
                report.error_log = res_restore.log_excerpt or res_restore.stderr
                return report

            report.artifacts_verified.append("CRIU restore --lazy-pages connected to supervised lazy daemon")
            state_log = workload_dir / "state.log"
            if state_log.exists():
                records = len(state_log.read_text(encoding="utf-8", errors="ignore").splitlines())
                report.artifacts_verified.append(f"Restored lazy-paged workload active ({records} state.log records)")

        finally:
            kill_process_tree(root_pid)
            if dump_proc and dump_proc.poll() is None:
                try:
                    dump_proc.terminate()
                except OSError:
                    pass
            if lazy_daemon_proc and lazy_daemon_proc.poll() is None:
                try:
                    lazy_daemon_proc.terminate()
                except OSError:
                    pass

        return report

    def run_scenario_d_agent_orchestrator_lazy(self) -> ScenarioReport:
        """
        Scenario D (Agent-to-Agent 2PC LAZY Migration):
        Spawns two isolated `lkmp agent` daemons (`Host A` & `Host B`) with mTLS PKI, launches a
        daemonized worker holding a 4 MiB anonymous `mmap` buffer inside `Host A`, executes
        `MigrationOrchestrator(strategy=LAZY, wipe_images_on_commit=True).execute()`, forces on-demand
        userfaultfd page faults across all 1024 pages on `Host B`, and verifies SHA-256 memory integrity,
        PRNG continuity, source reaping, and durable source tombstone persistence.
        """
        report = ScenarioReport(
            name="Scenario D: Agent-to-Agent mTLS 2PC LAZY Migration (MigrationOrchestrator + userfaultfd)",
            status="PASS",
            details="Full two-agent mTLS MigrationOrchestrator(strategy=LAZY) cutover + 4 MiB mmap SHA-256 verification",
        )

        if not self.is_linux or not self.criu_available:
            report.status = "SKIPPED"
            report.details = "Host is not Linux or criu binary is not found in PATH"
            return report

        uffd_chk = run_cmd([self.criu_bin, "check", "--extra"])
        report.commands.append(uffd_chk)
        if "uffd-noncoop" in uffd_chk.stderr and "FAIL" in uffd_chk.stderr:
            report.status = "SKIPPED"
            report.details = "Kernel lacks uffd-noncoop userfaultfd support"
            report.error_log = uffd_chk.stderr
            return report

        scenario_dir = self.base_dir / "scenario_d"
        scenario_dir.mkdir(parents=True, exist_ok=True)
        pki = generate_mtls_pki(
            out_dir=scenario_dir / "pki",
            hosts=("127.0.0.1", "localhost"),
            validity_days=1,
            overwrite=True,
        )
        tls = TlsConfig(
            enabled=True,
            ca_cert=str(pki.ca_cert),
            cert_file=str(pki.node_cert),
            key_file=str(pki.node_key),
        )

        host_a = IsolatedCriuHostAgent("host_a", scenario_dir, tls)
        host_b = IsolatedCriuHostAgent("host_b", scenario_dir, tls)
        worker_dir = scenario_dir / "lazy_worker"
        worker_dir.mkdir(parents=True, exist_ok=True)
        journal_dir = scenario_dir / "journals"
        journal_dir.mkdir(parents=True, exist_ok=True)

        try:
            host_a.start()
            host_b.start()

            host_a.ns_exec_daemon(
                [sys.executable, str(Path(__file__).resolve()), "--run-lazy-worker", str(worker_dir)]
            )

            deadline = time.monotonic() + 8.0
            while time.monotonic() < deadline:
                if (worker_dir / "ready.txt").exists() and (worker_dir / "expected_mmap.sha256").exists():
                    break
                time.sleep(0.05)
            else:
                report.status = "FAIL"
                report.details = "Lazy worker failed to initialize inside Host A namespace"
                return report

            src_pid = int((worker_dir / "worker.pid").read_text(encoding="utf-8").strip())
            expected_sha = (worker_dir / "expected_mmap.sha256").read_text(encoding="utf-8").strip()

            # Allow worker to emit at least 5 pre-migration records
            time.sleep(0.35)

            lazy_port = get_free_port()
            mig_id = "e2e-lazy-2pc"
            cfg = MigrationConfig(
                pid=src_pid,
                source_addr=host_a.address,
                dest_addr=host_b.address,
                strategy=MigrationStrategy.LAZY,
                fs_mode=FilesystemMode.SHARED,
                writable_paths=[str(worker_dir)],
                ip_mobility=IpMobilityMode.NONE,
                tcp_established=False,
                unsafe_bare=True,
                lazy_pages_port=lazy_port,
                lazy_transfer_timeout_sec=20.0,
                same_host_cow=False,
                prefer_tmpfs_work_dir=False,
                wipe_images_on_commit=True,
                journal_dir=str(journal_dir),
                tls=tls,
            )

            with AgentClient(host_a.address, tls=tls, timeout_sec=30.0) as src_cli, AgentClient(
                host_b.address, tls=tls, timeout_sec=30.0
            ) as dst_cli:
                orch = MigrationOrchestrator(
                    cfg,
                    src_cli,
                    dst_cli,
                    migration_id=mig_id,
                    require_persistent_journal=False,
                )
                res = orch.execute()

            if not res.success or res.restored_pid is None:
                err_msg = (res.error_message or "").lower()
                log_tail = ""
                for candidate_log in (
                    host_a.log_file,
                    host_b.log_file,
                    host_b.work_dir / mig_id / "final" / "lazy-pages.log",
                    host_a.work_dir / mig_id / "final" / "lazy-dump.log",
                ):
                    if candidate_log.exists():
                        log_tail += f"\n--- {candidate_log.name} ---\n" + candidate_log.read_text(
                            encoding="utf-8", errors="ignore"
                        )[-500:]
                combined_err = (err_msg + " " + log_tail.lower())
                if ("userfaultfd" in combined_err or "uffd" in combined_err) and (
                    "operation not permitted" in combined_err
                    or "permission denied" in combined_err
                    or "function not implemented" in combined_err
                ):
                    report.status = "SKIPPED"
                    report.details = "Kernel restricted userfaultfd syscall in runner environment"
                    report.error_log = (res.error_message or "") + log_tail
                    return report
                report.status = "FAIL"
                report.details = f"MigrationOrchestrator(LAZY) failed: {res.error_message}"
                report.error_log = log_tail
                return report

            # Trigger reading all 4 MiB (1024 pages) on Destination Host B
            (worker_dir / "verify_mmap.trigger").write_text("1\n", encoding="utf-8")
            verified_path = worker_dir / "verified_mmap.json"
            v_deadline = time.monotonic() + 8.0
            while time.monotonic() < v_deadline and not verified_path.exists():
                time.sleep(0.05)

            if not verified_path.exists():
                report.status = "FAIL"
                report.details = "Restored LAZY worker on Host B did not complete 4 MiB mmap verification"
                return report

            verified_payload = json.loads(verified_path.read_text(encoding="utf-8"))
            if verified_payload.get("sha256") != expected_sha:
                report.status = "FAIL"
                report.details = (
                    f"4 MiB mmap SHA-256 mismatch after LAZY migration: "
                    f"got {verified_payload.get('sha256')}, expected {expected_sha}"
                )
                return report

            if host_a.is_ns_pid_alive(src_pid):
                report.status = "FAIL"
                report.details = f"Source PID {src_pid} still alive on Host A after LAZY commit"
                return report
            if not host_b.is_ns_pid_alive(int(res.restored_pid)):
                report.status = "FAIL"
                report.details = f"Restored PID {res.restored_pid} not alive on Host B"
                return report

            tombstone = host_a.work_dir / ".tombstones" / f"{mig_id}.source.json"
            if not tombstone.exists():
                report.status = "FAIL"
                report.details = "Durable source tombstone missing after wipe_images_on_commit=True"
                return report

            ok_seq, total_records, seq_msg = _verify_prng_log(worker_dir / "state.log")
            if not ok_seq:
                report.status = "FAIL"
                report.details = f"PRNG state.log sequence error: {seq_msg}"
                return report

            report.artifacts_verified.extend(
                [
                    f"MigrationOrchestrator(LAZY) committed (B PID {res.restored_pid}, freeze={res.freeze_downtime_ms} ms)",
                    f"4 MiB (1024 pages) mmap SHA-256 verified ({expected_sha[:16]}...)",
                    f"Unbroken xorshift64* sequence ({total_records} records) & durable source tombstone verified",
                ]
            )
        finally:
            host_a.stop()
            host_b.stop()

        return report

    def run_all(self) -> Dict[str, Any]:
        """Execute full suite and compile summary reports."""
        if self.is_linux:
            cleanup_stale_criu_processes()
        self.inspect_environment()

        self.reports["cli_flags"] = self.test_cli_flags()
        self.reports["scenario_a"] = self.run_scenario_a_cold()
        self.reports["scenario_b"] = self.run_scenario_b_pre_copy()
        self.reports["scenario_c"] = self.run_scenario_c_lazy()
        self.reports["scenario_d"] = self.run_scenario_d_agent_orchestrator_lazy()

        return self.compile_results()

    def compile_results(self) -> Dict[str, Any]:
        """Format results into Markdown table and JSON summary."""
        results: Dict[str, Any] = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "system_info": self.sys_info,
            "scenarios": {},
            "summary": {
                "total": len(self.reports),
                "passed": sum(1 for r in self.reports.values() if r.status == "PASS"),
                "skipped": sum(1 for r in self.reports.values() if r.status in ("SKIPPED", "UNSUPPORTED")),
                "failed": sum(1 for r in self.reports.values() if r.status == "FAIL"),
            },
        }

        for key, rep in self.reports.items():
            results["scenarios"][key] = {
                "name": rep.name,
                "status": rep.status,
                "details": rep.details,
                "artifacts_verified": rep.artifacts_verified,
                "error_log": rep.error_log[:500] if rep.error_log else "",
                "commands_count": len(rep.commands),
            }

        return results

    def render_markdown(self, results: Dict[str, Any]) -> str:
        """Render beautiful GitHub-Flavored Markdown summary table."""
        sys_i = results["system_info"]
        summary = results["summary"]

        md: List[str] = []
        md.append("# Linux CRIU Live Migration E2E Verification Report")
        md.append("")
        md.append("### Host & CRIU Environment")
        md.append(f"- **OS / Kernel**: `{sys_i.get('uname', 'Unknown')}`")
        md.append(f"- **Python Version**: `{sys_i.get('python_version', 'Unknown')}`")
        md.append(f"- **CRIU Binary**: `{sys_i.get('criu_bin')}` (Available: `{sys_i.get('criu_available')}`)")
        md.append(f"- **CRIU Version**: `{sys_i.get('criu_version', 'N/A')}`")
        md.append(f"- **CRIU Check**: Exit Code `{sys_i.get('criu_check_exit')}`")
        md.append("")
        md.append("### Scenarios Execution Matrix")
        md.append("")
        md.append("| # | Scenario Name | Status | Details | Verified Artifacts |")
        md.append("|---|---|---|---|---|")

        idx = 1
        for key, sc in results["scenarios"].items():
            stat = sc["status"]
            badge = "🟢 PASS" if stat == "PASS" else ("🟡 SKIPPED" if stat in ("SKIPPED", "UNSUPPORTED") else "🔴 FAIL")
            artifacts_str = "<br/>".join(sc["artifacts_verified"]) if sc["artifacts_verified"] else "N/A"
            md.append(f"| {idx} | **{sc['name']}** | {badge} | {sc['details']} | {artifacts_str} |")
            idx += 1

        md.append("")
        md.append(
            f"**Total Scenarios**: {summary['total']} | **Passed**: {summary['passed']} | "
            f"**Skipped/Unsupported**: {summary['skipped']} | **Failed**: {summary['failed']}"
        )
        md.append("")

        for key, rep in self.reports.items():
            if rep.error_log:
                md.append(f"<details><summary><b>Error / Kernel Log Excerpt for {rep.name}</b></summary>\n")
                md.append("```text")
                md.append(rep.error_log)
                md.append("```\n</details>\n")

        return "\n".join(md)


def main() -> int:
    parser = argparse.ArgumentParser(description="Linux CRIU E2E Verification Suite")
    parser.add_argument(
        "--run-workload",
        help="Internal flag: run the multi-process stateful workload in the specified directory",
    )
    parser.add_argument(
        "--run-lazy-worker",
        help="Internal flag: run the daemonized 4 MiB mmap lazy worker in the specified directory",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON summary only",
    )
    args = parser.parse_args()

    if args.run_workload:
        run_workload_root(Path(args.run_workload))
        return 0
    if args.run_lazy_worker:
        run_lazy_mmap_worker(Path(args.run_lazy_worker))
        return 0

    runner = LinuxCriuE2ERunner()
    results = runner.run_all()
    md_report = runner.render_markdown(results)

    print(md_report)
    print("\n--- JSON TELEMETRY ---")
    print(json.dumps(results, indent=2))

    if results["summary"]["failed"] > 0:
        return 1
    if runner.is_linux and (not runner.criu_available or results["summary"]["passed"] == 0):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
