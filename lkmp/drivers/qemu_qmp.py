"""QEMU/KVM & TCG Zero-Copy Live Migration Driver (`QemuQmpDriver`) via QMP."""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from lkmp.config import MigrationConfig, MigrationStrategy, TlsConfig
from lkmp.drivers.detector import WorkloadKind, detect_workload_profile, read_proc_starttime
from lkmp.logging_utils import get_logger
from lkmp.network import parse_host_port

logger = get_logger("drivers.qemu")


class QmpError(RuntimeError):
    """Raised when a QEMU Machine Protocol (QMP) command returns an error or fails."""


class QmpClient:
    """
    Lightweight, zero-dependency QEMU Machine Protocol (QMP) client supporting
    UNIX domain sockets (`/path/to/qmp.sock` or `unix:/path/to/qmp.sock`) and TCP (`tcp:host:port`).
    Automatically handles QMP greeting negotiation and skips interleaved async `event` frames.
    """

    def __init__(self, endpoint: str, timeout_sec: float = 10.0) -> None:
        self.endpoint = endpoint.strip()
        self.timeout_sec = timeout_sec
        self._sock: Optional[socket.socket] = None
        self._rfile: Any = None
        self.greeting: Optional[Dict[str, Any]] = None

    def _connect_socket(self) -> socket.socket:
        ep = self.endpoint
        if ep.startswith("tcp:"):
            addr_part = ep[4:].split(",", 1)[0]
            host, port = parse_host_port(addr_part, default_port=4444)
            sock = socket.create_connection((host, port), timeout=self.timeout_sec)
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass
            return sock

        sock_path = ep[5:] if ep.startswith("unix:") else ep
        sock_path = sock_path.split(",", 1)[0]
        af_unix = getattr(socket, "AF_UNIX", None)
        if af_unix is None:
            raise QmpError("AF_UNIX sockets are not supported on this platform")
        sock = socket.socket(af_unix, socket.SOCK_STREAM)
        sock.settimeout(self.timeout_sec)
        sock.connect(sock_path)
        return sock

    def connect(self) -> Dict[str, Any]:
        if self._sock is not None:
            return self.greeting or {}
        sock = self._connect_socket()
        rfile = sock.makefile("rb")
        raw_greeting = rfile.readline(1024 * 1024)
        if not raw_greeting:
            sock.close()
            raise QmpError(f"Empty QMP greeting from {self.endpoint}")
        self.greeting = json.loads(raw_greeting.decode("utf-8"))
        self._sock = sock
        self._rfile = rfile
        self.execute("qmp_capabilities")
        return self.greeting

    def execute(self, command: str, arguments: Optional[Dict[str, Any]] = None) -> Any:
        if self._sock is None and command != "qmp_capabilities":
            self.connect()
        assert self._sock is not None and self._rfile is not None

        req: Dict[str, Any] = {"execute": command}
        if arguments is not None:
            req["arguments"] = arguments
        payload = (json.dumps(req) + "\n").encode("utf-8")
        self._sock.sendall(payload)

        while True:
            line = self._rfile.readline(4 * 1024 * 1024)
            if not line:
                raise QmpError(f"Connection closed by QEMU during QMP command {command!r}")
            msg = json.loads(line.decode("utf-8"))
            if "event" in msg:
                logger.debug("QMP async event on %s: %s", self.endpoint, msg.get("event"))
                continue
            if "error" in msg:
                err_obj = msg["error"]
                desc = err_obj.get("desc", str(err_obj)) if isinstance(err_obj, dict) else str(err_obj)
                raise QmpError(f"QMP command {command!r} failed: {desc}")
            if "return" in msg:
                return msg["return"]

    def close(self) -> None:
        if self._rfile is not None:
            try:
                self._rfile.close()
            except Exception:
                pass
            self._rfile = None
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def __enter__(self) -> QmpClient:
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()


def qmp_call(
    endpoint: str,
    command: str,
    arguments: Optional[Dict[str, Any]] = None,
    timeout_sec: float = 10.0,
) -> Any:
    """Execute a single QMP command over `endpoint` and close cleanly."""
    with QmpClient(endpoint, timeout_sec=timeout_sec) as client:
        return client.execute(command, arguments)


def build_standby_qemu_cmdline(
    source_cmdline: List[str],
    dest_qmp_sock: str | Path,
    dest_pidfile: str | Path,
) -> List[str]:
    """
    Transform Source A's `qemu-system-*` argv into a Destination B standby receiver argv:
    - Strips source-specific `-qmp`, `-qmp-pretty`, `-pidfile`, `-daemonize`, `-incoming`, `-S`,
      and QMP `-mon`/`-chardev` pairs to prevent socket collisions on shared/same-host filesystems.
    - Injects `-S` (hold guest vCPUs paused after incoming load for 2PC verification!),
      `-incoming defer`, `-daemonize`, `-pidfile <dest_pidfile>`, and `-qmp unix:<dest_qmp_sock>,server=on,wait=off`.
    """
    if not source_cmdline:
        raise ValueError("Cannot construct standby QEMU command from empty source_cmdline")

    filtered: List[str] = [source_cmdline[0]]
    qmp_chardev_ids = set()

    # Pass 1: find chardev IDs attached to control monitors
    idx = 1
    while idx < len(source_cmdline):
        arg = source_cmdline[idx]
        nxt = source_cmdline[idx + 1] if idx + 1 < len(source_cmdline) else ""
        if arg == "-mon" and nxt:
            kv = dict(item.split("=", 1) for item in nxt.split(",") if "=" in item)
            if kv.get("mode") == "control" and "chardev" in kv:
                qmp_chardev_ids.add(kv["chardev"])
            idx += 2
            continue
        idx += 1

    # Pass 2: rebuild clean hardware/guest argv
    i = 1
    while i < len(source_cmdline):
        arg = source_cmdline[i]
        nxt = source_cmdline[i + 1] if i + 1 < len(source_cmdline) else ""

        if arg in ("-daemonize", "-S"):
            i += 1
            continue
        if arg in ("-qmp", "-qmp-pretty", "-pidfile", "-incoming"):
            i += 2
            continue
        if arg == "-mon" and nxt:
            kv = dict(item.split("=", 1) for item in nxt.split(",") if "=" in item)
            if kv.get("mode") == "control" or kv.get("chardev") in qmp_chardev_ids:
                i += 2
                continue
        if arg == "-chardev" and nxt:
            kv = dict(item.split("=", 1) for item in nxt.split(",") if "=" in item)
            if kv.get("id") in qmp_chardev_ids or "qmp" in (kv.get("id") or "").lower():
                i += 2
                continue

        filtered.append(arg)
        i += 1

    filtered.extend(
        [
            "-S",
            "-incoming",
            "defer",
            "-daemonize",
            "-pidfile",
            str(dest_pidfile),
            "-qmp",
            f"unix:{dest_qmp_sock},server=on,wait=off",
        ]
    )
    return filtered


def build_migratable_qemu_command(
    workload_id: str,
    qmp_sock_dir: str | Path = "/tmp/lkmp-qmp",
    qmp_socket: Optional[str] = None,
    qemu_bin: str = "qemu-system-x86_64",
    memory_mb: int = 512,
    vcpus: int = 2,
    disk_path: Optional[str] = None,
    accel: str = "kvm:tcg",
    cpu_model: str = "max",
    extra_args: Optional[List[str]] = None,
) -> Tuple[List[str], str]:
    """
    Generate an out-of-the-box zero-copy live-migratable QEMU launch command (`lkmp run --profile qemu`):
    - Shared `memory-backend-memfd` (`share=on`) enabling `MSG_ZEROCOPY` (`zero-copy-send`)
    - Deterministic QMP control socket
    - Migratable CPU baseline
    """
    if qmp_socket:
        qmp_path = str(qmp_socket)
    else:
        sock_root = Path(qmp_sock_dir)
        sock_root.mkdir(parents=True, exist_ok=True)
        qmp_path = str(sock_root / f"{workload_id}.qmp")
    accel_flags: List[str] = []
    for acc in [a.strip() for a in accel.split(":") if a.strip()]:
        accel_flags.extend(["-accel", acc])

    cmd = [
        qemu_bin,
        "-name",
        workload_id,
        *accel_flags,
        "-cpu",
        cpu_model,
        "-smp",
        str(vcpus),
        "-m",
        f"{memory_mb}M",
        "-object",
        f"memory-backend-memfd,id=mem0,size={memory_mb}M,share=on",
        "-numa",
        "node,memdev=mem0",
        "-display",
        "none",
        "-no-user-config",
        "-nodefaults",
        "-qmp",
        f"unix:{qmp_path},server=on,wait=off",
    ]
    if disk_path:
        fmt = "qcow2" if disk_path.endswith(".qcow2") else "raw"
        cmd.extend(
            [
                "-drive",
                f"file={disk_path},if=virtio,format={fmt},cache=none",
            ]
        )
    if extra_args:
        cmd.extend(extra_args)
    return cmd, qmp_path


class QemuQmpDriver:
    """
    2PC-compliant QEMU/KVM & TCG Live Migration Driver using QMP:
    - Standby QEMU on Destination B runs with `-S -incoming defer` + `late-block-activate=true`.
    - Iterative Pre-Copy uses `pause-before-switchover=true` + optional `multifd` & `zero-copy-send`.
    - At `FREEZE`/`FINAL_DUMP`, QEMU reaches `pre-switchover` -> flushes final `<2 ms` `vmstate`
      so Source A lands in `postmigrate` (alive & paused) and Destination B lands in `paused`
      with 100% state loaded and block locks deferred!
    - `COMMIT` resumes Destination B via QMP `cont` and quits Source A.
    - `ROLLBACK` terminates standby Destination B and resumes Source A via QMP `cont` with zero guest loss.
    """

    kind = WorkloadKind.QEMU_VM

    def __init__(
        self,
        proc_root: str = "/proc",
        qmp_caller: Optional[Callable[[str, str, Optional[Dict[str, Any]]], Any]] = None,
        spawner: Optional[Callable[[List[str]], subprocess.CompletedProcess]] = None,
        signal_sender: Optional[Callable[[int, int], None]] = None,
    ) -> None:
        self.proc_root = proc_root
        self._qmp_call = qmp_caller or self._default_qmp_call
        self._spawn = spawner or self._default_spawn
        if signal_sender is not None:
            self._send_signal: Callable[[int, int], None] = signal_sender
        elif self.proc_root == "/proc":
            self._send_signal = os.kill
        else:
            self._send_signal = lambda _pid, _sig: None
        self._started_migrations: set[str] = set()

    @staticmethod
    def _default_qmp_call(
        endpoint: str,
        command: str,
        arguments: Optional[Dict[str, Any]] = None,
    ) -> Any:
        return qmp_call(endpoint, command, arguments, timeout_sec=15.0)

    @staticmethod
    def _default_spawn(cmd: List[str]) -> subprocess.CompletedProcess:
        return subprocess.run(cmd, check=True, text=True, capture_output=True)

    @staticmethod
    def _dest_paths(mig_dir: Path) -> Tuple[Path, Path, Path]:
        final_dir = mig_dir / "final"
        final_dir.mkdir(parents=True, exist_ok=True)
        # Keep UNIX socket path short (< 104 bytes sun_path limit on Linux/macOS)!
        short_hash = mig_dir.name[-24:]
        short_sock = Path("/tmp") / f"lkmp-qmp-{short_hash}.sock"
        pidfile = final_dir / "dest-qemu.pid"
        state_file = final_dir / "restore_state.json"
        return short_sock, pidfile, state_file

    def _resolve_source_qmp_and_cmdline(
        self,
        config: MigrationConfig,
    ) -> Tuple[str, List[str]]:
        meta = dict(config.runtime_metadata or {})
        qmp_ep = meta.get("qmp_socket")
        qemu_cmd = meta.get("qemu_cmdline")
        if not qmp_ep or not qemu_cmd:
            prof = detect_workload_profile(config.pid, proc_root=self.proc_root)
            qmp_ep = qmp_ep or prof.control_socket
            qemu_cmd = qemu_cmd or prof.cmdline
        if not qmp_ep:
            raise QmpError(
                f"QEMU PID {config.pid} has no QMP socket; pass `-qmp unix:/path/qmp.sock,server=on,wait=off`"
            )
        if not qemu_cmd:
            raise QmpError(f"Unable to determine QEMU command line for PID {config.pid}")
        return str(qmp_ep), list(qemu_cmd)

    def _supported_caps(self, qmp_ep: str) -> set[str]:
        try:
            raw = self._qmp_call(qmp_ep, "query-migrate-capabilities", None)
            if isinstance(raw, list):
                return {str(item.get("capability")) for item in raw if isinstance(item, dict)}
        except Exception as exc:
            logger.debug("query-migrate-capabilities failed on %s: %s", qmp_ep, exc)
        return {"pause-before-switchover", "late-block-activate", "auto-converge"}

    def _configure_caps(
        self,
        qmp_ep: str,
        *,
        is_source: bool,
        multifd_channels: int,
        enable_zero_copy: bool,
        enable_postcopy: bool,
    ) -> List[str]:
        supported = self._supported_caps(qmp_ep)
        desired: List[Dict[str, Any]] = []
        enabled_names: List[str] = []

        def _want(cap_name: str, state: bool = True) -> None:
            if cap_name in supported:
                desired.append({"capability": cap_name, "state": state})
                if state:
                    enabled_names.append(cap_name)

        _want("late-block-activate", True)
        if is_source:
            _want("pause-before-switchover", True)
            _want("auto-converge", True)
        if multifd_channels > 1:
            _want("multifd", True)
            if is_source and enable_zero_copy:
                _want("zero-copy-send", True)
        if enable_postcopy:
            _want("postcopy-ram", True)

        if desired:
            self._qmp_call(qmp_ep, "migrate-set-capabilities", {"capabilities": desired})

        params: Dict[str, Any] = {}
        if multifd_channels > 1 and "multifd" in enabled_names:
            params["multifd-channels"] = int(multifd_channels)
        if is_source:
            params["downtime-limit"] = max(5, int(config_downtime := 25))
            _ = config_downtime
        if params:
            try:
                self._qmp_call(qmp_ep, "migrate-set-parameters", params)
            except Exception as exc:
                logger.debug("migrate-set-parameters partial support on %s: %s", qmp_ep, exc)
        return enabled_names

    @staticmethod
    def _write_restricted_file(src: Path, dst: Path) -> None:
        raw = src.read_bytes()
        fd = os.open(str(dst), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            offset = 0
            while offset < len(raw):
                written = os.write(fd, raw[offset:])
                if written <= 0:
                    raise OSError("Short write staging QEMU TLS credential")
                offset += written
        finally:
            os.close(fd)

    def _configure_tls_creds(
        self,
        qmp_ep: str,
        mig_dir: Path,
        tls: TlsConfig,
        *,
        is_source: bool,
    ) -> Optional[Path]:
        """
        Configure QEMU native `tls-creds-x509` over QMP when `tls.enabled=True`.
        Fails closed (raises `QmpError`) if certificate files are missing or if QEMU
        rejects `tls-creds-x509`, preventing silent fallback to plaintext RAM streaming.
        """
        if not tls.enabled:
            try:
                self._qmp_call(qmp_ep, "migrate-set-parameters", {"tls-creds": ""})
            except Exception:
                pass
            return None

        if not tls.ca_cert or not tls.cert_file or not tls.key_file:
            raise QmpError(
                "TLS is enabled for QEMU migration, but ca_cert, cert_file, or key_file is missing. "
                "Refusing plaintext QEMU RAM stream; supply X.509 credentials or explicitly disable TLS."
            )
        ca_p = Path(tls.ca_cert)
        cert_p = Path(tls.cert_file)
        key_p = Path(tls.key_file)
        for p in (ca_p, cert_p, key_p):
            if not p.is_file():
                raise QmpError(f"QEMU TLS credential file does not exist: {p}")

        role = "client" if is_source else "server"
        tls_dir = mig_dir / f"qemu_tls_{role}"
        tls_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(tls_dir, 0o700)
        except OSError:
            pass

        self._write_restricted_file(ca_p, tls_dir / "ca-cert.pem")
        self._write_restricted_file(cert_p, tls_dir / f"{role}-cert.pem")
        self._write_restricted_file(key_p, tls_dir / f"{role}-key.pem")

        try:
            self._qmp_call(qmp_ep, "object-del", {"id": "lkmp_tls0"})
        except Exception:
            pass

        self._qmp_call(
            qmp_ep,
            "object-add",
            {
                "qom-type": "tls-creds-x509",
                "id": "lkmp_tls0",
                "dir": str(tls_dir),
                "endpoint": role,
                "verify-peer": not bool(tls.no_verify),
            },
        )
        self._qmp_call(qmp_ep, "migrate-set-parameters", {"tls-creds": "lkmp_tls0"})
        return tls_dir

    def _cleanup_tls_dirs(self, mig_dir: Path) -> None:
        for role in ("client", "server"):
            tdir = mig_dir / f"qemu_tls_{role}"
            if tdir.exists():
                shutil.rmtree(tdir, ignore_errors=True)

    def _ensure_standby_started(
        self,
        migration_id: str,
        mig_dir: Path,
        config: MigrationConfig,
    ) -> Tuple[int, Path]:
        dest_sock, dest_pidfile, state_file = self._dest_paths(mig_dir)
        if dest_pidfile.exists() and dest_sock.exists():
            try:
                existing_pid = int(dest_pidfile.read_text(encoding="utf-8").strip())
                st = self._qmp_call(str(dest_sock), "query-status", None)
                if isinstance(st, dict):
                    return existing_pid, dest_sock
            except Exception:
                pass

        if dest_sock.exists():
            try:
                dest_sock.unlink()
            except OSError:
                pass

        meta = dict(config.runtime_metadata or {})
        src_cmd = meta.get("qemu_cmdline")
        if not src_cmd:
            raise QmpError("Destination standby launch requires `runtime_metadata['qemu_cmdline']`")

        standby_cmd = build_standby_qemu_cmdline(list(src_cmd), dest_sock, dest_pidfile)
        self._spawn(standby_cmd)

        # Wait up to 5s for standby QEMU QMP socket and pidfile
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if dest_pidfile.exists() and dest_sock.exists():
                try:
                    st = self._qmp_call(str(dest_sock), "query-status", None)
                    if isinstance(st, dict):
                        break
                except Exception:
                    pass
            time.sleep(0.02)

        if not dest_pidfile.exists():
            raise QmpError(f"Standby QEMU did not write pidfile {dest_pidfile}")
        standby_pid = int(dest_pidfile.read_text(encoding="utf-8").strip())

        try:
            multifd = int(meta.get("qemu_multifd_channels", config.qemu_multifd_channels))
            enable_postcopy = config.strategy in (MigrationStrategy.LAZY, MigrationStrategy.HYBRID)
            self._configure_caps(
                str(dest_sock),
                is_source=False,
                multifd_channels=multifd,
                enable_zero_copy=False,
                enable_postcopy=enable_postcopy,
            )
            self._configure_tls_creds(str(dest_sock), mig_dir, config.tls, is_source=False)
            uri = f"tcp:0.0.0.0:{config.page_server_port}"
            self._qmp_call(str(dest_sock), "migrate-incoming", {"uri": uri})
        except Exception:
            try:
                self._qmp_call(str(dest_sock), "quit", None)
            except Exception:
                pass
            try:
                self._send_signal(standby_pid, signal.SIGKILL)
            except OSError:
                pass
            self._cleanup_tls_dirs(mig_dir)
            raise

        starttime = read_proc_starttime(standby_pid, self.proc_root)
        restore_state = {
            "driver": WorkloadKind.QEMU_VM.value,
            "restored_pid": standby_pid,
            "tree_pids": [standby_pid],
            "starttimes": {str(standby_pid): starttime},
            "dest_qmp_socket": str(dest_sock),
            "workload_ip": config.workload_ip,
            "tcp_established": config.tcp_established,
            "resumed": False,
        }
        state_file.write_text(json.dumps(restore_state, indent=2), encoding="utf-8")
        return standby_pid, dest_sock

    def prepare_dest(
        self,
        migration_id: str,
        mig_dir: Path,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        meta = dict(config.runtime_metadata or {})
        if meta.get("qemu_cmdline"):
            pid, sock = self._ensure_standby_started(migration_id, mig_dir, config)
            return {"standby_pid": pid, "dest_qmp_socket": str(sock)}
        return {"standby_deferred": True}

    def start_pre_copy_target(
        self,
        migration_id: str,
        mig_dir: Path,
        round_name: str,
        prev_round_name: Optional[str],
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = (round_name, prev_round_name)
        pid, sock = self._ensure_standby_started(migration_id, mig_dir, config)
        return {"standby_pid": pid, "dest_qmp_socket": str(sock), "round": round_name}

    def _ensure_source_migration_started(
        self,
        migration_id: str,
        mig_dir: Path,
        qmp_ep: str,
        dest_host: str,
        config: MigrationConfig,
    ) -> List[str]:
        mig_info = self._qmp_call(qmp_ep, "query-migrate", None) or {}
        status = str(mig_info.get("status", ""))
        if status in ("setup", "active", "pre-switchover", "device", "postcopy-active"):
            self._started_migrations.add(migration_id)
            return []
        if status == "completed" and migration_id in self._started_migrations:
            return []

        clean_host = dest_host[1:-1] if dest_host.startswith("[") and dest_host.endswith("]") else dest_host
        uri_host = f"[{clean_host}]" if ":" in clean_host else clean_host
        uri = f"tcp:{uri_host}:{config.page_server_port}"
        multifd = int(config.qemu_multifd_channels)
        enable_postcopy = config.strategy in (MigrationStrategy.LAZY, MigrationStrategy.HYBRID)
        # QEMU kernel MSG_ZEROCOPY (`zero-copy-send`) is mutually exclusive with userspace GnuTLS (`tls-creds`)
        enable_zero_copy = bool(config.qemu_zero_copy_send) and not bool(config.tls.enabled)

        caps = self._configure_caps(
            qmp_ep,
            is_source=True,
            multifd_channels=multifd,
            enable_zero_copy=enable_zero_copy,
            enable_postcopy=enable_postcopy,
        )
        self._configure_tls_creds(qmp_ep, mig_dir, config.tls, is_source=True)
        try:
            self._qmp_call(qmp_ep, "migrate", {"uri": uri})
        except QmpError as exc:
            if not config.tls.enabled and ("zero-copy" in str(exc).lower() or "memlock" in str(exc).lower()):
                logger.warning("QMP zero-copy-send unavailable (%s); retrying standard multifd stream", exc)
                self._qmp_call(
                    qmp_ep,
                    "migrate-set-capabilities",
                    {"capabilities": [{"capability": "zero-copy-send", "state": False}]},
                )
                self._qmp_call(qmp_ep, "migrate", {"uri": uri})
            else:
                raise
        self._started_migrations.add(migration_id)
        return caps

    def run_pre_copy_source(
        self,
        migration_id: str,
        mig_dir: Path,
        round_name: str,
        prev_round_name: Optional[str],
        dest_host: str,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = prev_round_name
        t0 = time.monotonic()
        qmp_ep, _cmdline = self._resolve_source_qmp_and_cmdline(config)
        self._ensure_source_migration_started(migration_id, mig_dir, qmp_ep, dest_host, config)

        # Sample QEMU background RAM streaming progress up to 150ms or until `pre-switchover`
        deadline = time.monotonic() + 0.15
        remaining_bytes = 0
        while True:
            info = self._qmp_call(qmp_ep, "query-migrate", None) or {}
            status = str(info.get("status", ""))
            ram = info.get("ram") or {}
            remaining_bytes = int(ram.get("remaining", 0))
            if status in ("pre-switchover", "completed"):
                remaining_bytes = 0
                break
            if status in ("failed", "cancelled"):
                err_desc = info.get("error-desc", f"QMP migration status={status}")
                raise QmpError(f"QEMU pre-copy failed: {err_desc}")
            if time.monotonic() >= deadline:
                break
            time.sleep(0.02)

        duration_ms = (time.monotonic() - t0) * 1000.0
        return {
            "dirty_bytes": remaining_bytes,
            "duration_ms": round(duration_ms, 2),
            "round": round_name,
        }

    def freeze_and_dump_source(
        self,
        migration_id: str,
        mig_dir: Path,
        prev_round_name: Optional[str],
        dest_host: str,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = (migration_id, prev_round_name)
        qmp_ep, cmdline = self._resolve_source_qmp_and_cmdline(config)
        starttime = read_proc_starttime(config.pid, self.proc_root)
        source_state = {
            "driver": WorkloadKind.QEMU_VM.value,
            "pid": config.pid,
            "tree_pids": [config.pid],
            "starttimes": {str(config.pid): starttime},
            "qmp_socket": qmp_ep,
            "qemu_cmdline": cmdline,
            "committed": False,
        }
        (mig_dir / "source_state.json").write_text(json.dumps(source_state, indent=2), encoding="utf-8")

        if config.strategy == MigrationStrategy.COLD:
            self._qmp_call(qmp_ep, "stop", None)

        self._ensure_source_migration_started(migration_id, mig_dir, qmp_ep, dest_host, config)

        # Phase A: Wait until QEMU reaches `pre-switchover` (or `completed` if pause-before-switchover unsupported)
        deadline = time.monotonic() + 30.0
        status = ""
        while time.monotonic() < deadline:
            info = self._qmp_call(qmp_ep, "query-migrate", None) or {}
            status = str(info.get("status", ""))
            if status == "pre-switchover":
                # Flush final `<2ms` vmstate + tail dirty pages into Destination B's `-S` paused VM!
                self._qmp_call(qmp_ep, "migrate-continue", {"state": "pre-switchover"})
            elif status == "completed":
                break
            elif status in ("failed", "cancelled"):
                err_desc = info.get("error-desc", f"QMP migration status={status}")
                raise QmpError(f"QEMU final switchover stream failed: {err_desc}")
            elif (
                status == "active"
                and config.strategy in (MigrationStrategy.LAZY, MigrationStrategy.HYBRID)
            ):
                try:
                    self._qmp_call(qmp_ep, "migrate-start-postcopy", None)
                except Exception:
                    pass
            time.sleep(0.01)

        if status != "completed":
            raise QmpError(f"Timed out waiting for QEMU migration completion (last status={status!r})")

        final_info = self._qmp_call(qmp_ep, "query-migrate", None) or {}
        return {
            "images_dir": str(mig_dir / "final"),
            "qemu_downtime_ms": final_info.get("downtime", 0),
            "driver": WorkloadKind.QEMU_VM.value,
        }

    def restore_stopped_dest(
        self,
        migration_id: str,
        mig_dir: Path,
        source_host: str,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = source_host
        standby_pid, dest_sock = self._ensure_standby_started(migration_id, mig_dir, config)

        # Confirm Destination QEMU finished receiving incoming stream and sits in `paused` (`-S`)!
        deadline = time.monotonic() + 10.0
        last_status: Dict[str, Any] = {}
        while time.monotonic() < deadline:
            last_status = self._qmp_call(str(dest_sock), "query-status", None) or {}
            if last_status.get("status") == "paused" and last_status.get("running") is False:
                break
            time.sleep(0.01)

        if last_status.get("status") != "paused":
            raise QmpError(
                f"Destination QEMU did not reach 2PC `paused` barrier (status={last_status})"
            )

        starttime = read_proc_starttime(standby_pid, self.proc_root)
        return {
            "restored_pid": standby_pid,
            "restored_starttime": starttime,
            "dest_qmp_socket": str(dest_sock),
            "driver": WorkloadKind.QEMU_VM.value,
        }

    def verify_stopped_dest(
        self,
        migration_id: str,
        mig_dir: Path,
        restored_pid: int,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = (migration_id, config)
        dest_sock, _pidfile, state_file = self._dest_paths(mig_dir)
        if state_file.exists():
            try:
                data = json.loads(state_file.read_text(encoding="utf-8"))
                if data.get("dest_qmp_socket"):
                    dest_sock = Path(data["dest_qmp_socket"])
            except Exception:
                pass
        st = self._qmp_call(str(dest_sock), "query-status", None) or {}
        if st.get("running") is not False or st.get("status") not in ("paused", "inmigrate"):
            return {
                "healthy": False,
                "reason": f"Destination QEMU PID {restored_pid} is not paused at 2PC barrier: {st}",
            }
        return {
            "healthy": True,
            "checked_pids": [restored_pid],
            "stopped_confirmed": True,
            "qemu_status": st.get("status"),
        }

    def verify_running_dest(
        self,
        migration_id: str,
        mig_dir: Path,
        restored_pid: int,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = (migration_id, config)
        dest_sock, _pidfile, state_file = self._dest_paths(mig_dir)
        if state_file.exists():
            try:
                data = json.loads(state_file.read_text(encoding="utf-8"))
                if data.get("dest_qmp_socket"):
                    dest_sock = Path(data["dest_qmp_socket"])
            except Exception:
                pass
        try:
            st = self._qmp_call(str(dest_sock), "query-status", None) or {}
        except Exception as exc:
            return {
                "healthy": False,
                "reason": f"Unable to query QMP status on destination QEMU PID {restored_pid}: {exc}",
            }
        if st.get("running") is True:
            return {
                "healthy": True,
                "checked_pids": [restored_pid],
                "qemu_status": st.get("status", "running"),
            }
        status_name = str(st.get("status") or "")
        if st.get("running") is False and status_name in ("paused", "inmigrate", "prelaunch", "restore-vm"):
            return {
                "healthy": False,
                "still_stopped": True,
                "reason": f"Destination QEMU PID {restored_pid} is still paused ({st})",
            }
        return {
            "healthy": False,
            "reason": f"Destination QEMU PID {restored_pid} is not running: {st}",
        }

    def resume_dest(
        self,
        migration_id: str,
        mig_dir: Path,
        restored_pid: int,
        target_host: str,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = (migration_id, target_host, config)
        dest_sock, _pidfile, state_file = self._dest_paths(mig_dir)
        state_data: Dict[str, Any] = {}
        if state_file.exists():
            try:
                state_data = json.loads(state_file.read_text(encoding="utf-8"))
                if state_data.get("dest_qmp_socket"):
                    dest_sock = Path(state_data["dest_qmp_socket"])
            except Exception:
                state_data = {}
        cur_st = self._qmp_call(str(dest_sock), "query-status", None) or {}
        if not cur_st.get("running", False):
            self._qmp_call(str(dest_sock), "cont", None)
            cur_st = self._qmp_call(str(dest_sock), "query-status", None) or {}
        if not cur_st.get("running", False):
            raise QmpError(f"Destination QEMU PID {restored_pid} failed to resume after QMP `cont`: {cur_st}")
        if state_file.exists():
            try:
                state_data["resumed"] = True
                state_file.write_text(json.dumps(state_data, indent=2), encoding="utf-8")
            except Exception:
                pass
        self._cleanup_tls_dirs(mig_dir)
        return {"resumed_pid": restored_pid, "qemu_status": cur_st.get("status")}

    def commit_source(
        self,
        migration_id: str,
        mig_dir: Path,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        self._started_migrations.discard(migration_id)
        src_state_file = mig_dir / "source_state.json"
        qmp_ep: Optional[str] = None
        exp_st: Optional[int] = None
        if src_state_file.exists():
            try:
                data = json.loads(src_state_file.read_text(encoding="utf-8"))
                qmp_ep = data.get("qmp_socket")
                raw_st = data.get("starttimes") or {}
                exp_st = raw_st.get(str(config.pid))
            except Exception:
                pass
        if exp_st is None and (config.runtime_metadata or {}).get("source_starttime") is not None:
            exp_st = int(config.runtime_metadata["source_starttime"])

        pid_reused = False
        if exp_st is not None:
            curr_st = read_proc_starttime(config.pid, self.proc_root)
            if curr_st is not None and curr_st != exp_st:
                pid_reused = True

        if qmp_ep and not pid_reused:
            try:
                self._qmp_call(qmp_ep, "quit", None)
            except Exception:
                pass
        if not pid_reused:
            try:
                self._send_signal(config.pid, signal.SIGKILL)
            except OSError:
                pass
            if self.proc_root == "/proc" and self._send_signal is os.kill:
                stat_path = Path(f"/proc/{config.pid}/stat")
                deadline = time.monotonic() + 1.0
                while time.monotonic() < deadline:
                    try:
                        raw_stat = stat_path.read_text(encoding="utf-8", errors="ignore")
                    except OSError:
                        break
                    rparen = raw_stat.rfind(")")
                    if rparen == -1:
                        break
                    fields = raw_stat[rparen + 1 :].strip().split()
                    if not fields or fields[0] in ("Z", "X", "x"):
                        break
                    if exp_st is not None and len(fields) >= 20:
                        try:
                            if int(fields[19]) != exp_st:
                                break
                        except ValueError:
                            pass
                    time.sleep(0.005)
        self._cleanup_tls_dirs(mig_dir)
        return {"committed": True, "driver": WorkloadKind.QEMU_VM.value}

    def rollback_dest(
        self,
        migration_id: str,
        mig_dir: Path,
        restored_pid: Optional[int],
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = (migration_id, config)
        dest_sock, dest_pidfile, state_file = self._dest_paths(mig_dir)
        exp_st: Optional[int] = None
        if state_file.exists():
            try:
                st_data = json.loads(state_file.read_text(encoding="utf-8"))
                if restored_pid is not None:
                    exp_st = (st_data.get("starttimes") or {}).get(str(restored_pid))
            except Exception:
                pass
        if dest_sock.exists():
            try:
                self._qmp_call(str(dest_sock), "quit", None)
            except Exception:
                pass
        target_pid = restored_pid
        if target_pid is None and dest_pidfile.exists():
            try:
                target_pid = int(dest_pidfile.read_text(encoding="utf-8").strip())
            except Exception:
                target_pid = None
        if target_pid is not None:
            curr_st = read_proc_starttime(int(target_pid), self.proc_root)
            if exp_st is None or curr_st is None or curr_st == exp_st:
                try:
                    self._send_signal(int(target_pid), signal.SIGKILL)
                except OSError:
                    pass
        if dest_sock.exists():
            try:
                dest_sock.unlink()
            except OSError:
                pass
        self._cleanup_tls_dirs(mig_dir)
        return {"rolled_back_dest": True, "errors": []}

    def rollback_source(
        self,
        migration_id: str,
        mig_dir: Path,
        source_host: str,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = source_host
        self._started_migrations.discard(migration_id)
        src_state_file = mig_dir / "source_state.json"
        qmp_ep: Optional[str] = None
        if src_state_file.exists():
            try:
                data = json.loads(src_state_file.read_text(encoding="utf-8"))
                qmp_ep = data.get("qmp_socket")
            except Exception:
                pass
        if not qmp_ep:
            qmp_ep, _ = self._resolve_source_qmp_and_cmdline(config)

        try:
            self._qmp_call(qmp_ep, "migrate_cancel", None)
        except Exception:
            pass
        self._qmp_call(qmp_ep, "cont", None)
        st = self._qmp_call(qmp_ep, "query-status", None) or {}
        if not st.get("running", False):
            raise QmpError(f"Source QEMU PID {config.pid} did not resume on rollback: {st}")
        return {"rolled_back_source": True, "resumed_pid": config.pid, "qemu_status": st.get("status")}
