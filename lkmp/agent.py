"""Privileged LKMP host agent (`lkmp-agent`) and JSON-RPC over mTLS client/server."""

from __future__ import annotations

import base64
import dataclasses
import errno
import json
import os
import secrets
import shlex
import shutil
import signal
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from lkmp.attestation import CheckpointAttestor, compute_directory_img_digests
from lkmp.config import (
    FilesystemMode,
    GpuPlugin,
    IpMobilityMode,
    MigrationConfig,
    MigrationStrategy,
    TlsConfig,
)
from lkmp.convergence import measure_predump_dirty_bytes
from lkmp.criu_driver import CriuDriver
from lkmp.drivers import (
    MicroVmDriver,
    OciContainerDriver,
    QemuQmpDriver,
    WorkloadKind,
    WorkloadMigrationDriver,
    diagnose_workload_porting,
)
from lkmp.envelope import EnvelopeManager
from lkmp.fs_sync import (
    STORAGE_PROBE_FILENAME,
    FilesystemSyncManager,
    _default_runner as _fs_default_runner,
)
from lkmp.journal import validate_safe_identifier
from lkmp.logging_utils import get_logger
from lkmp.models import FileArtifact, HostCapabilities
from lkmp.network import (
    NetworkMobilityManager,
    TcpRepairError,
    TcpRepairResult,
    parse_host_port,
    set_tree_tcp_repair,
)
from lkmp.preflight import (
    collect_host_capabilities,
    compute_file_sha256,
    discover_process_tree_pids,
    inspect_process_tree,
    is_pid_stopped,
    parse_elf_build_id,
    read_proc_starttime,
)
from lkmp.realtime import resolve_tmpfs_work_dir
from lkmp.telemetry import PrometheusMetricsCollector

logger = get_logger("agent")

MAX_RPC_MESSAGE_BYTES = 16 * 1024 * 1024
MAX_INBAND_TRANSFER_BYTES = 8 * 1024 * 1024
IDEMPOTENT_READ_METHODS = frozenset(
    {
        "get_capabilities",
        "inspect_process",
        "diagnose_workload",
        "stat_files",
        "verify_process",
        "verify_restored_stopped",
        "health_check",
        "get_metrics",
    }
)

# Safe HostCapabilities from_dict wrapper accepting extra fields (criu_check_extra_ok, etc.)
_orig_hc_from_dict = HostCapabilities.from_dict


def _safe_hc_from_dict(cls: Any, data: Dict[str, Any]) -> HostCapabilities:
    known = {f.name for f in dataclasses.fields(cls)}
    inst = _orig_hc_from_dict({k: v for k, v in data.items() if k in known})
    for k, v in data.items():
        if k not in known:
            setattr(inst, k, v)
    return inst


HostCapabilities.from_dict = classmethod(_safe_hc_from_dict)


def config_to_dict(config: MigrationConfig) -> Dict[str, Any]:
    data = asdict(config)
    data["strategy"] = config.strategy.value
    data["fs_mode"] = config.fs_mode.value
    data["ip_mobility"] = config.ip_mobility.value
    data["gpu_plugin"] = config.gpu_plugin.value
    return data


def config_from_dict(data: Dict[str, Any]) -> MigrationConfig:
    d = dict(data)
    d["strategy"] = MigrationStrategy(d["strategy"])
    d["fs_mode"] = FilesystemMode(d["fs_mode"])
    d["ip_mobility"] = IpMobilityMode(d["ip_mobility"])
    d["gpu_plugin"] = GpuPlugin(d["gpu_plugin"])
    if isinstance(d.get("tls"), dict):
        d["tls"] = TlsConfig(**d["tls"])
    return MigrationConfig(**d)


class AgentService:
    """Host-level operations executed on Source A or Destination B."""

    def __init__(
        self,
        work_dir: str = "/var/lib/lkmp/migrations",
        proc_root: str = "/proc",
        criu_driver: Optional[CriuDriver] = None,
        net_manager: Optional[NetworkMobilityManager] = None,
        fs_manager: Optional[FilesystemSyncManager] = None,
        envelope_manager: Optional[EnvelopeManager] = None,
        attestor: Optional[CheckpointAttestor] = None,
        signal_sender: Optional[Callable[[int, int], None]] = None,
        pid_alive_checker: Optional[Callable[[int], bool]] = None,
        tcp_repair_handler: Optional[Callable[[Sequence[int], bool], List[TcpRepairResult]]] = None,
        qemu_driver: Optional[QemuQmpDriver] = None,
        oci_driver: Optional[OciContainerDriver] = None,
        microvm_driver: Optional[MicroVmDriver] = None,
        prefer_tmpfs: bool = False,
        capabilities_override: Optional[Any] = None,
    ) -> None:
        base_work = (
            resolve_tmpfs_work_dir(str(work_dir), prefer_tmpfs=True)[0]
            if prefer_tmpfs
            else Path(work_dir)
        )
        self.work_dir = Path(base_work).resolve()
        self.proc_root = proc_root
        self._capabilities_override = capabilities_override
        self.criu = criu_driver or CriuDriver()
        self.net = net_manager or NetworkMobilityManager()
        self.fs = fs_manager or FilesystemSyncManager()
        self.envelope = envelope_manager or EnvelopeManager()
        self.attestor = attestor or CheckpointAttestor()
        self.qemu_driver = qemu_driver or QemuQmpDriver(proc_root=self.proc_root)
        self.oci_driver = oci_driver or OciContainerDriver(proc_root=self.proc_root)
        self.microvm_driver = microvm_driver or MicroVmDriver(proc_root=self.proc_root)
        self._send_signal = signal_sender or os.kill
        self._check_pid_alive = pid_alive_checker or self._default_pid_alive
        self._tcp_repair_handler = tcp_repair_handler
        self._instance_id = secrets.token_hex(16)
        self.metrics = PrometheusMetricsCollector()
        self._state_lock = threading.RLock()
        self._migration_locks: Dict[str, threading.RLock] = {}
        self._migration_roots: Dict[str, Path] = {}
        self._active_source_pids: Dict[int, str] = {}

    def _select_driver(self, config: MigrationConfig) -> Optional[WorkloadMigrationDriver]:
        wk = (config.workload_kind or "auto").lower()
        if wk == WorkloadKind.QEMU_VM.value:
            return self.qemu_driver
        if wk == WorkloadKind.OCI_CONTAINER.value:
            return self.oci_driver
        if wk == WorkloadKind.MICROVM.value:
            return self.microvm_driver
        return None

    def _select_driver_by_name(self, kind_name: Optional[str]) -> Optional[WorkloadMigrationDriver]:
        if not kind_name:
            return None
        wk = str(kind_name).lower()
        if wk == WorkloadKind.QEMU_VM.value:
            return self.qemu_driver
        if wk == WorkloadKind.OCI_CONTAINER.value:
            return self.oci_driver
        if wk == WorkloadKind.MICROVM.value:
            return self.microvm_driver
        return None

    def _get_migration_lock(self, migration_id: str) -> Optional[threading.RLock]:
        try:
            validate_safe_identifier(migration_id, "migration_id")
        except ValueError:
            return None
        with self._state_lock:
            lock = self._migration_locks.get(migration_id)
            if lock is None:
                lock = threading.RLock()
                self._migration_locks[migration_id] = lock
            return lock

    def _acquire_source_pid(self, pid: int, migration_id: str) -> None:
        with self._state_lock:
            existing = self._active_source_pids.get(int(pid))
            if existing is not None and existing != migration_id:
                if self._check_pid_alive(int(pid)):
                    raise RuntimeError(
                        f"Source process PID {pid} is already locked by active migration {existing!r}"
                    )
            self._active_source_pids[int(pid)] = migration_id
            self.metrics.set_active_migrations(len(self._active_source_pids))

    def _release_source_pid(
        self,
        pid: Optional[int] = None,
        migration_id: Optional[str] = None,
    ) -> None:
        with self._state_lock:
            if pid is not None:
                cur = self._active_source_pids.get(int(pid))
                if cur is not None and (migration_id is None or cur == migration_id):
                    self._active_source_pids.pop(int(pid), None)
            if migration_id is not None:
                stale = [k for k, v in self._active_source_pids.items() if v == migration_id]
                for k in stale:
                    self._active_source_pids.pop(k, None)
            self.metrics.set_active_migrations(len(self._active_source_pids))

    def _uses_real_linux_proc(self) -> bool:
        if not sys.platform.startswith("linux"):
            return False
        try:
            return Path(self.proc_root).resolve() == Path("/proc").resolve()
        except OSError:
            return False

    def _collect_verified_tree_pids(
        self,
        root_pid: int,
        recorded_pids: Optional[List[int]] = None,
        expected_starttimes: Optional[Dict[str, int]] = None,
    ) -> List[int]:
        discovered = discover_process_tree_pids(int(root_pid), self.proc_root)
        targets: List[int] = [int(p) for p in discovered]
        if recorded_pids:
            for p in recorded_pids:
                if int(p) not in targets:
                    targets.append(int(p))
        verified: List[int] = []
        for p in targets:
            if expected_starttimes:
                exp_st = expected_starttimes.get(str(p))
                if exp_st is None:
                    exp_st = expected_starttimes.get(p)  # type: ignore[arg-type]
                if exp_st is not None:
                    curr_st = read_proc_starttime(p, self.proc_root)
                    if curr_st is not None and curr_st != exp_st:
                        continue
            verified.append(p)
        return verified

    def _apply_tcp_repair(
        self,
        pids: Sequence[int],
        enable: bool,
    ) -> Optional[List[TcpRepairResult]]:
        if self._tcp_repair_handler is not None:
            return self._tcp_repair_handler(pids, enable)
        if self._uses_real_linux_proc():
            return set_tree_tcp_repair(pids, enable=enable, proc_root=Path(self.proc_root))
        return None

    def _default_pid_alive(self, pid: int) -> bool:
        proc_entry = Path(self.proc_root) / str(pid)
        if proc_entry.exists():
            return True
        try:
            os.kill(pid, 0)
            return True
        except OSError:
            return False

    def _signal_process_tree(
        self,
        root_pid: int,
        sig: int,
        recorded_pids: Optional[List[int]] = None,
        expected_starttimes: Optional[Dict[str, int]] = None,
    ) -> List[int]:
        """Send signal to root_pid and all descendants in its process tree with PID-reuse protection."""
        discovered = discover_process_tree_pids(root_pid, self.proc_root)
        targets: List[int] = list(discovered)
        if recorded_pids:
            for p in recorded_pids:
                if int(p) not in targets:
                    targets.append(int(p))

        signaled: List[int] = []
        first_error: Optional[OSError] = None
        for p in targets:
            if expected_starttimes:
                exp_st = expected_starttimes.get(str(p))
                if exp_st is None:
                    exp_st = expected_starttimes.get(p)  # type: ignore[arg-type]
                if exp_st is not None:
                    curr_st = read_proc_starttime(p, self.proc_root)
                    if curr_st is not None and curr_st != exp_st:
                        # PID was reused! Skip signaling
                        continue
            try:
                self._send_signal(p, sig)
                signaled.append(p)
            except OSError as exc:
                if exc.errno != errno.ESRCH and first_error is None:
                    first_error = exc
        if first_error is not None:
            raise first_error
        return signaled

    def _migration_base_root(self, migration_id: str, prefer_tmpfs: bool = False) -> Path:
        validate_safe_identifier(migration_id, "migration_id")
        with self._state_lock:
            existing = self._migration_roots.get(migration_id)
            if existing is not None:
                return existing
            if prefer_tmpfs:
                chosen = resolve_tmpfs_work_dir(str(self.work_dir), prefer_tmpfs=True)[0].resolve()
                self._migration_roots[migration_id] = chosen
                return chosen
            return self.work_dir

    def _migration_dir(self, migration_id: str) -> Path:
        validate_safe_identifier(migration_id, "migration_id")
        base_root = self._migration_base_root(migration_id)
        mig_dir = (base_root / migration_id).resolve()
        if not mig_dir.is_relative_to(base_root) or mig_dir == base_root:
            raise ValueError(f"Invalid migration directory path for {migration_id!r}")
        return mig_dir

    def _round_dir(self, migration_id: str, round_name: str) -> Path:
        mig_dir = self._migration_dir(migration_id)
        validate_safe_identifier(round_name, "round_name")
        rnd_dir = (mig_dir / round_name).resolve()
        if not rnd_dir.is_relative_to(mig_dir) or rnd_dir == mig_dir:
            raise ValueError(f"Invalid round directory path for {round_name!r}")
        return rnd_dir

    def get_capabilities(self) -> Dict[str, Any]:
        if self._capabilities_override is not None:
            caps_dict = (
                self._capabilities_override.to_dict()
                if hasattr(self._capabilities_override, "to_dict")
                else dict(self._capabilities_override)
            )
            caps_dict.setdefault("criu_check_extra_ok", True)
            caps_dict.setdefault("criu_checked_features", {"mem_dirty_track": True, "uffd-noncoop": True})
            caps_dict.setdefault("host_id", self._instance_id)
            return caps_dict
        caps = collect_host_capabilities(proc_root=self.proc_root)
        try:
            res = self.criu.runner([self.criu.criu_bin, "--version"])
            caps.criu_available = res.returncode == 0
            if res.stdout:
                caps.criu_version = res.stdout.splitlines()[0].strip()
        except Exception:
            caps.criu_available = False

        # Also check criu check --extra and features (mem_dirty_track, uffd-noncoop)
        criu_extra_ok = False
        if caps.criu_available:
            try:
                res_extra = self.criu.runner(self.criu.build_check_extra_cmd())
                criu_extra_ok = (res_extra.returncode == 0)
            except Exception:
                criu_extra_ok = False

        checked_features: Dict[str, bool] = {}
        for feat in ("mem_dirty_track", "uffd-noncoop"):
            feat_ok = False
            if caps.criu_available:
                try:
                    res_feat = self.criu.runner(self.criu.build_check_feature_cmd(feat))
                    feat_ok = (res_feat.returncode == 0)
                except Exception:
                    feat_ok = False
            checked_features[feat] = feat_ok

        host_id = None
        for mid_path in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
            try:
                p = Path(mid_path)
                if p.exists():
                    host_id = p.read_text(encoding="utf-8").strip()
                    if host_id:
                        break
            except Exception:
                pass
        if not host_id:
            try:
                host_id = socket.gethostname()
            except Exception:
                host_id = "local-node"

        try:
            probe_dir = self.work_dir
            while not probe_dir.exists() and probe_dir != probe_dir.parent:
                probe_dir = probe_dir.parent
            if probe_dir.exists():
                caps.work_dir_free_bytes = int(shutil.disk_usage(probe_dir).free)
        except Exception:
            pass

        # Probe QEMU / Podman / tmpfs capabilities for VM & Container runtime drivers
        for qbin in ("qemu-system-x86_64", "qemu-system-aarch64", "qemu-kvm"):
            qpath = shutil.which(qbin)
            if qpath:
                caps.qemu_available = True
                try:
                    qres = subprocess.run(
                        [qpath, "--version"],
                        capture_output=True,
                        text=True,
                        timeout=2.0,
                        check=False,
                    )
                    if qres.stdout:
                        caps.qemu_version = qres.stdout.splitlines()[0].strip()
                except Exception:
                    pass
                break

        caps.podman_available = bool(shutil.which("podman"))
        if sys.platform.startswith("linux") and Path("/dev/shm").is_dir():
            try:
                st_shm = os.statvfs("/dev/shm")
                caps.tmpfs_available_bytes = int(st_shm.f_bavail * st_shm.f_frsize)
            except OSError:
                pass

        caps_dict = caps.to_dict()
        setattr(caps, "criu_check_extra_ok", criu_extra_ok)
        setattr(caps, "criu_checked_features", checked_features)
        setattr(caps, "host_id", host_id)
        caps_dict["criu_check_extra_ok"] = criu_extra_ok
        caps_dict["criu_checked_features"] = checked_features
        caps_dict["host_id"] = host_id
        return caps_dict

    def health_check(self) -> Dict[str, Any]:
        """Return live agent health status, active migration count, and host capabilities."""
        with self._state_lock:
            active_count = len(self._active_source_pids)
        return {
            "status": "ok",
            "agent_id": self._instance_id,
            "active_migrations": active_count,
            "capabilities": self.get_capabilities(),
        }

    def get_metrics(self) -> Dict[str, Any]:
        """Return Prometheus/OpenMetrics text exposition and active migration count."""
        with self._state_lock:
            active_count = len(self._active_source_pids)
        return {
            "prometheus_text": self.metrics.export_prometheus_text(),
            "active_migrations": active_count,
        }

    def inspect_process(
        self,
        pid: int,
        ghost_limit_bytes: int,
        active_sample_ms: int = 0,
    ) -> Dict[str, Any]:
        try:
            snapshot = inspect_process_tree(
                pid=int(pid),
                proc_root=self.proc_root,
                ghost_limit_bytes=int(ghost_limit_bytes),
                active_sample_ms=int(active_sample_ms),
            )
        except TypeError:
            snapshot = inspect_process_tree(
                pid=int(pid),
                proc_root=self.proc_root,
                ghost_limit_bytes=int(ghost_limit_bytes),
            )
        return snapshot.to_dict()

    def run_check_only(self, migration_id: str, config_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Execute `criu pre-dump --check-only` verification into a temporary directory and wipe it."""
        config = config_from_dict(config_dict)
        chk_dir = self._round_dir(migration_id, "check_only")
        chk_dir.mkdir(parents=True, exist_ok=True)
        try:
            cmd = self.criu.build_check_only_cmd(config.pid, str(chk_dir))
            self.criu.runner(cmd)
        finally:
            self.fs.secure_wipe_directory(chk_dir, allowed_parent=self.work_dir)
        return {
            "check_only_ok": True,
            "note": "CRIU --check-only completed and temporary artifacts cleaned",
        }

    def stat_files(self, paths: List[str]) -> Dict[str, Dict[str, Any]]:
        result: Dict[str, Dict[str, Any]] = {}
        for p in paths:
            path_obj = Path(p)
            if not path_obj.exists():
                continue
            try:
                st = path_obj.stat()
                build_id = parse_elf_build_id(path_obj)
                sha256 = (
                    compute_file_sha256(path_obj)
                    if build_id is None and st.st_size <= 16 * 1024 * 1024
                    else None
                )
                artifact = FileArtifact(
                    path=p,
                    size=st.st_size,
                    sha256=sha256,
                    build_id=build_id,
                    is_deleted=False,
                    is_mapped_executable=os.access(p, os.X_OK),
                )
                result[p] = artifact.to_dict()
            except OSError:
                continue
        return result

    def diagnose_workload(self, pid: int) -> Dict[str, Any]:
        """Inspect target PID and return runtime driver classification + zero-copy porting advice."""
        return diagnose_workload_porting(int(pid), proc_root=self.proc_root)

    def prepare_migration(
        self,
        migration_id: str,
        config_dict: Optional[Dict[str, Any]] = None,
        is_dest: bool = False,
    ) -> Dict[str, Any]:
        config: Optional[MigrationConfig] = (
            config_from_dict(config_dict) if config_dict is not None else None
        )
        if config is not None and config.prefer_tmpfs_work_dir:
            self._migration_base_root(migration_id, prefer_tmpfs=True)

        mig_dir = self._migration_dir(migration_id)
        mig_dir.mkdir(parents=True, exist_ok=True)
        final_dir = self._round_dir(migration_id, "final")
        final_dir.mkdir(parents=True, exist_ok=True)
        probe_token = secrets.token_hex(16)
        probe_payload = {
            "agent_id": self._instance_id,
            "migration_id": migration_id,
            "token": probe_token,
        }
        (mig_dir / STORAGE_PROBE_FILENAME).write_text(
            json.dumps(probe_payload), encoding="utf-8"
        )
        res: Dict[str, Any] = {
            "migration_dir": str(mig_dir),
            "images_dir": str(final_dir),
            "dest_agent_id": self._instance_id,
            "storage_probe_token": probe_token,
        }
        if is_dest and config is not None:
            drv = self._select_driver(config)
            if drv is not None:
                drv_res = drv.prepare_dest(migration_id, mig_dir, config)
                res.update(drv_res)
        return res

    def pre_sync_fs(self, config_dict: Dict[str, Any], dest_host: str) -> Dict[str, Any]:
        config = config_from_dict(config_dict)
        cmds = self.fs.pre_sync_writable_paths(config, dest_host)
        return {"synced_paths": len(cmds)}

    def start_page_server(
        self,
        migration_id: str,
        round_name: str,
        prev_round_name: Optional[str],
        config_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Start `criu page-server --daemon` (or VM/OCI pre-copy target) on Destination B."""
        config = config_from_dict(config_dict)
        drv = self._select_driver(config)
        if drv is not None:
            mig_dir = self._migration_dir(migration_id)
            mig_dir.mkdir(parents=True, exist_ok=True)
            img_dir = self._round_dir(migration_id, round_name)
            img_dir.mkdir(parents=True, exist_ok=True)
            drv_res = drv.start_pre_copy_target(
                migration_id, mig_dir, round_name, prev_round_name, config
            )
            return {"images_dir": str(img_dir), **drv_res}

        img_dir = self._round_dir(migration_id, round_name)
        img_dir.mkdir(parents=True, exist_ok=True)
        if prev_round_name:
            validate_safe_identifier(prev_round_name, "prev_round_name")
        prev_rel = f"../{prev_round_name}" if prev_round_name else None
        pidfile = str(img_dir / "page-server.pid")
        cmd = self.criu.build_page_server_cmd(
            images_dir=str(img_dir),
            port=config.page_server_port,
            tls=config.tls,
            prev_images_dir=prev_rel,
            pidfile=pidfile,
            auto_dedup=bool(config.auto_dedup),
        )
        self.criu.runner(cmd)
        return {"images_dir": str(img_dir), "pidfile": pidfile, "command": cmd}

    def finalize_page_server_round(
        self,
        migration_id: str,
        round_name: str,
    ) -> Dict[str, Any]:
        """
        Inspect the completed `page-server` directory on Destination B to report the actual
        received `pages-*.img` volume and their SHA-256 Merkle root for attestation.
        """
        img_dir = self._round_dir(migration_id, round_name)
        dirty_bytes = measure_predump_dirty_bytes(img_dir)
        _digests, pages_merkle_root = compute_directory_img_digests(
            img_dir, prefix_filter="pages-"
        )
        return {
            "received_dirty_bytes": dirty_bytes,
            "dest_pages_merkle_root": pages_merkle_root,
        }

    def run_pre_dump(
        self,
        migration_id: str,
        round_name: str,
        prev_round_name: Optional[str],
        dest_host: str,
        config_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        config = config_from_dict(config_dict)
        drv = self._select_driver(config)
        if drv is not None:
            mig_dir = self._migration_dir(migration_id)
            mig_dir.mkdir(parents=True, exist_ok=True)
            img_dir = self._round_dir(migration_id, round_name)
            img_dir.mkdir(parents=True, exist_ok=True)
            return drv.run_pre_copy_source(
                migration_id, mig_dir, round_name, prev_round_name, dest_host, config
            )

        img_dir = self._round_dir(migration_id, round_name)
        img_dir.mkdir(parents=True, exist_ok=True)
        if prev_round_name:
            validate_safe_identifier(prev_round_name, "prev_round_name")
        prev_rel = f"../{prev_round_name}" if prev_round_name else None
        t0 = time.monotonic()
        cmd = self.criu.build_pre_dump_cmd(
            config=config,
            images_dir=str(img_dir),
            prev_images_dir=prev_rel,
            dest_host=dest_host,
        )
        self.criu.runner(cmd)
        duration_ms = (time.monotonic() - t0) * 1000.0
        dirty_bytes = measure_predump_dirty_bytes(img_dir)
        return {
            "dirty_bytes": dirty_bytes,
            "duration_ms": round(duration_ms, 2),
            "images_dir": str(img_dir),
            "command": cmd,
        }

    def freeze_and_final_dump(
        self,
        migration_id: str,
        prev_round_name: Optional[str],
        dest_host: str,
        config_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        config = config_from_dict(config_dict)
        mig_dir = self._migration_dir(migration_id)
        if prev_round_name:
            validate_safe_identifier(prev_round_name, "prev_round_name")
        prev_rel = f"../{prev_round_name}" if prev_round_name else None

        self._acquire_source_pid(config.pid, migration_id)
        mig_dir.mkdir(parents=True, exist_ok=True)
        img_dir = self._round_dir(migration_id, "final")
        img_dir.mkdir(parents=True, exist_ok=True)

        drv = self._select_driver(config)
        if drv is not None:
            try:
                if config.quiesce_cmd:
                    subprocess.run(
                        shlex.split(config.quiesce_cmd),
                        timeout=config.quiesce_timeout_sec,
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                self.net.lock_network(config.workload_ip, migration_id=migration_id)
                drv_res = drv.freeze_and_dump_source(
                    migration_id, mig_dir, prev_round_name, dest_host, config
                )
                if config.volume_snapshot_cmd or config.writable_paths:
                    self.fs.snapshot_writable_paths_while_frozen(config, img_dir / "vol_snap")
                return drv_res
            except Exception:
                src_state = mig_dir / "source_state.json"
                if not src_state.exists():
                    self._release_source_pid(config.pid, migration_id)
                raise

        source_state_written = False
        try:
            # Discover initial process tree PIDs and starttimes
            tree_pids = discover_process_tree_pids(config.pid, self.proc_root)
            starttimes = {str(p): read_proc_starttime(p, self.proc_root) for p in tree_pids}
            quiesced = False

            # 0. Run application quiesce_cmd BEFORE lock_network and freeze_cgroup if configured
            if config.quiesce_cmd:
                subprocess.run(
                    shlex.split(config.quiesce_cmd),
                    timeout=config.quiesce_timeout_sec,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                quiesced = True

            # Record source_state.json in mig_dir
            source_state_file = mig_dir / "source_state.json"
            state_data = {
                "pid": config.pid,
                "tree_pids": tree_pids,
                "starttimes": starttimes,
                "committed": False,
                "quiesced": quiesced,
            }
            source_state_file.write_text(json.dumps(state_data, indent=2), encoding="utf-8")
            source_state_written = True
        except Exception:
            if not source_state_written:
                self._release_source_pid(config.pid, migration_id)
            raise

        # 1. Lock network per-migration to suppress TCP RSTs
        self.net.lock_network(config.workload_ip, migration_id=migration_id)

        # 2. Freeze cgroup if workload_id is provided
        if config.workload_id:
            validate_safe_identifier(config.workload_id, "workload_id")
            self.envelope.freeze_cgroup(config.workload_id)

        # 3. Run GPU pre-dump hook if configured
        self.criu.run_gpu_pre_dump_hook(config)

        # 4. Run CRIU final dump (--leave-stopped preserves source for rollback)
        cmd = self.criu.build_dump_cmd(
            config=config,
            images_dir=str(img_dir),
            prev_images_dir=prev_rel,
            dest_host=dest_host if config.strategy == MigrationStrategy.PRE_COPY else None,
        )
        if config.strategy in (MigrationStrategy.LAZY, MigrationStrategy.HYBRID):
            lazy_dump_pidfile = img_dir / "lazy-dump.pid"
            self.criu.run_background_daemon(cmd, pidfile=lazy_dump_pidfile)
        else:
            self.criu.runner(cmd)

        # 5. While still frozen: run snapshot_writable_paths_while_frozen if configured
        vol_snapshotted = False
        if config.volume_snapshot_cmd or config.writable_paths:
            self.fs.snapshot_writable_paths_while_frozen(config, img_dir / "vol_snap")
            vol_snapshotted = True

        if vol_snapshotted:
            state_data["volume_snapshotted_while_frozen"] = True
            source_state_file.write_text(json.dumps(state_data, indent=2), encoding="utf-8")

        if config.verify_attestation:
            try:
                pages_size = sum(
                    p.stat().st_size
                    for p in img_dir.iterdir()
                    if p.is_file() and p.name.startswith("pages-") and p.name.endswith(".img")
                )
                expected_pages_bytes = pages_size if pages_size > 0 else None
                self.attestor.generate_manifest(
                    images_dir=img_dir,
                    migration_id=migration_id,
                    pid=config.pid,
                    dest_pages_merkle_root=None,
                    key_hex=config.attestation_key_hex,
                    expected_pages_bytes=expected_pages_bytes,
                )
            except Exception:
                pass

        res_dict: Dict[str, Any] = {"images_dir": str(img_dir), "command": cmd}
        if vol_snapshotted:
            res_dict["volume_snapshotted_while_frozen"] = True
        return res_dict

    def sign_final_checkpoint(
        self,
        migration_id: str,
        config_dict: Dict[str, Any],
        dest_pages_merkle_root: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate `manifest.sig.json` on Source A binding local `.img` and remote `pages-*.img`."""
        config = config_from_dict(config_dict)
        img_dir = self._round_dir(migration_id, "final")
        pages_size = sum(
            p.stat().st_size
            for p in img_dir.iterdir()
            if p.is_file() and p.name.startswith("pages-") and p.name.endswith(".img")
        )
        expected_pages_bytes = pages_size if pages_size > 0 else None
        manifest = self.attestor.generate_manifest(
            images_dir=img_dir,
            migration_id=migration_id,
            pid=config.pid,
            dest_pages_merkle_root=dest_pages_merkle_root,
            key_hex=config.attestation_key_hex,
            expected_pages_bytes=expected_pages_bytes,
        )
        return {"merkle_root": manifest.merkle_root}

    def _resolve_same_host_dest_images_dir(
        self,
        migration_id: str,
        dest_host: str,
        config: MigrationConfig,
        dest_images_dir: Optional[str],
        dest_probe_token: Optional[str] = None,
    ) -> Optional[str]:
        if not config.same_host_cow:
            return None
        img_dir = self._round_dir(migration_id, "final")
        candidates: List[str] = []
        if dest_images_dir:
            candidates.append(dest_images_dir)
        else:
            try:
                _dhost, dest_port = parse_host_port(config.dest_addr, default_port=9700)
            except ValueError:
                dest_port = 9700
            clean_dest = dest_host[1:-1] if dest_host.startswith("[") and dest_host.endswith("]") else dest_host
            srv = (
                _ACTIVE_SERVERS.get((clean_dest, dest_port))
                or _ACTIVE_SERVERS.get(("127.0.0.1", dest_port))
                or _ACTIVE_SERVERS.get(("::1", dest_port))
            )
            if srv is not None and srv.service is not self:
                candidates.append(str(srv.service._round_dir(migration_id, "final")))

        for candidate in candidates:
            if self.fs.is_same_host_or_shared_storage(
                config.source_addr,
                dest_host,
                source_dir=img_dir,
                dest_dir=candidate,
                expected_probe_token=dest_probe_token,
                source_agent_id=self._instance_id,
                expected_migration_id=migration_id,
            ):
                return candidate
        return None

    def export_inband_metadata(
        self,
        migration_id: str,
        dest_host: str,
        config_dict: Dict[str, Any],
        dest_pages_merkle_root: Optional[str] = None,
        dest_images_dir: Optional[str] = None,
        dest_probe_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Zero-fork fast path for streaming small final checkpoint metadata (`.img` + `manifest.sig.json`)
        over the persistent mTLS JSON-RPC socket instead of cold-forking `rsync` + `ssh` during freeze.
        """
        config = config_from_dict(config_dict)
        wk = (config.workload_kind or "auto").lower()
        if wk == WorkloadKind.QEMU_VM.value:
            return {"eligible": True, "skip_upload": True, "driver": wk}

        if self.fs.runner is not _fs_default_runner:
            return {"eligible": False, "reason": "custom_fs_runner"}
        if not config.inband_metadata_transfer:
            return {"eligible": False, "reason": "disabled"}
        if config.strategy == MigrationStrategy.COLD and wk not in (
            WorkloadKind.OCI_CONTAINER.value,
            WorkloadKind.MICROVM.value,
        ):
            return {"eligible": False, "reason": "cold_pages_on_disk"}

        resolved_cow = self._resolve_same_host_dest_images_dir(
            migration_id=migration_id,
            dest_host=dest_host,
            config=config,
            dest_images_dir=dest_images_dir,
            dest_probe_token=dest_probe_token,
        )
        if resolved_cow is not None:
            return {"eligible": False, "reason": "same_host_cow_faster"}

        img_dir = self._round_dir(migration_id, "final")
        if config.verify_attestation and wk not in (
            WorkloadKind.OCI_CONTAINER.value,
            WorkloadKind.MICROVM.value,
        ):
            pages_size = sum(
                p.stat().st_size
                for p in img_dir.iterdir()
                if p.is_file() and p.name.startswith("pages-") and p.name.endswith(".img")
            )
            expected_pages_bytes = pages_size if pages_size > 0 else None
            self.attestor.generate_manifest(
                images_dir=img_dir,
                migration_id=migration_id,
                pid=config.pid,
                dest_pages_merkle_root=dest_pages_merkle_root,
                key_hex=config.attestation_key_hex,
                expected_pages_bytes=expected_pages_bytes,
            )

        candidates: List[Path] = []
        total_bytes = 0
        for item in sorted(img_dir.iterdir()):
            if not item.is_file():
                continue
            if item.name.startswith("pages-") and item.name.endswith(".img"):
                continue
            if (
                item.name == "manifest.sig.json"
                or item.name.endswith(".img")
                or item.name.endswith(".tar")
                or item.name.endswith(".snap")
                or item.name.endswith(".mem")
            ):
                sz = item.stat().st_size
                total_bytes += sz
                if total_bytes > MAX_INBAND_TRANSFER_BYTES:
                    return {"eligible": False, "reason": "exceeds_inband_limit", "total_bytes": total_bytes}
                candidates.append(item)

        files_b64 = {
            p.name: base64.b64encode(p.read_bytes()).decode("ascii")
            for p in candidates
        }
        return {"eligible": True, "files_b64": files_b64, "total_bytes": total_bytes}

    def upload_checkpoint_files(
        self,
        migration_id: str,
        round_name: str,
        files_b64: Dict[str, str],
    ) -> Dict[str, Any]:
        """Receive in-band checkpoint metadata files over the warm persistent mTLS RPC socket."""
        dst_dir = self._round_dir(migration_id, round_name)
        dst_dir.mkdir(parents=True, exist_ok=True)
        written = 0
        total_bytes = 0
        for fname, b64_payload in files_b64.items():
            if not fname or "/" in fname or "\\" in fname or fname in (".", ".."):
                raise ValueError(f"Invalid checkpoint filename: {fname!r}")
            target = (dst_dir / fname).resolve()
            if target.parent != dst_dir:
                raise ValueError(f"Path traversal rejected for checkpoint file: {fname!r}")
            raw = base64.b64decode(b64_payload.encode("ascii"))
            tmp_path = dst_dir / f".{fname}.tmp.{os.getpid()}"
            tmp_path.write_bytes(raw)
            os.replace(tmp_path, target)
            written += 1
            total_bytes += len(raw)
        return {"uploaded_files": written, "total_bytes": total_bytes}

    def transfer_final_state(
        self,
        migration_id: str,
        dest_host: str,
        config_dict: Dict[str, Any],
        dest_pages_merkle_root: Optional[str] = None,
        dest_images_dir: Optional[str] = None,
        dest_probe_token: Optional[str] = None,
        skip_images_sync: bool = False,
    ) -> Dict[str, Any]:
        config = config_from_dict(config_dict)
        wk = (config.workload_kind or "auto").lower()
        img_dir = self._round_dir(migration_id, "final")

        if wk == WorkloadKind.QEMU_VM.value:
            snap_dir = img_dir / "vol_snap"
            self.fs.final_delta_sync(config, dest_host, snapshot_dir=snap_dir)
            return {"transferred": True, "included_pages": False, "cow_fast_path": False, "driver": wk}

        pages_size = sum(
            p.stat().st_size
            for p in img_dir.iterdir()
            if p.is_file() and p.name.startswith("pages-") and p.name.endswith(".img")
        )
        expected_pages_bytes = pages_size if pages_size > 0 else None

        if not skip_images_sync and config.verify_attestation and wk not in (
            WorkloadKind.OCI_CONTAINER.value,
            WorkloadKind.MICROVM.value,
        ):
            self.attestor.generate_manifest(
                images_dir=img_dir,
                migration_id=migration_id,
                pid=config.pid,
                dest_pages_merkle_root=dest_pages_merkle_root,
                key_hex=config.attestation_key_hex,
                expected_pages_bytes=expected_pages_bytes,
            )

        # For COLD migration, pages-*.img were NOT sent via page-server, so transfer MUST include them!
        include_pages = config.strategy == MigrationStrategy.COLD
        used_cow = False
        if not skip_images_sync:
            resolved_dest_img_dir = self._resolve_same_host_dest_images_dir(
                migration_id=migration_id,
                dest_host=dest_host,
                config=config,
                dest_images_dir=dest_images_dir,
                dest_probe_token=dest_probe_token,
            )
            used_cow = resolved_dest_img_dir is not None
            self.fs.sync_checkpoint_images(
                str(img_dir),
                dest_host,
                include_pages=include_pages,
                source_host=config.source_addr,
                dest_images_dir=resolved_dest_img_dir,
                dest_probe_token=dest_probe_token,
                source_agent_id=self._instance_id,
                migration_id=migration_id,
            )
        snap_dir = img_dir / "vol_snap"
        self.fs.final_delta_sync(
            config,
            dest_host,
            snapshot_dir=snap_dir,
        )
        return {
            "transferred": True,
            "included_pages": include_pages,
            "cow_fast_path": used_cow,
            "inband_fast_path": skip_images_sync,
        }

    def restore_process(
        self,
        migration_id: str,
        source_host: str,
        config_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        config = config_from_dict(config_dict)
        mig_dir = self._migration_dir(migration_id)
        img_dir = self._round_dir(migration_id, "final")
        img_dir.mkdir(parents=True, exist_ok=True)

        drv = self._select_driver(config)
        if drv is not None:
            self.net.lock_network(config.workload_ip, migration_id=migration_id)
            self.net.assign_ip_for_restore(config)
            if config.volume_restore_cmd:
                self.fs.runner(shlex.split(config.volume_restore_cmd))
            drv_res = drv.restore_stopped_dest(migration_id, mig_dir, source_host, config)
            restored_pid = int(drv_res["restored_pid"])
            restored_st = drv_res.get("restored_starttime")
            if restored_st is None:
                restored_st = read_proc_starttime(restored_pid, self.proc_root)
            state_path = img_dir / "restore_state.json"
            existing_state: Dict[str, Any] = {}
            if state_path.exists():
                try:
                    existing_state = json.loads(state_path.read_text(encoding="utf-8"))
                except Exception:
                    existing_state = {}
            restore_state = {
                **existing_state,
                "driver": (config.workload_kind or "auto").lower(),
                "config_dict": config_dict,
                "restored_pid": restored_pid,
                "tree_pids": [restored_pid],
                "starttimes": {str(restored_pid): restored_st},
                "workload_ip": config.workload_ip,
                "tcp_established": bool(config.workload_ip),
            }
            if drv_res.get("dest_qmp_socket"):
                restore_state["dest_qmp_socket"] = drv_res.get("dest_qmp_socket")
            state_path.write_text(json.dumps(restore_state, indent=2), encoding="utf-8")
            return {
                "restored_pid": restored_pid,
                "restored_starttime": restored_st,
                **drv_res,
            }

        # 1. Always verify cryptographic Merkle-tree checkpoint attestation when enabled
        if config.verify_attestation:
            self.attestor.verify_directory(
                img_dir,
                expected_migration_id=migration_id,
                key_hex=config.attestation_key_hex,
            )

        # 2. Lock network on Destination B so restored sockets do not emit packets prematurely
        self.net.lock_network(config.workload_ip, migration_id=migration_id)

        # 3. Assign workload IP on Destination B BEFORE `criu restore --tcp-established`
        # so the local socket address exists in the target netns for TCP_REPAIR bind()
        self.net.assign_ip_for_restore(config)

        # 4. If LAZY or HYBRID, start `criu lazy-pages` in background before restore
        if config.strategy in (MigrationStrategy.LAZY, MigrationStrategy.HYBRID):
            lazy_pidfile = img_dir / "lazy-pages.pid"
            lazy_cmd = self.criu.build_lazy_pages_daemon_cmd(
                config=config,
                images_dir=str(img_dir),
                source_host=source_host,
            )
            self.criu.run_background_daemon(lazy_cmd, pidfile=lazy_pidfile)

        # If volume_restore_cmd is set, execute via self.fs.runner before criu restore
        if config.volume_restore_cmd:
            self.fs.runner(shlex.split(config.volume_restore_cmd))

        # 5. Execute `criu restore --restore-detached --leave-stopped`
        pidfile = img_dir / "restored.pid"
        restore_cmd = self.criu.build_restore_cmd(
            config=config,
            images_dir=str(img_dir),
            pidfile=str(pidfile),
        )
        self.criu.runner(restore_cmd)

        restored_pid = config.pid
        if pidfile.exists():
            try:
                restored_pid = int(pidfile.read_text(encoding="utf-8").strip())
            except ValueError:
                restored_pid = config.pid

        # Write final/restore_state.json right after criu restore
        tree_pids = discover_process_tree_pids(restored_pid, self.proc_root)
        starttimes = {str(p): read_proc_starttime(p, self.proc_root) for p in tree_pids}
        restore_state = {
            "restored_pid": restored_pid,
            "tree_pids": tree_pids,
            "starttimes": starttimes,
            "workload_ip": config.workload_ip,
            "tcp_established": config.tcp_established,
        }
        (img_dir / "restore_state.json").write_text(json.dumps(restore_state, indent=2), encoding="utf-8")

        self.criu.run_gpu_post_restore_hook(config, restored_pid)
        return {
            "restored_pid": restored_pid,
            "restored_starttime": starttimes.get(str(restored_pid)),
            "command": restore_cmd,
        }

    def release_ip(
        self,
        config_dict: Dict[str, Any],
        migration_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        config = config_from_dict(config_dict)
        cmds = self.net.release_ip_on_host(config, migration_id=migration_id)
        return {"commands": cmds}

    def claim_ip_and_resume(
        self,
        restored_pid: Optional[int],
        target_host: str,
        config_dict: Dict[str, Any],
        migration_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        config = config_from_dict(config_dict)
        tree_pids: Optional[List[int]] = None
        starttimes: Optional[Dict[str, int]] = None
        if migration_id:
            state_file = self._round_dir(migration_id, "final") / "restore_state.json"
            if state_file.exists():
                try:
                    data = json.loads(state_file.read_text(encoding="utf-8"))
                    if restored_pid is None:
                        restored_pid = data.get("restored_pid")
                    tree_pids = data.get("tree_pids")
                    starttimes = data.get("starttimes")
                except Exception:
                    pass
            if restored_pid is None:
                pidfile = self._round_dir(migration_id, "final") / "restored.pid"
                if pidfile.exists():
                    try:
                        restored_pid = int(pidfile.read_text(encoding="utf-8").strip())
                    except Exception:
                        pass

        if restored_pid is None or int(restored_pid) <= 0:
            raise RuntimeError("No restored PID found on destination; refusing to claim IP or resume")

        root_pid = int(restored_pid)
        if starttimes:
            exp_root_st = starttimes.get(str(root_pid))
            if exp_root_st is None:
                exp_root_st = starttimes.get(root_pid)  # type: ignore[arg-type]
            if exp_root_st is not None:
                curr_root_st = read_proc_starttime(root_pid, self.proc_root)
                if curr_root_st is None or curr_root_st != exp_root_st:
                    raise RuntimeError(
                        f"Restored process {root_pid} starttime mismatch on destination "
                        f"(expected {exp_root_st}, got {curr_root_st}); refusing to claim IP or resume"
                    )

        cmds = self.net.announce_ip_on_host(config, target_host=target_host, ensure_assigned=True)
        self.net.unlock_network(config.workload_ip, migration_id=migration_id)
        if config.workload_id:
            validate_safe_identifier(config.workload_id, "workload_id")
            self.envelope.unfreeze_cgroup(config.workload_id)

        drv = self._select_driver(config)
        if drv is not None and migration_id:
            mig_dir = self._migration_dir(migration_id)
            drv.resume_dest(migration_id, mig_dir, int(restored_pid), target_host, config)
        else:
            self._signal_process_tree(
                int(restored_pid),
                signal.SIGCONT,
                recorded_pids=tree_pids,
                expected_starttimes=starttimes,
            )

        if config.resume_cmd:
            subprocess.run(
                shlex.split(config.resume_cmd),
                timeout=config.quiesce_timeout_sec,
                check=True,
                capture_output=True,
                text=True,
            )

        return {"resumed_pid": restored_pid, "ip_commands": cmds}

    def verify_process(
        self,
        restored_pid: Optional[int],
        health_check_cmd: Optional[str],
        timeout_sec: float = 5.0,
        migration_id: Optional[str] = None,
        expected_restored_starttime: Optional[int] = None,
    ) -> Dict[str, Any]:
        expected_starttimes: Dict[str, Optional[int]] = {}

        if migration_id:
            state_file = self._round_dir(migration_id, "final") / "restore_state.json"
            if state_file.exists():
                try:
                    data = json.loads(state_file.read_text(encoding="utf-8"))
                    st_pid = data.get("restored_pid")
                    if restored_pid is None:
                        restored_pid = st_pid
                    elif st_pid is not None and int(st_pid) != int(restored_pid):
                        return {
                            "healthy": False,
                            "reason": (
                                f"Restored PID mismatch on destination: WAL expected {restored_pid}, "
                                f"restore_state.json recorded {st_pid}"
                            ),
                        }
                    raw_st = data.get("starttimes")
                    if isinstance(raw_st, dict):
                        expected_starttimes.update({str(k): v for k, v in raw_st.items()})
                except Exception as exc:
                    return {
                        "healthy": False,
                        "reason": f"Failed to parse restore_state.json on destination: {exc}",
                    }
            if restored_pid is None:
                pidfile = self._round_dir(migration_id, "final") / "restored.pid"
                if pidfile.exists():
                    try:
                        restored_pid = int(pidfile.read_text(encoding="utf-8").strip())
                    except Exception:
                        pass

        try:
            pid_int = int(restored_pid) if restored_pid is not None else 0
        except (TypeError, ValueError):
            pid_int = 0
        if pid_int <= 0:
            return {"healthy": False, "reason": "No restored PID found on destination"}

        if (
            expected_restored_starttime is not None
            and expected_starttimes.get(str(pid_int)) is None
        ):
            expected_starttimes[str(pid_int)] = int(expected_restored_starttime)

        tree_pids: List[int] = [pid_int]
        for p in discover_process_tree_pids(pid_int, self.proc_root):
            if int(p) not in tree_pids:
                tree_pids.append(int(p))

        for p in tree_pids:
            if not self._check_pid_alive(p):
                return {
                    "healthy": False,
                    "reason": f"Restored process {p} is not alive on destination",
                }
            exp_st = expected_starttimes.get(str(p))
            if exp_st is not None:
                curr_st = read_proc_starttime(p, self.proc_root)
                if curr_st is None or curr_st != exp_st:
                    return {
                        "healthy": False,
                        "reason": (
                            f"Restored process {p} starttime mismatch on destination "
                            f"(expected {exp_st}, got {curr_st}); PID was reused or vanished"
                        ),
                    }
        if health_check_cmd:
            try:
                res = subprocess.run(
                    shlex.split(health_check_cmd),
                    timeout=timeout_sec,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if res.returncode != 0:
                    return {
                        "healthy": False,
                        "reason": f"Health check exited with code {res.returncode}: {res.stderr.strip()}",
                    }
            except Exception as exc:
                return {"healthy": False, "reason": f"Health check failed: {exc}"}
        return {"healthy": True, "reason": "OK"}

    def verify_restored_stopped(
        self,
        restored_pid: int,
        migration_id: Optional[str] = None,
        workload_ip: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Verify that restored_pid and all restored process tree PIDs are alive, match recorded
        kernel starttimes, are explicitly in stopped state ('T'/'t' via --leave-stopped), and
        are protected by an active nftables network drop lock on Destination B before 2PC commit.
        """
        tree_pids: List[int] = [int(restored_pid)]
        resolved_ip: Optional[str] = workload_ip
        tcp_established: bool = True
        expected_starttimes: Dict[str, Optional[int]] = {}
        driver_name: Optional[str] = None
        saved_cfg_dict: Optional[Dict[str, Any]] = None

        if migration_id:
            state_file = self._round_dir(migration_id, "final") / "restore_state.json"
            if state_file.exists():
                try:
                    data = json.loads(state_file.read_text(encoding="utf-8"))
                    driver_name = data.get("driver")
                    if isinstance(data.get("config_dict"), dict):
                        saved_cfg_dict = data["config_dict"]
                    rec_pids = data.get("tree_pids")
                    if rec_pids:
                        for p in rec_pids:
                            if int(p) not in tree_pids:
                                tree_pids.append(int(p))
                    raw_st = data.get("starttimes")
                    if isinstance(raw_st, dict):
                        expected_starttimes.update({str(k): v for k, v in raw_st.items()})
                    if resolved_ip is None:
                        resolved_ip = data.get("workload_ip")
                    if "tcp_established" in data:
                        tcp_established = bool(data.get("tcp_established"))
                except Exception as exc:
                    return {
                        "healthy": False,
                        "reason": f"Failed to parse restore_state.json on destination: {exc}",
                    }

        drv = self._select_driver_by_name(driver_name)
        if drv is not None and migration_id:
            if not self._check_pid_alive(int(restored_pid)):
                return {
                    "healthy": False,
                    "reason": f"Restored runtime process {restored_pid} is not alive on destination",
                }
            exp_st = expected_starttimes.get(str(restored_pid))
            if exp_st is not None:
                curr_st = read_proc_starttime(int(restored_pid), self.proc_root)
                if curr_st is None or curr_st != exp_st:
                    return {
                        "healthy": False,
                        "reason": (
                            f"Restored runtime process {restored_pid} starttime mismatch on destination "
                            f"(expected {exp_st}, got {curr_st})"
                        ),
                    }
            cfg = (
                config_from_dict(saved_cfg_dict)
                if saved_cfg_dict is not None
                else MigrationConfig(pid=int(restored_pid), source_addr="", dest_addr="")
            )
            drv_chk = drv.verify_stopped_dest(
                migration_id, self._migration_dir(migration_id), int(restored_pid), cfg
            )
            if not drv_chk.get("healthy"):
                return drv_chk
            if resolved_ip:
                if not self.net.verify_network_locked(resolved_ip, migration_id=migration_id):
                    table = self.net.table_name_for(resolved_ip, migration_id)
                    return {
                        "healthy": False,
                        "reason": (
                            f"Active nftables network lock not confirmed on destination "
                            f"(table {table} missing or lacking drop rules for {resolved_ip})"
                        ),
                    }
            return {
                "healthy": True,
                "checked_pids": [int(restored_pid)],
                "stopped_confirmed": True,
                "network_lock_confirmed": bool(resolved_ip),
                "driver": driver_name,
            }

        # Discover any additional descendants
        discovered = discover_process_tree_pids(int(restored_pid), self.proc_root)
        for p in discovered:
            if p not in tree_pids:
                tree_pids.append(p)

        for p in tree_pids:
            if not self._check_pid_alive(p):
                return {
                    "healthy": False,
                    "reason": f"Restored process {p} is not alive on destination",
                }
            exp_st = expected_starttimes.get(str(p))
            if exp_st is not None:
                curr_st = read_proc_starttime(p, self.proc_root)
                if curr_st is None or curr_st != exp_st:
                    return {
                        "healthy": False,
                        "reason": (
                            f"Restored process {p} starttime mismatch on destination "
                            f"(expected {exp_st}, got {curr_st}); PID was reused or vanished"
                        ),
                    }
            stopped_ok, stopped_detail = is_pid_stopped(p, self.proc_root)
            if not stopped_ok:
                return {
                    "healthy": False,
                    "reason": f"Restored process {p} is not stopped on destination ({stopped_detail})",
                }

        network_lock_required = bool(tcp_established or resolved_ip)
        if network_lock_required:
            if not resolved_ip:
                return {
                    "healthy": False,
                    "reason": (
                        "Active nftables network lock required for stopped-readiness barrier, "
                        "but workload_ip is not configured"
                    ),
                }
            if not self.net.verify_network_locked(resolved_ip, migration_id=migration_id):
                table = self.net.table_name_for(resolved_ip, migration_id)
                return {
                    "healthy": False,
                    "reason": (
                        f"Active nftables network lock not confirmed on destination "
                        f"(table {table} missing or lacking drop rules for {resolved_ip})"
                    ),
                }

        return {
            "healthy": True,
            "checked_pids": tree_pids,
            "stopped_confirmed": True,
            "network_lock_confirmed": network_lock_required,
        }

    def commit_source(self, migration_id: str, config_dict: Dict[str, Any]) -> Dict[str, Any]:
        mig_dir = self._migration_dir(migration_id)
        base_root = self._migration_base_root(migration_id)
        config = config_from_dict(config_dict)
        source_state_file = mig_dir / "source_state.json"
        tree_pids: Optional[List[int]] = None
        starttimes: Optional[Dict[str, int]] = None
        state_data: Optional[Dict[str, Any]] = None

        if source_state_file.exists():
            try:
                state_data = json.loads(source_state_file.read_text(encoding="utf-8"))
                if state_data.get("committed"):
                    self._release_source_pid(config.pid, migration_id)
                    return {"committed": True, "idempotent_noop": True}
                tree_pids = state_data.get("tree_pids")
                starttimes = state_data.get("starttimes")
            except Exception:
                state_data = None
        elif not self._check_pid_alive(config.pid) and not mig_dir.exists():
            self._release_source_pid(config.pid, migration_id)
            return {"committed": True, "idempotent_noop": True}

        drv = self._select_driver(config)
        if drv is not None:
            drv_res = drv.commit_source(migration_id, mig_dir, config)
            if state_data is not None and source_state_file.exists():
                try:
                    state_data["committed"] = True
                    source_state_file.write_text(json.dumps(state_data), encoding="utf-8")
                except Exception:
                    pass
            try:
                self.net.unlock_network(config.workload_ip, migration_id=migration_id)
            except Exception:
                pass
            if config.wipe_images_on_commit:
                self.fs.secure_wipe_directory(mig_dir, allowed_parent=base_root)
            self._release_source_pid(config.pid, migration_id)
            return drv_res

        # Stop lazy-dump daemon if running
        lazy_dump_pidfile = self._round_dir(migration_id, "final") / "lazy-dump.pid"
        if lazy_dump_pidfile.exists():
            self.criu.stop_daemon(lazy_dump_pidfile, proc_root=self.proc_root)

        # Confirm TCP_REPAIR=1 on source sockets before SIGKILL so kernel socket teardown cannot queue FIN/RST
        verified_src_pids = self._collect_verified_tree_pids(
            config.pid,
            recorded_pids=tree_pids,
            expected_starttimes=starttimes,
        )
        repair_res = self._apply_tcp_repair(verified_src_pids, enable=True)
        tcp_sockets_confirmed = (
            sum(r.tcp_sockets_confirmed for r in repair_res)
            if repair_res is not None
            else 0
        )

        # Terminate source process tree BEFORE marking source_state.json as committed
        self._signal_process_tree(
            config.pid,
            signal.SIGKILL,
            recorded_pids=tree_pids,
            expected_starttimes=starttimes,
        )

        if config.workload_id:
            try:
                validate_safe_identifier(config.workload_id, "workload_id")
                self.envelope.unfreeze_cgroup(config.workload_id)
            except Exception:
                pass

        if state_data is not None and source_state_file.exists():
            try:
                state_data["committed"] = True
                source_state_file.write_text(json.dumps(state_data), encoding="utf-8")
            except Exception:
                pass

        try:
            self.net.unlock_network(config.workload_ip, migration_id=migration_id)
        except Exception:
            pass
        if config.wipe_images_on_commit:
            self.fs.secure_wipe_directory(mig_dir, allowed_parent=base_root)
        self._release_source_pid(config.pid, migration_id)
        return {
            "committed": True,
            "tcp_repair_confirmed": repair_res is not None,
            "tcp_sockets_confirmed": tcp_sockets_confirmed,
        }

    def cleanup_dest(self, migration_id: str, wipe_images: bool) -> Dict[str, Any]:
        mig_dir = self._migration_dir(migration_id)
        base_root = self._migration_base_root(migration_id)
        final_dir = self._round_dir(migration_id, "final")
        lazy_pidfile = final_dir / "lazy-pages.pid"
        if lazy_pidfile.exists():
            self.criu.stop_daemon(lazy_pidfile, proc_root=self.proc_root)
        if mig_dir.exists():
            for ps_pidfile in mig_dir.glob("*/page-server.pid"):
                self.criu.stop_daemon(ps_pidfile, proc_root=self.proc_root)
        if wipe_images:
            saved_restore_state: Optional[str] = None
            keep_live_qmp_dir = False
            state_file = final_dir / "restore_state.json"
            if state_file.exists():
                try:
                    saved_restore_state = state_file.read_text(encoding="utf-8")
                    parsed_st = json.loads(saved_restore_state)
                    if parsed_st.get("driver") == WorkloadKind.QEMU_VM.value:
                        keep_live_qmp_dir = True
                except Exception:
                    pass
            if not keep_live_qmp_dir:
                self.fs.secure_wipe_directory(mig_dir, allowed_parent=base_root)
                if saved_restore_state is not None:
                    final_dir.mkdir(parents=True, exist_ok=True)
                    state_file.write_text(saved_restore_state, encoding="utf-8")
        return {"cleaned": True}

    def rollback_dest(
        self,
        migration_id: str,
        restored_pid: Optional[int],
        config_dict: Dict[str, Any],
        expected_restored_starttime: Optional[int] = None,
    ) -> Dict[str, Any]:
        mig_dir = self._migration_dir(migration_id)
        base_root = self._migration_base_root(migration_id)
        config = config_from_dict(config_dict)
        errors: List[str] = []

        drv = self._select_driver(config)
        if drv is not None:
            try:
                drv_res = drv.rollback_dest(migration_id, mig_dir, restored_pid, config)
                if drv_res.get("errors"):
                    errors.extend(drv_res["errors"])
            except Exception as exc:
                errors.append(f"driver rollback_dest failed: {exc}")
            try:
                self.net.teardown_tunnel(config, migration_id=migration_id)
            except Exception:
                pass
            try:
                self.net.release_ip_on_host(config, migration_id=migration_id)
            except Exception as exc:
                errors.append(f"release_ip_on_host failed: {exc}")
            try:
                self.net.unlock_network(config.workload_ip, migration_id=migration_id)
            except Exception:
                pass
            if not errors:
                self.fs.secure_wipe_directory(mig_dir, allowed_parent=base_root)
            return {
                "rolled_back_dest": len(errors) == 0,
                "tcp_repair_confirmed": False,
                "tcp_sockets_confirmed": 0,
                "errors": errors,
            }

        tree_pids: Optional[List[int]] = None
        starttimes: Optional[Dict[str, int]] = None
        state_file = self._round_dir(migration_id, "final") / "restore_state.json"
        if state_file.exists():
            try:
                data = json.loads(state_file.read_text(encoding="utf-8"))
                if restored_pid is None:
                    restored_pid = data.get("restored_pid")
                tree_pids = data.get("tree_pids")
                starttimes = data.get("starttimes")
            except Exception:
                pass

        if restored_pid is None:
            pidfile = self._round_dir(migration_id, "final") / "restored.pid"
            if pidfile.exists():
                try:
                    restored_pid = int(pidfile.read_text(encoding="utf-8").strip())
                except Exception:
                    pass

        if (
            restored_pid is not None
            and expected_restored_starttime is not None
            and (starttimes is None or starttimes.get(str(restored_pid)) is None)
        ):
            starttimes = dict(starttimes or {})
            starttimes[str(restored_pid)] = int(expected_restored_starttime)

        # Stop lazy-pages and page-server daemons if running
        lazy_pidfile = self._round_dir(migration_id, "final") / "lazy-pages.pid"
        if lazy_pidfile.exists():
            self.criu.stop_daemon(lazy_pidfile, proc_root=self.proc_root)
        if mig_dir.exists():
            for ps_pidfile in mig_dir.glob("*/page-server.pid"):
                self.criu.stop_daemon(ps_pidfile, proc_root=self.proc_root)

        tcp_repair_confirmed = False
        tcp_sockets_confirmed = 0
        if restored_pid is not None:
            verified_dst_pids = self._collect_verified_tree_pids(
                int(restored_pid),
                recorded_pids=tree_pids,
                expected_starttimes=starttimes,
            )
            try:
                repair_res = self._apply_tcp_repair(verified_dst_pids, enable=True)
                if repair_res is not None:
                    tcp_repair_confirmed = True
                    tcp_sockets_confirmed = sum(r.tcp_sockets_confirmed for r in repair_res)
            except TcpRepairError as exc:
                errors.append(f"TCP_REPAIR=1 confirmation before SIGKILL failed: {exc}")
                return {
                    "rolled_back_dest": False,
                    "tcp_repair_confirmed": False,
                    "tcp_sockets_confirmed": 0,
                    "errors": errors,
                }

            try:
                self._signal_process_tree(
                    int(restored_pid),
                    signal.SIGKILL,
                    recorded_pids=tree_pids,
                    expected_starttimes=starttimes,
                )
            except OSError as exc:
                if exc.errno != errno.ESRCH:
                    errors.append(f"SIGKILL({restored_pid}) failed: {exc}")

        try:
            self.net.teardown_tunnel(config, migration_id=migration_id)
        except Exception:
            pass
        try:
            self.net.release_ip_on_host(config, migration_id=migration_id)
        except Exception as exc:
            errors.append(f"release_ip_on_host failed: {exc}")
        try:
            self.net.unlock_network(config.workload_ip, migration_id=migration_id)
        except Exception:
            pass
        if not errors:
            self.fs.secure_wipe_directory(mig_dir, allowed_parent=base_root)
        return {
            "rolled_back_dest": len(errors) == 0,
            "tcp_repair_confirmed": tcp_repair_confirmed,
            "tcp_sockets_confirmed": tcp_sockets_confirmed,
            "errors": errors,
        }

    def rollback_source(
        self,
        migration_id: str,
        source_host: str,
        config_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        mig_dir = self._migration_dir(migration_id)
        base_root = self._migration_base_root(migration_id)
        config = config_from_dict(config_dict)
        errors: List[str] = []

        drv = self._select_driver(config)
        if drv is not None:
            try:
                self.net.teardown_tunnel(config, migration_id=migration_id)
            except Exception:
                pass
            try:
                self.net.announce_ip_on_host(config, target_host=source_host, ensure_assigned=True)
            except Exception as exc:
                errors.append(f"announce_ip_on_host failed: {exc}")
            try:
                self.net.unlock_network(config.workload_ip, migration_id=migration_id)
            except Exception:
                pass
            try:
                drv.rollback_source(migration_id, mig_dir, source_host, config)
            except Exception as exc:
                errors.append(f"driver rollback_source failed: {exc}")
            if not self._check_pid_alive(config.pid):
                errors.append(f"Source process {config.pid} is not alive after rollback attempt")
            if config.resume_cmd:
                try:
                    subprocess.run(
                        shlex.split(config.resume_cmd),
                        timeout=config.quiesce_timeout_sec,
                        check=True,
                        capture_output=True,
                        text=True,
                    )
                except Exception as r_exc:
                    errors.append(f"resume_cmd failed: {r_exc}")
            if not errors:
                self.fs.secure_wipe_directory(mig_dir, allowed_parent=base_root)
                self._release_source_pid(config.pid, migration_id)
            if errors:
                raise RuntimeError("; ".join(errors))
            return {
                "rolled_back_source": True,
                "resumed_pid": config.pid,
                "tcp_repair_confirmed": False,
                "tcp_sockets_confirmed": 0,
            }

        # Stop lazy-dump daemon if running
        lazy_dump_pidfile = self._round_dir(migration_id, "final") / "lazy-dump.pid"
        if lazy_dump_pidfile.exists():
            self.criu.stop_daemon(lazy_dump_pidfile, proc_root=self.proc_root)

        source_state_file = mig_dir / "source_state.json"
        tree_pids: Optional[List[int]] = None
        starttimes: Optional[Dict[str, int]] = None
        quiesced = False
        if source_state_file.exists():
            try:
                st_data = json.loads(source_state_file.read_text(encoding="utf-8"))
                tree_pids = st_data.get("tree_pids")
                starttimes = st_data.get("starttimes")
                quiesced = bool(st_data.get("quiesced", False))
            except Exception:
                pass

        verified_src_pids = self._collect_verified_tree_pids(
            config.pid,
            recorded_pids=tree_pids,
            expected_starttimes=starttimes,
        )
        tcp_repair_confirmed = False
        tcp_sockets_confirmed = 0
        try:
            repair_res = self._apply_tcp_repair(verified_src_pids, enable=False)
            if repair_res is not None:
                tcp_repair_confirmed = True
                tcp_sockets_confirmed = sum(r.tcp_sockets_confirmed for r in repair_res)
        except TcpRepairError as exc:
            errors.append(f"TCP_REPAIR=0 confirmation before SIGCONT failed: {exc}")
            raise RuntimeError("; ".join(errors)) from exc

        try:
            self.criu.run_gpu_rollback_hook(config)
        except Exception as exc:
            errors.append(f"gpu_rollback_hook failed: {exc}")
        try:
            self.net.teardown_tunnel(config, migration_id=migration_id)
        except Exception:
            pass
        try:
            self.net.announce_ip_on_host(config, target_host=source_host, ensure_assigned=True)
        except Exception as exc:
            errors.append(f"announce_ip_on_host failed: {exc}")
        try:
            self.net.unlock_network(config.workload_ip, migration_id=migration_id)
        except Exception:
            pass
        if config.workload_id:
            validate_safe_identifier(config.workload_id, "workload_id")
            self.envelope.unfreeze_cgroup(config.workload_id)

        try:
            self._signal_process_tree(
                config.pid,
                signal.SIGCONT,
                recorded_pids=tree_pids,
                expected_starttimes=starttimes,
            )
        except OSError as exc:
            errors.append(f"SIGCONT({config.pid}) failed: {exc}")

        check_pids = list(tree_pids) if tree_pids else [config.pid]
        for cp in check_pids:
            if not self._check_pid_alive(cp):
                errors.append(f"Source process {cp} is not alive after rollback attempt")

        if (quiesced or config.resume_cmd) and config.resume_cmd:
            try:
                subprocess.run(
                    shlex.split(config.resume_cmd),
                    timeout=config.quiesce_timeout_sec,
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except Exception as r_exc:
                errors.append(f"resume_cmd failed: {r_exc}")

        if not errors:
            self.fs.secure_wipe_directory(mig_dir, allowed_parent=base_root)
            self._release_source_pid(config.pid, migration_id)
        if errors:
            raise RuntimeError("; ".join(errors))
        return {
            "rolled_back_source": True,
            "resumed_pid": config.pid,
            "tcp_repair_confirmed": tcp_repair_confirmed,
            "tcp_sockets_confirmed": tcp_sockets_confirmed,
        }

    def dispatch_rpc(self, method: str, params: Dict[str, Any]) -> Any:
        """Dispatch an incoming JSON-RPC call to the corresponding service method."""
        allowed_methods = {
            "get_capabilities",
            "health_check",
            "get_metrics",
            "inspect_process",
            "diagnose_workload",
            "stat_files",
            "prepare_migration",
            "pre_sync_fs",
            "start_page_server",
            "finalize_page_server_round",
            "run_pre_dump",
            "run_check_only",
            "freeze_and_final_dump",
            "sign_final_checkpoint",
            "export_inband_metadata",
            "upload_checkpoint_files",
            "transfer_final_state",
            "restore_process",
            "release_ip",
            "claim_ip_and_resume",
            "verify_process",
            "verify_restored_stopped",
            "commit_source",
            "cleanup_dest",
            "rollback_dest",
            "rollback_source",
        }
        if method not in allowed_methods:
            self.metrics.record_rpc(str(method), 0.0, error=True)
            raise ValueError(f"Unknown RPC method: {method}")
        fn = getattr(self, method)
        mig_lock: Optional[threading.RLock] = None
        raw_mid = params.get("migration_id") if isinstance(params, dict) else None
        if isinstance(raw_mid, str):
            mig_lock = self._get_migration_lock(raw_mid)

        t0 = time.monotonic()
        try:
            if mig_lock is not None:
                with mig_lock:
                    res = fn(**params)
            else:
                res = fn(**params)
            self.metrics.record_rpc(method, (time.monotonic() - t0) * 1000.0, error=False)
            return res
        except Exception:
            self.metrics.record_rpc(method, (time.monotonic() - t0) * 1000.0, error=True)
            raise


class _RpcRequestHandler(socketserver.StreamRequestHandler):
    """Persistent keep-alive, TCP_NODELAY, timeout-enforced line-delimited JSON-RPC handler."""

    def handle(self) -> None:
        try:
            self.connection.settimeout(120.0)
        except Exception:
            pass
        if hasattr(socket, "IPPROTO_TCP") and hasattr(socket, "TCP_NODELAY"):
            try:
                self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            except OSError:
                pass

        while True:
            try:
                raw_line = self.rfile.readline(MAX_RPC_MESSAGE_BYTES + 1)
            except (ConnectionResetError, BrokenPipeError, TimeoutError, socket.timeout, ssl.SSLError, OSError):
                break
            if not raw_line:
                break
            oversized = len(raw_line) > MAX_RPC_MESSAGE_BYTES
            if oversized:
                resp = {
                    "ok": False,
                    "error": f"RPC message exceeds maximum allowed frame size ({MAX_RPC_MESSAGE_BYTES} bytes)",
                }
            else:
                try:
                    req = json.loads(raw_line.decode("utf-8"))
                    if not isinstance(req, dict):
                        raise ValueError("RPC request frame must be a JSON object")
                    method = req["method"]
                    params = req.get("params", {})
                    if not isinstance(method, str) or not isinstance(params, dict):
                        raise ValueError("Invalid RPC method or params type")
                    service: AgentService = self.server.agent_service  # type: ignore[attr-defined]
                    result = service.dispatch_rpc(method, params)
                    resp = {"ok": True, "result": result}
                except Exception as exc:
                    resp = {"ok": False, "error": str(exc)}
            payload = (json.dumps(resp) + "\n").encode("utf-8")
            try:
                self.wfile.write(payload)
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, ssl.SSLError, OSError):
                break
            if oversized:
                break


class _ThreadedTcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _ThreadedTcpServerV6(_ThreadedTcpServer):
    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        if hasattr(socket, "IPPROTO_IPV6") and hasattr(socket, "IPV6_V6ONLY"):
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        super().server_bind()


class _ThreadedHttpServerV6(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def _make_metrics_handler(service: AgentService) -> type[BaseHTTPRequestHandler]:
    class _MetricsHttpHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path == "/metrics":
                body = service.metrics.export_prometheus_text().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif path in ("/healthz", "/health"):
                body = (json.dumps(service.health_check()) + "\n").encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format: str, *args: Any) -> None:
            return

    return _MetricsHttpHandler


_ACTIVE_SERVERS: Dict[Tuple[str, int], AgentServer] = {}
_SSL_CONTEXT_CACHE: Dict[Tuple[str, str, str, bool, float, float, float], ssl.SSLContext] = {}
_SSL_CACHE_LOCK = threading.Lock()


def _get_cached_client_ssl_context(tls: TlsConfig) -> ssl.SSLContext:
    assert tls.ca_cert and tls.cert_file and tls.key_file
    ca_mtime = Path(tls.ca_cert).stat().st_mtime
    cert_mtime = Path(tls.cert_file).stat().st_mtime
    key_mtime = Path(tls.key_file).stat().st_mtime
    cache_key = (
        tls.ca_cert,
        tls.cert_file,
        tls.key_file,
        bool(tls.no_verify),
        ca_mtime,
        cert_mtime,
        key_mtime,
    )
    with _SSL_CACHE_LOCK:
        cached = _SSL_CONTEXT_CACHE.get(cache_key)
        if cached is not None:
            return cached
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.load_verify_locations(cafile=tls.ca_cert)
        if tls.no_verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        ctx.load_cert_chain(certfile=tls.cert_file, keyfile=tls.key_file)
        if len(_SSL_CONTEXT_CACHE) > 32:
            _SSL_CONTEXT_CACHE.clear()
        _SSL_CONTEXT_CACHE[cache_key] = ctx
        return ctx


class AgentServer:
    """Dual-stack TCP / mTLS JSON-RPC daemon wrapping an `AgentService` with optional `/metrics` HTTP exporter."""

    def __init__(
        self,
        host: str,
        port: int,
        service: AgentService,
        tls: Optional[TlsConfig] = None,
        metrics_port: Optional[int] = None,
    ) -> None:
        clean_host = host[1:-1] if host.startswith("[") and host.endswith("]") else host
        self.host = clean_host
        self.port = port
        self.service = service
        self.tls = tls if tls is not None else TlsConfig(enabled=False)
        self.metrics_port = metrics_port

        if self.tls.enabled:
            if not self.tls.ca_cert or not self.tls.cert_file or not self.tls.key_file:
                raise ValueError(
                    "TLS is enabled on AgentServer, but ca_cert, cert_file or key_file is missing. "
                    "Strict mTLS requires CA, certificate, and private key."
                )

        server_cls = _ThreadedTcpServerV6 if ":" in clean_host else _ThreadedTcpServer
        self._server = server_cls((clean_host, port), _RpcRequestHandler)
        self._server.agent_service = service  # type: ignore[attr-defined]
        if self.tls.enabled:
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(certfile=self.tls.cert_file, keyfile=self.tls.key_file)
            ctx.load_verify_locations(cafile=self.tls.ca_cert)
            ctx.verify_mode = ssl.CERT_REQUIRED
            self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)
        self._thread: Optional[threading.Thread] = None

        self._metrics_server: Optional[ThreadingHTTPServer] = None
        self._metrics_thread: Optional[threading.Thread] = None
        if metrics_port is not None:
            http_cls = _ThreadedHttpServerV6 if ":" in clean_host else ThreadingHTTPServer
            self._metrics_server = http_cls((clean_host, int(metrics_port)), _make_metrics_handler(service))

    @property
    def bound_address(self) -> Tuple[str, int]:
        addr = self._server.server_address
        return str(addr[0]), int(addr[1])

    @property
    def bound_metrics_address(self) -> Optional[Tuple[str, int]]:
        if self._metrics_server is None:
            return None
        addr = self._metrics_server.server_address
        return str(addr[0]), int(addr[1])

    def _register_active(self) -> None:
        host, port = self.bound_address
        _ACTIVE_SERVERS[(host, port)] = self
        _ACTIVE_SERVERS[("127.0.0.1", port)] = self
        _ACTIVE_SERVERS[("::1", port)] = self
        _ACTIVE_SERVERS[("localhost", port)] = self

    def _unregister_active(self) -> None:
        host, port = self.bound_address
        _ACTIVE_SERVERS.pop((host, port), None)
        _ACTIVE_SERVERS.pop(("127.0.0.1", port), None)
        _ACTIVE_SERVERS.pop(("::1", port), None)
        _ACTIVE_SERVERS.pop("localhost", None)  # type: ignore[arg-type]
        _ACTIVE_SERVERS.pop(("localhost", port), None)

    def start_background(self) -> None:
        self._register_active()
        if self._metrics_server is not None and self._metrics_thread is None:
            self._metrics_thread = threading.Thread(
                target=self._metrics_server.serve_forever, daemon=True
            )
            self._metrics_thread.start()
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def serve_forever(self) -> None:
        self._register_active()
        if self._metrics_server is not None and self._metrics_thread is None:
            self._metrics_thread = threading.Thread(
                target=self._metrics_server.serve_forever, daemon=True
            )
            self._metrics_thread.start()
        self._server.serve_forever()

    def shutdown(self) -> None:
        self._unregister_active()
        if self._metrics_server is not None:
            if self._metrics_thread is not None and self._metrics_thread.is_alive():
                self._metrics_server.shutdown()
            self._metrics_server.server_close()
            if self._metrics_thread:
                self._metrics_thread.join(timeout=2.0)
        if self._thread is not None and self._thread.is_alive():
            self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2.0)


class AgentClient:
    """
    Persistent keep-alive JSON-RPC over mTLS client for `AgentService`.
    Reuses a single `TCP_NODELAY` + TLS session across the migration hot path to eliminate
    repeated TCP + TLS handshake RTTs during the freeze blackout window.
    """

    def __init__(
        self,
        address: str,
        tls: Optional[TlsConfig] = None,
        timeout_sec: float = 30.0,
        direct_service: Optional[AgentService] = None,
        max_retries: int = 2,
        keep_alive: bool = True,
    ) -> None:
        self.address = address
        self.tls = tls if tls is not None else TlsConfig(enabled=False)
        self.timeout_sec = timeout_sec
        self._direct_service = direct_service
        self.max_retries = max(0, int(max_retries))
        self.keep_alive = bool(keep_alive)
        self._conn_lock = threading.Lock()
        self._sock: Optional[socket.socket] = None
        self._rfile: Optional[Any] = None
        self.connections_opened: int = 0

    @property
    def host(self) -> str:
        host, _ = parse_host_port(self.address, default_port=9700)
        return host

    @property
    def port(self) -> int:
        _, port = parse_host_port(self.address, default_port=9700)
        return port

    def _drop_conn_locked(self) -> None:
        rfile, sock = self._rfile, self._sock
        self._rfile = None
        self._sock = None
        if rfile is not None:
            try:
                rfile.close()
            except Exception:
                pass
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass

    def close(self) -> None:
        """Close any pooled persistent TCP/mTLS connection."""
        with self._conn_lock:
            self._drop_conn_locked()

    def __enter__(self) -> AgentClient:
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _open_conn_locked(self) -> Tuple[socket.socket, Any]:
        raw_sock = socket.create_connection((self.host, self.port), timeout=self.timeout_sec)
        try:
            raw_sock.settimeout(self.timeout_sec)
            if hasattr(socket, "IPPROTO_TCP") and hasattr(socket, "TCP_NODELAY"):
                try:
                    raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except OSError:
                    pass
            if self.tls.enabled:
                ctx = _get_cached_client_ssl_context(self.tls)
                conn = ctx.wrap_socket(raw_sock, server_hostname=self.host)
                conn.settimeout(self.timeout_sec)
            else:
                conn = raw_sock
            rfile = conn.makefile("rb")
            self.connections_opened += 1
            if self.keep_alive:
                self._sock = conn
                self._rfile = rfile
            return conn, rfile
        except Exception:
            try:
                raw_sock.close()
            except Exception:
                pass
            raise

    def _call_once(self, method: str, req_bytes: bytes, params: Dict[str, Any]) -> Any:
        with self._conn_lock:
            reused = False
            try:
                if self.keep_alive and self._sock is not None and self._rfile is not None:
                    conn, rfile = self._sock, self._rfile
                    conn.settimeout(self.timeout_sec)
                    reused = True
                else:
                    conn, rfile = self._open_conn_locked()
            except PermissionError:
                srv = _ACTIVE_SERVERS.get((self.host, self.port))
                if srv is None and self.host in ("127.0.0.1", "::1", "localhost"):
                    srv = _ACTIVE_SERVERS.get(("127.0.0.1", self.port)) or _ACTIVE_SERVERS.get(("::1", self.port))
                if srv is not None:
                    if self.tls.enabled:
                        for fpath in (self.tls.ca_cert, self.tls.cert_file, self.tls.key_file):
                            if not fpath or not Path(fpath).exists():
                                raise FileNotFoundError(f"TLS certificate file not found: {fpath}")
                    return srv.service.dispatch_rpc(method, params)
                raise

            try:
                try:
                    conn.sendall(req_bytes)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError, OSError):
                    if not reused:
                        raise
                    self._drop_conn_locked()
                    conn, rfile = self._open_conn_locked()
                    reused = False
                    conn.sendall(req_bytes)

                resp_line = rfile.readline(MAX_RPC_MESSAGE_BYTES + 1)
                if not resp_line and reused and method in IDEMPOTENT_READ_METHODS:
                    self._drop_conn_locked()
                    conn, rfile = self._open_conn_locked()
                    conn.sendall(req_bytes)
                    resp_line = rfile.readline(MAX_RPC_MESSAGE_BYTES + 1)

                if not self.keep_alive:
                    try:
                        rfile.close()
                    finally:
                        conn.close()
            except Exception:
                self._drop_conn_locked()
                if not self.keep_alive:
                    try:
                        conn.close()
                    except Exception:
                        pass
                raise

            if not resp_line:
                self._drop_conn_locked()
                raise RuntimeError(f"Empty RPC response from agent {self.address} for {method}")
            if len(resp_line) > MAX_RPC_MESSAGE_BYTES:
                self._drop_conn_locked()
                raise RuntimeError(f"Oversized RPC response from agent {self.address} for {method}")

        resp = json.loads(resp_line.decode("utf-8"))
        if not resp.get("ok"):
            raise RuntimeError(f"Agent {self.address} error in {method}: {resp.get('error')}")
        return resp.get("result")

    def call(self, method: str, **params: Any) -> Any:
        if self._direct_service is not None:
            return self._direct_service.dispatch_rpc(method, params)

        if self.tls.enabled and (not self.tls.ca_cert or not self.tls.cert_file or not self.tls.key_file):
            raise ValueError(
                "TLS is enabled on AgentClient, but ca_cert, cert_file or key_file is missing. "
                "Strict mTLS requires CA, certificate, and private key."
            )

        req_bytes = (json.dumps({"method": method, "params": params}) + "\n").encode("utf-8")
        attempts = 1 + (self.max_retries if method in IDEMPOTENT_READ_METHODS else 0)
        last_exc: Optional[BaseException] = None
        for attempt in range(attempts):
            try:
                return self._call_once(method, req_bytes, params)
            except (ConnectionResetError, TimeoutError, socket.timeout) as exc:
                last_exc = exc
                if attempt + 1 < attempts:
                    time.sleep(0.05 * (attempt + 1))
                    continue
                raise
        assert last_exc is not None
        raise last_exc
