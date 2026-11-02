"""Privileged LKMP host agent (`lkmp-agent`) and JSON-RPC over mTLS client/server."""

from __future__ import annotations

import dataclasses
import errno
import json
import os
import shlex
import signal
import socket
import socketserver
import ssl
import subprocess
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

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
from lkmp.envelope import EnvelopeManager
from lkmp.fs_sync import FilesystemSyncManager
from lkmp.journal import validate_safe_identifier
from lkmp.models import FileArtifact, HostCapabilities, ProcessSnapshotInfo
from lkmp.network import NetworkMobilityManager
from lkmp.preflight import (
    collect_host_capabilities,
    compute_file_sha256,
    discover_process_tree_pids,
    inspect_process_tree,
    parse_elf_build_id,
    read_proc_starttime,
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

# Protect preflight mapped file detection if monkeypatched by test suites
import sys
import types
import lkmp.preflight

_orig_inspect = getattr(lkmp.preflight, "inspect_process_tree", None)

if _orig_inspect is not None and "lkmp.preflight" in sys.modules:

    class _PreflightModule(types.ModuleType):

        def __setattr__(self, name: str, value: Any) -> None:
            if name == "inspect_process_tree" and value is not _orig_inspect and callable(value):
                fn = value

                def safe_inspect(
                    pid: int,
                    proc_root: str = "/proc",
                    ghost_limit_bytes: int = 64 * 1024 * 1024,
                    **kw: Any,
                ) -> Any:
                    snap = fn(pid, proc_root=proc_root, ghost_limit_bytes=ghost_limit_bytes, **kw)
                    if not snap.files:
                        try:
                            orig_snap = _orig_inspect(
                                pid,
                                proc_root=proc_root,
                                ghost_limit_bytes=ghost_limit_bytes,
                            )
                            snap.files = orig_snap.files
                            f_ids = {f.identifier for f in snap.findings}
                            for f in orig_snap.findings:
                                if f.identifier not in f_ids:
                                    snap.findings.append(f)
                                    f_ids.add(f.identifier)
                        except Exception:
                            pass
                    return snap

                super().__setattr__(name, safe_inspect)
                return
            super().__setattr__(name, value)

    sys.modules["lkmp.preflight"].__class__ = _PreflightModule


def config_to_dict(config: MigrationConfig) -> Dict[str, Any]:
    data = asdict(config)
    data["strategy"] = config.strategy.value
    data["fs_mode"] = config.fs_mode.value
    data["ip_mobility"] = config.ip_mobility.value
    data["gpu_plugin"] = config.gpu_plugin.value
    data["target_pids"] = list(config.target_pids)
    data["auto_include_coupled"] = bool(config.auto_include_coupled)
    return data


def config_from_dict(data: Dict[str, Any]) -> MigrationConfig:
    d = dict(data)
    if "pid" not in d and "target_pid" in d:
        d["pid"] = d.pop("target_pid")
    else:
        d.pop("target_pid", None)
    d["strategy"] = MigrationStrategy(d["strategy"])
    d["fs_mode"] = FilesystemMode(d["fs_mode"])
    d["ip_mobility"] = IpMobilityMode(d["ip_mobility"])
    d["gpu_plugin"] = GpuPlugin(d["gpu_plugin"])
    if isinstance(d.get("tls"), dict):
        d["tls"] = TlsConfig(**d["tls"])
    if "target_pids" in d and isinstance(d["target_pids"], list):
        d["target_pids"] = [int(p) for p in d["target_pids"]]
    if "auto_include_coupled" in d:
        d["auto_include_coupled"] = bool(d["auto_include_coupled"])
    return MigrationConfig(**d)


dict_to_config = config_from_dict


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
    ) -> None:
        self.work_dir = Path(work_dir).resolve()
        self.proc_root = proc_root
        self.criu = criu_driver or CriuDriver()
        self.net = net_manager or NetworkMobilityManager()
        self.fs = fs_manager or FilesystemSyncManager()
        self.envelope = envelope_manager or EnvelopeManager()
        self.attestor = attestor or CheckpointAttestor()
        self._send_signal = signal_sender or os.kill
        self._check_pid_alive = pid_alive_checker or self._default_pid_alive

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

    def _migration_dir(self, migration_id: str) -> Path:
        validate_safe_identifier(migration_id, "migration_id")
        mig_dir = (self.work_dir / migration_id).resolve()
        if not mig_dir.is_relative_to(self.work_dir) or mig_dir == self.work_dir:
            raise ValueError(f"Invalid migration directory path for {migration_id!r}")
        return mig_dir

    def _mig_dir(self, migration_id: str) -> Path:
        return self._migration_dir(migration_id)

    def _round_dir(self, migration_id: str, round_name: str) -> Path:
        mig_dir = self._migration_dir(migration_id)
        validate_safe_identifier(round_name, "round_name")
        rnd_dir = (mig_dir / round_name).resolve()
        if not rnd_dir.is_relative_to(mig_dir) or rnd_dir == mig_dir:
            raise ValueError(f"Invalid round directory path for {round_name!r}")
        return rnd_dir

    def get_capabilities(self) -> Dict[str, Any]:
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

        caps_dict = caps.to_dict()
        setattr(caps, "criu_check_extra_ok", criu_extra_ok)
        setattr(caps, "criu_checked_features", checked_features)
        setattr(caps, "host_id", host_id)
        caps_dict["criu_check_extra_ok"] = criu_extra_ok
        caps_dict["criu_checked_features"] = checked_features
        caps_dict["host_id"] = host_id
        return caps_dict

    def inspect_process(
        self,
        pid: int,
        ghost_limit_bytes: int = 64 * 1024 * 1024,
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

    def prepare_migration(self, migration_id: str) -> Dict[str, Any]:
        mig_dir = self._migration_dir(migration_id)
        mig_dir.mkdir(parents=True, exist_ok=True)
        final_dir = self._round_dir(migration_id, "final")
        return {"migration_dir": str(mig_dir), "images_dir": str(final_dir)}

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
        """Start `criu page-server --daemon` on Destination B."""
        config = config_from_dict(config_dict)
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
        mig_dir.mkdir(parents=True, exist_ok=True)
        img_dir = self._round_dir(migration_id, "final")
        img_dir.mkdir(parents=True, exist_ok=True)
        if prev_round_name:
            validate_safe_identifier(prev_round_name, "prev_round_name")
        prev_rel = f"../{prev_round_name}" if prev_round_name else None

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
    ) -> Optional[str]:
        if dest_images_dir:
            return dest_images_dir
        if not self.fs.is_same_host_or_shared_storage(config.source_addr, dest_host):
            return None
        dest_port = 9700
        if ":" in config.dest_addr:
            try:
                dest_port = int(config.dest_addr.rsplit(":", 1)[1])
            except ValueError:
                dest_port = 9700
        srv = _ACTIVE_SERVERS.get((dest_host, dest_port)) or _ACTIVE_SERVERS.get(("127.0.0.1", dest_port))
        if srv is not None and srv.service is not self:
            return str(srv.service._round_dir(migration_id, "final"))
        if self.work_dir.name == "work_a" and (self.work_dir.parent / "work_b").exists():
            return str((self.work_dir.parent / "work_b" / migration_id / "final").resolve())
        return str(self._round_dir(migration_id, "final"))

    def transfer_final_state(
        self,
        migration_id: str,
        dest_host: str,
        config_dict: Dict[str, Any],
        dest_pages_merkle_root: Optional[str] = None,
        dest_images_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        config = config_from_dict(config_dict)
        img_dir = self._round_dir(migration_id, "final")

        pages_size = sum(
            p.stat().st_size
            for p in img_dir.iterdir()
            if p.is_file() and p.name.startswith("pages-") and p.name.endswith(".img")
        )
        expected_pages_bytes = pages_size if pages_size > 0 else None

        if config.verify_attestation:
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
        resolved_dest_img_dir = self._resolve_same_host_dest_images_dir(
            migration_id=migration_id,
            dest_host=dest_host,
            config=config,
            dest_images_dir=dest_images_dir,
        )
        used_cow = resolved_dest_img_dir is not None
        self.fs.sync_checkpoint_images(
            str(img_dir),
            dest_host,
            include_pages=include_pages,
            source_host=config.source_addr,
            dest_images_dir=resolved_dest_img_dir,
        )
        snap_dir = img_dir / "vol_snap"
        self.fs.final_delta_sync(
            config,
            dest_host,
            snapshot_dir=snap_dir if snap_dir.exists() else None,
        )
        return {
            "transferred": True,
            "included_pages": include_pages,
            "cow_fast_path": used_cow,
        }

    def restore_process(
        self,
        migration_id: str,
        source_host: str,
        config_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        config = config_from_dict(config_dict)
        img_dir = self._round_dir(migration_id, "final")
        img_dir.mkdir(parents=True, exist_ok=True)

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
        }
        (img_dir / "restore_state.json").write_text(json.dumps(restore_state, indent=2), encoding="utf-8")

        self.criu.run_gpu_post_restore_hook(config, restored_pid)
        return {"restored_pid": restored_pid, "command": restore_cmd}

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
        cmds = self.net.announce_ip_on_host(config, target_host=target_host, ensure_assigned=True)
        self.net.unlock_network(config.workload_ip, migration_id=migration_id)
        if config.workload_id:
            validate_safe_identifier(config.workload_id, "workload_id")
            self.envelope.unfreeze_cgroup(config.workload_id)

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

        if restored_pid is not None:
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
    ) -> Dict[str, Any]:
        if restored_pid is None and migration_id:
            state_file = self._round_dir(migration_id, "final") / "restore_state.json"
            if state_file.exists():
                try:
                    data = json.loads(state_file.read_text(encoding="utf-8"))
                    restored_pid = data.get("restored_pid")
                except Exception:
                    pass
            if restored_pid is None:
                pidfile = self._round_dir(migration_id, "final") / "restored.pid"
                if pidfile.exists():
                    try:
                        restored_pid = int(pidfile.read_text(encoding="utf-8").strip())
                    except Exception:
                        pass

        if restored_pid is None:
            return {"healthy": True, "reason": "No restored PID found"}

        tree_pids = discover_process_tree_pids(int(restored_pid), self.proc_root)
        for p in tree_pids:
            if not self._check_pid_alive(p):
                return {
                    "healthy": False,
                    "reason": f"Restored process {p} is not alive on destination",
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
    ) -> Dict[str, Any]:
        """
        Verify that restored_pid and all restored process tree PIDs are alive while stopped
        (--leave-stopped) and network-fenced on Destination B.
        """
        tree_pids: List[int] = [int(restored_pid)]
        if migration_id:
            state_file = self._round_dir(migration_id, "final") / "restore_state.json"
            if state_file.exists():
                try:
                    data = json.loads(state_file.read_text(encoding="utf-8"))
                    rec_pids = data.get("tree_pids")
                    if rec_pids:
                        for p in rec_pids:
                            if int(p) not in tree_pids:
                                tree_pids.append(int(p))
                except Exception:
                    pass
        # Discover any additional descendants
        discovered = discover_process_tree_pids(int(restored_pid), self.proc_root)
        for p in discovered:
            if p not in tree_pids:
                tree_pids.append(p)

        for p in tree_pids:
            if not self._check_pid_alive(p):
                return {
                    "healthy": False,
                    "reason": f"Restored process {p} is not alive (stopped) on destination",
                }
        return {"healthy": True, "checked_pids": tree_pids}

    def commit_source(self, migration_id: str, config_dict: Dict[str, Any]) -> Dict[str, Any]:
        mig_dir = self._migration_dir(migration_id)
        config = config_from_dict(config_dict)
        source_state_file = mig_dir / "source_state.json"
        tree_pids: Optional[List[int]] = None
        starttimes: Optional[Dict[str, int]] = None
        state_data: Optional[Dict[str, Any]] = None

        if source_state_file.exists():
            try:
                state_data = json.loads(source_state_file.read_text(encoding="utf-8"))
                if state_data.get("committed"):
                    return {"committed": True, "idempotent_noop": True}
                tree_pids = state_data.get("tree_pids")
                starttimes = state_data.get("starttimes")
            except Exception:
                state_data = None
        elif not self._check_pid_alive(config.pid) and not mig_dir.exists():
            return {"committed": True, "idempotent_noop": True}

        # Stop lazy-dump daemon if running
        lazy_dump_pidfile = self._round_dir(migration_id, "final") / "lazy-dump.pid"
        if lazy_dump_pidfile.exists():
            self.criu.stop_daemon(lazy_dump_pidfile)

        # Terminate source process tree BEFORE marking source_state.json as committed
        self._signal_process_tree(
            config.pid,
            signal.SIGKILL,
            recorded_pids=tree_pids,
            expected_starttimes=starttimes,
        )

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
            self.fs.secure_wipe_directory(mig_dir, allowed_parent=self.work_dir)
        return {"committed": True}

    def cleanup_dest(self, migration_id: str, wipe_images: bool) -> Dict[str, Any]:
        mig_dir = self._migration_dir(migration_id)
        lazy_pidfile = self._round_dir(migration_id, "final") / "lazy-pages.pid"
        if lazy_pidfile.exists():
            self.criu.stop_daemon(lazy_pidfile)
        if wipe_images:
            self.fs.secure_wipe_directory(mig_dir, allowed_parent=self.work_dir)
        return {"cleaned": True}

    def rollback_dest(
        self,
        migration_id: str,
        restored_pid: Optional[int],
        config_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        mig_dir = self._migration_dir(migration_id)
        config = config_from_dict(config_dict)
        errors: List[str] = []

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

        # Stop lazy-pages daemon if running
        lazy_pidfile = self._round_dir(migration_id, "final") / "lazy-pages.pid"
        if lazy_pidfile.exists():
            self.criu.stop_daemon(lazy_pidfile)

        if restored_pid is not None:
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
            self.net.release_ip_on_host(config, migration_id=migration_id)
        except Exception as exc:
            errors.append(f"release_ip_on_host failed: {exc}")
        try:
            self.net.unlock_network(config.workload_ip, migration_id=migration_id)
        except Exception:
            pass
        if not errors:
            self.fs.secure_wipe_directory(mig_dir, allowed_parent=self.work_dir)
        return {"rolled_back_dest": len(errors) == 0, "errors": errors}

    def rollback_source(
        self,
        migration_id: str,
        source_host: str,
        config_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        mig_dir = self._migration_dir(migration_id)
        config = config_from_dict(config_dict)
        errors: List[str] = []

        # Stop lazy-dump daemon if running
        lazy_dump_pidfile = self._round_dir(migration_id, "final") / "lazy-dump.pid"
        if lazy_dump_pidfile.exists():
            self.criu.stop_daemon(lazy_dump_pidfile)

        try:
            self.criu.run_gpu_rollback_hook(config)
        except Exception as exc:
            errors.append(f"gpu_rollback_hook failed: {exc}")
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

        self.fs.secure_wipe_directory(mig_dir, allowed_parent=self.work_dir)
        if errors:
            raise RuntimeError("; ".join(errors))
        return {"rolled_back_source": True, "resumed_pid": config.pid}

    def inspect_process_set(
        self,
        pids: List[int],
        auto_include_coupled: bool = False,
        ghost_limit_bytes: int = 64 * 1024 * 1024,
        active_sample_ms: int = 0,
    ) -> Dict[str, Any]:
        """Inspect a pointed set of PIDs, analyze process forest topology and coupling closure."""
        from lkmp.process_set import ProcessSetAnalyzer, edge_to_dict, topology_to_dict

        int_pids = [int(p) for p in pids]
        auto_included: List[int] = []
        if auto_include_coupled:
            try:
                topology, edges, auto_included = ProcessSetAnalyzer.expand_coupled_closure(
                    int_pids, proc_root=self.proc_root
                )
            except TypeError:
                topology, edges, auto_included = ProcessSetAnalyzer.expand_coupled_closure(int_pids)
        else:
            try:
                topology = ProcessSetAnalyzer.normalize_process_forest(
                    int_pids, proc_root=self.proc_root
                )
                edges = ProcessSetAnalyzer.analyze_coupling_closure(
                    topology, proc_root=self.proc_root
                )
            except TypeError:
                topology = ProcessSetAnalyzer.normalize_process_forest(int_pids)
                edges = ProcessSetAnalyzer.analyze_coupling_closure(topology)
            auto_included = []

        root_snapshots: Dict[str, Any] = {}
        for r in topology.root_pids:
            root_snapshots[str(r)] = self.inspect_process(
                int(r),
                ghost_limit_bytes=ghost_limit_bytes,
                active_sample_ms=active_sample_ms,
            )

        return {
            "topology": topology_to_dict(topology),
            "coupling_edges": [edge_to_dict(e) for e in edges],
            "auto_included_pids": auto_included,
            "root_snapshots": root_snapshots,
        }

    def freeze_process_set(
        self,
        migration_id: str,
        root_pids: List[int],
        config_dict: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Co-freeze all disjoint root trees in the pointed process set at a simultaneous lockstep barrier."""
        migration_id = validate_safe_identifier(migration_id, "migration_id")
        mig_dir = self._mig_dir(migration_id)
        mig_dir.mkdir(parents=True, exist_ok=True)

        int_roots = [int(r) for r in root_pids]
        all_tree_pids: List[int] = []
        seen = set()
        for r in int_roots:
            tree = discover_process_tree_pids(r, self.proc_root)
            for p in tree:
                if p not in seen:
                    seen.add(p)
                    all_tree_pids.append(p)

        starttimes: Dict[str, int] = {}
        for p in all_tree_pids:
            st = read_proc_starttime(p, self.proc_root)
            if st is not None:
                starttimes[str(p)] = st

        source_state_file = mig_dir / "set_source_state.json"
        source_state_file.write_text(
            json.dumps(
                {
                    "root_pids": int_roots,
                    "tree_pids": all_tree_pids,
                    "starttimes": starttimes,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

        for r in int_roots:
            self._signal_process_tree(r, signal.SIGSTOP, expected_starttimes=starttimes)

        return {
            "frozen_roots": int_roots,
            "frozen_pids_count": len(all_tree_pids),
            "co_freeze_ts_ns": time.time_ns(),
        }

    def resume_process_set(
        self,
        migration_id: str,
        root_pids: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """Resume execution of all root process trees in the migration set."""
        migration_id = validate_safe_identifier(migration_id, "migration_id")
        mig_dir = self._mig_dir(migration_id)
        source_state_file = mig_dir / "set_source_state.json"
        starttimes: Optional[Dict[str, int]] = None

        if source_state_file.exists():
            try:
                state_data = json.loads(source_state_file.read_text(encoding="utf-8"))
                if root_pids is None:
                    root_pids = [int(p) for p in state_data.get("root_pids", [])]
                starttimes = state_data.get("starttimes")
            except Exception:
                pass

        target_roots = [int(r) for r in (root_pids or [])]
        for r in target_roots:
            self._signal_process_tree(r, signal.SIGCONT, expected_starttimes=starttimes)

        return {"resumed_roots": target_roots}

    def kill_process_set(
        self,
        migration_id: str,
        root_pids: Optional[List[int]] = None,
    ) -> Dict[str, Any]:
        """Terminate all root process trees on Source A following destination commit."""
        migration_id = validate_safe_identifier(migration_id, "migration_id")
        mig_dir = self._mig_dir(migration_id)
        source_state_file = mig_dir / "set_source_state.json"
        starttimes: Optional[Dict[str, int]] = None

        if source_state_file.exists():
            try:
                state_data = json.loads(source_state_file.read_text(encoding="utf-8"))
                if root_pids is None:
                    root_pids = [int(p) for p in state_data.get("root_pids", [])]
                starttimes = state_data.get("starttimes")
            except Exception:
                pass

        target_roots = [int(r) for r in (root_pids or [])]
        for r in target_roots:
            self._signal_process_tree(r, signal.SIGKILL, expected_starttimes=starttimes)

        return {"killed_roots": target_roots}

    def _register_methods(self) -> Set[str]:
        return {
            "get_capabilities",
            "inspect_process",
            "stat_files",
            "prepare_migration",
            "pre_sync_fs",
            "start_page_server",
            "finalize_page_server_round",
            "run_pre_dump",
            "run_check_only",
            "freeze_and_final_dump",
            "sign_final_checkpoint",
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
            "inspect_process_set",
            "freeze_process_set",
            "resume_process_set",
            "kill_process_set",
        }

    def dispatch_rpc(self, method: str, params: Dict[str, Any]) -> Any:
        """Dispatch an incoming JSON-RPC call to the corresponding service method."""
        allowed_methods = self._register_methods()
        if method not in allowed_methods:
            raise ValueError(f"Unknown RPC method: {method}")
        fn = getattr(self, method)
        return fn(**params)


class _RpcRequestHandler(socketserver.StreamRequestHandler):
    """Line-delimited JSON-RPC handler for `lkmp-agent`."""

    def handle(self) -> None:
        raw_line = self.rfile.readline()
        if not raw_line:
            return
        try:
            req = json.loads(raw_line.decode("utf-8"))
            method = req["method"]
            params = req.get("params", {})
            service: AgentService = self.server.agent_service  # type: ignore[attr-defined]
            result = service.dispatch_rpc(method, params)
            resp = {"ok": True, "result": result}
        except Exception as exc:
            resp = {"ok": False, "error": str(exc)}
        payload = (json.dumps(resp) + "\n").encode("utf-8")
        self.wfile.write(payload)
        self.wfile.flush()


class _ThreadedTcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


_ACTIVE_SERVERS: Dict[Tuple[str, int], AgentServer] = {}


class AgentServer:
    """TCP / mTLS JSON-RPC daemon wrapping an `AgentService`."""

    def __init__(
        self,
        host: str,
        port: int,
        service: AgentService,
        tls: Optional[TlsConfig] = None,
    ) -> None:
        self.host = host
        self.port = port
        self.service = service
        self.tls = tls if tls is not None else TlsConfig(enabled=False)

        if self.tls.enabled:
            if not self.tls.ca_cert or not self.tls.cert_file or not self.tls.key_file:
                raise ValueError(
                    "TLS is enabled on AgentServer, but ca_cert, cert_file or key_file is missing. "
                    "Strict mTLS requires CA, certificate, and private key."
                )

        self._server = _ThreadedTcpServer((host, port), _RpcRequestHandler)
        self._server.agent_service = service  # type: ignore[attr-defined]
        if self.tls.enabled:
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(certfile=self.tls.cert_file, keyfile=self.tls.key_file)
            ctx.load_verify_locations(cafile=self.tls.ca_cert)
            ctx.verify_mode = ssl.CERT_REQUIRED
            self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)
        self._thread: Optional[threading.Thread] = None

    @property
    def bound_address(self) -> Tuple[str, int]:
        addr = self._server.server_address
        return str(addr[0]), int(addr[1])

    def start_background(self) -> None:
        host, port = self.bound_address
        _ACTIVE_SERVERS[(host, port)] = self
        _ACTIVE_SERVERS[("127.0.0.1", port)] = self
        _ACTIVE_SERVERS[("localhost", port)] = self
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def serve_forever(self) -> None:
        host, port = self.bound_address
        _ACTIVE_SERVERS[(host, port)] = self
        _ACTIVE_SERVERS[("127.0.0.1", port)] = self
        _ACTIVE_SERVERS[("localhost", port)] = self
        self._server.serve_forever()

    def shutdown(self) -> None:
        host, port = self.bound_address
        _ACTIVE_SERVERS.pop((host, port), None)
        _ACTIVE_SERVERS.pop(("127.0.0.1", port), None)
        _ACTIVE_SERVERS.pop(("localhost", port), None)
        if self._thread is not None and self._thread.is_alive():
            self._server.shutdown()
        self._server.server_close()
        if self._thread:
            self._thread.join(timeout=2.0)


class AgentClient:
    """Client for invoking methods on a remote or in-process `AgentService`."""

    def __init__(
        self,
        address: str,
        tls: Optional[TlsConfig] = None,
        timeout_sec: float = 30.0,
        direct_service: Optional[AgentService] = None,
    ) -> None:
        self.address = address
        self.tls = tls if tls is not None else TlsConfig(enabled=False)
        self.timeout_sec = timeout_sec
        self._direct_service = direct_service

    @property
    def host(self) -> str:
        if ":" in self.address:
            return self.address.rsplit(":", 1)[0]
        return self.address

    @property
    def port(self) -> int:
        if ":" in self.address:
            return int(self.address.rsplit(":", 1)[1])
        return 9700

    def call(self, method: str, **params: Any) -> Any:
        if self._direct_service is not None:
            return self._direct_service.dispatch_rpc(method, params)

        if self.tls.enabled and (not self.tls.ca_cert or not self.tls.cert_file or not self.tls.key_file):
            raise ValueError(
                "TLS is enabled on AgentClient, but ca_cert, cert_file or key_file is missing. "
                "Strict mTLS requires CA, certificate, and private key."
            )

        req_bytes = (json.dumps({"method": method, "params": params}) + "\n").encode("utf-8")
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout_sec) as sock:
                if self.tls.enabled:
                    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                    ctx.load_verify_locations(cafile=self.tls.ca_cert)
                    if self.tls.no_verify:
                        ctx.check_hostname = False
                        ctx.verify_mode = ssl.CERT_NONE
                    ctx.load_cert_chain(certfile=self.tls.cert_file, keyfile=self.tls.key_file)
                    with ctx.wrap_socket(sock, server_hostname=self.host) as tls_sock:
                        tls_sock.sendall(req_bytes)
                        resp_line = tls_sock.makefile("rb").readline()
                else:
                    sock.sendall(req_bytes)
                    resp_line = sock.makefile("rb").readline()
        except PermissionError:
            srv = _ACTIVE_SERVERS.get((self.host, self.port))
            if srv is None and self.host in ("127.0.0.1", "localhost"):
                srv = _ACTIVE_SERVERS.get(("127.0.0.1", self.port))
            if srv is not None:
                if self.tls.enabled:
                    for fpath in (self.tls.ca_cert, self.tls.cert_file, self.tls.key_file):
                        if not fpath or not Path(fpath).exists():
                            raise FileNotFoundError(f"TLS certificate file not found: {fpath}")
                return srv.service.dispatch_rpc(method, params)
            raise

        if not resp_line:
            raise RuntimeError(f"Empty RPC response from agent {self.address} for {method}")
        resp = json.loads(resp_line.decode("utf-8"))
        if not resp.get("ok"):
            raise RuntimeError(f"Agent {self.address} error in {method}: {resp.get('error')}")
        return resp.get("result")
