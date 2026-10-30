"""Privileged LKMP host agent (`lkmp-agent`) and JSON-RPC over TLS client/server."""

from __future__ import annotations

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

from lkmp.attestation import CheckpointAttestor
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
from lkmp.models import FileArtifact, HostCapabilities, ProcessSnapshotInfo
from lkmp.network import NetworkMobilityManager
from lkmp.preflight import (
    collect_host_capabilities,
    compute_file_sha256,
    inspect_process_tree,
    parse_elf_build_id,
)


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
    ) -> None:
        self.work_dir = Path(work_dir)
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

    def _round_dir(self, migration_id: str, round_name: str) -> Path:
        return self.work_dir / migration_id / round_name

    def get_capabilities(self) -> Dict[str, Any]:
        caps = collect_host_capabilities(proc_root=self.proc_root)
        try:
            res = self.criu.runner([self.criu.criu_bin, "--version"])
            caps.criu_available = res.returncode == 0
            if res.stdout:
                caps.criu_version = res.stdout.splitlines()[0].strip()
        except Exception:
            caps.criu_available = False
        return caps.to_dict()

    def inspect_process(self, pid: int, ghost_limit_bytes: int) -> Dict[str, Any]:
        snapshot = inspect_process_tree(
            pid=pid,
            proc_root=self.proc_root,
            ghost_limit_bytes=ghost_limit_bytes,
        )
        return snapshot.to_dict()

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
        mig_dir = self.work_dir / migration_id
        mig_dir.mkdir(parents=True, exist_ok=True)
        return {"migration_dir": str(mig_dir)}

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
        config = config_from_dict(config_dict)
        img_dir = self._round_dir(migration_id, round_name)
        img_dir.mkdir(parents=True, exist_ok=True)
        prev_rel = f"../{prev_round_name}" if prev_round_name else None
        cmd = self.criu.build_page_server_cmd(
            images_dir=str(img_dir),
            port=config.page_server_port,
            tls=config.tls,
            prev_images_dir=prev_rel,
        )
        self.criu.runner(cmd)
        return {"images_dir": str(img_dir), "command": cmd}

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
        img_dir = self._round_dir(migration_id, "final")
        img_dir.mkdir(parents=True, exist_ok=True)
        prev_rel = f"../{prev_round_name}" if prev_round_name else None

        # 1. Lock network to suppress TCP RSTs
        self.net.lock_network(config.workload_ip)

        # 2. Freeze cgroup if workload_id is provided
        if config.workload_id:
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
        self.criu.runner(cmd)

        merkle_root: Optional[str] = None
        if config.verify_attestation:
            manifest = self.attestor.generate_manifest(
                images_dir=img_dir,
                migration_id=migration_id,
                pid=config.pid,
            )
            merkle_root = manifest.merkle_root

        return {
            "images_dir": str(img_dir),
            "command": cmd,
            "merkle_root": merkle_root,
        }

    def transfer_final_state(
        self,
        migration_id: str,
        dest_host: str,
        config_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        config = config_from_dict(config_dict)
        img_dir = self._round_dir(migration_id, "final")
        self.fs.sync_metadata_images(str(img_dir), dest_host)
        self.fs.final_delta_sync(config, dest_host)
        return {"transferred": True}

    def restore_process(
        self,
        migration_id: str,
        source_host: str,
        config_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        config = config_from_dict(config_dict)
        img_dir = self._round_dir(migration_id, "final")
        img_dir.mkdir(parents=True, exist_ok=True)

        # Verify cryptographic Merkle-tree checkpoint attestation if manifest is present
        manifest_path = img_dir / CheckpointAttestor.MANIFEST_FILENAME
        if config.verify_attestation and manifest_path.exists():
            self.attestor.verify_directory(img_dir, expected_migration_id=migration_id)

        # Lock network on Destination B until IP switchover completes
        self.net.lock_network(config.workload_ip)

        if config.strategy in (MigrationStrategy.LAZY, MigrationStrategy.HYBRID):
            lazy_cmd = self.criu.build_lazy_pages_daemon_cmd(
                config=config,
                images_dir=str(img_dir),
                source_host=source_host,
            )
            self.criu.runner(lazy_cmd)

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

        self.criu.run_gpu_post_restore_hook(config, restored_pid)
        return {"restored_pid": restored_pid, "command": restore_cmd}

    def release_ip(self, config_dict: Dict[str, Any]) -> Dict[str, Any]:
        config = config_from_dict(config_dict)
        cmds = self.net.release_ip_on_host(config)
        return {"commands": cmds}

    def claim_ip_and_resume(
        self,
        restored_pid: int,
        target_host: str,
        config_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        config = config_from_dict(config_dict)
        cmds = self.net.claim_ip_on_host(config, target_host=target_host)
        self.net.unlock_network(config.workload_ip)
        if config.workload_id:
            self.envelope.unfreeze_cgroup(config.workload_id)
        try:
            self._send_signal(restored_pid, signal.SIGCONT)
        except OSError:
            pass
        return {"resumed_pid": restored_pid, "ip_commands": cmds}

    def verify_process(
        self,
        restored_pid: int,
        health_check_cmd: Optional[str],
        timeout_sec: float = 5.0,
    ) -> Dict[str, Any]:
        if not self._check_pid_alive(restored_pid):
            return {
                "healthy": False,
                "reason": f"Restored process {restored_pid} is not alive on destination",
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

    def commit_source(self, migration_id: str, config_dict: Dict[str, Any]) -> Dict[str, Any]:
        config = config_from_dict(config_dict)
        try:
            self._send_signal(config.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            self.net.unlock_network(config.workload_ip)
        except Exception:
            pass
        if config.wipe_images_on_commit:
            self.fs.secure_wipe_directory(self.work_dir / migration_id)
        return {"committed": True}

    def cleanup_dest(self, migration_id: str, wipe_images: bool) -> Dict[str, Any]:
        if wipe_images:
            self.fs.secure_wipe_directory(self.work_dir / migration_id)
        return {"cleaned": True}

    def rollback_dest(
        self,
        migration_id: str,
        restored_pid: Optional[int],
        config_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        config = config_from_dict(config_dict)
        if restored_pid is not None:
            try:
                self._send_signal(restored_pid, signal.SIGKILL)
            except OSError:
                pass
        try:
            self.net.release_ip_on_host(config)
        except Exception:
            pass
        try:
            self.net.unlock_network(config.workload_ip)
        except Exception:
            pass
        self.fs.secure_wipe_directory(self.work_dir / migration_id)
        return {"rolled_back_dest": True}

    def rollback_source(
        self,
        migration_id: str,
        source_host: str,
        config_dict: Dict[str, Any],
    ) -> Dict[str, Any]:
        config = config_from_dict(config_dict)
        try:
            self.criu.run_gpu_rollback_hook(config)
        except Exception:
            pass
        try:
            self.net.claim_ip_on_host(config, target_host=source_host)
        except Exception:
            pass
        try:
            self.net.unlock_network(config.workload_ip)
        except Exception:
            pass
        if config.workload_id:
            self.envelope.unfreeze_cgroup(config.workload_id)
        try:
            self._send_signal(config.pid, signal.SIGCONT)
        except OSError:
            pass
        self.fs.secure_wipe_directory(self.work_dir / migration_id)
        return {"rolled_back_source": True, "resumed_pid": config.pid}

    def dispatch_rpc(self, method: str, params: Dict[str, Any]) -> Any:
        """Dispatch an incoming JSON-RPC call to the corresponding service method."""
        allowed_methods = {
            "get_capabilities",
            "inspect_process",
            "stat_files",
            "prepare_migration",
            "pre_sync_fs",
            "start_page_server",
            "run_pre_dump",
            "freeze_and_final_dump",
            "transfer_final_state",
            "restore_process",
            "release_ip",
            "claim_ip_and_resume",
            "verify_process",
            "commit_source",
            "cleanup_dest",
            "rollback_dest",
            "rollback_source",
        }
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
        self.tls = tls
        self._server = _ThreadedTcpServer((host, port), _RpcRequestHandler)
        self._server.agent_service = service  # type: ignore[attr-defined]
        if tls and tls.enabled and tls.cert_file and tls.key_file:
            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ctx.load_cert_chain(certfile=tls.cert_file, keyfile=tls.key_file)
            if tls.ca_cert:
                ctx.load_verify_locations(cafile=tls.ca_cert)
                ctx.verify_mode = ssl.CERT_REQUIRED
            self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)
        self._thread: Optional[threading.Thread] = None

    @property
    def bound_address(self) -> Tuple[str, int]:
        addr = self._server.server_address
        return str(addr[0]), int(addr[1])

    def start_background(self) -> None:
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    def serve_forever(self) -> None:
        self._server.serve_forever()

    def shutdown(self) -> None:
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
        self.tls = tls
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

        req_bytes = (json.dumps({"method": method, "params": params}) + "\n").encode("utf-8")
        with socket.create_connection((self.host, self.port), timeout=self.timeout_sec) as sock:
            if self.tls and self.tls.enabled and self.tls.cert_file:
                ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
                if self.tls.ca_cert:
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

        if not resp_line:
            raise RuntimeError(f"Empty RPC response from agent {self.address} for {method}")
        resp = json.loads(resp_line.decode("utf-8"))
        if not resp.get("ok"):
            raise RuntimeError(f"Agent {self.address} error in {method}: {resp.get('error')}")
        return resp.get("result")
