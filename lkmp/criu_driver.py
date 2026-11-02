"""CRIU command builder, daemon lifecycle manager, and GPU checkpoint plugin hooks."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Callable, Dict, List, Optional

from lkmp.config import GpuPlugin, MigrationConfig, MigrationStrategy, TlsConfig


CommandRunner = Callable[[List[str]], subprocess.CompletedProcess]


def _default_runner(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, text=True, capture_output=True)


class CriuDriver:
    """Wraps CRIU invocations and GPU plugin hooks on Source A and Destination B."""

    def __init__(
        self,
        criu_bin: str = "criu",
        cuda_checkpoint_bin: str = "cuda-checkpoint",
        runner: Optional[CommandRunner] = None,
    ) -> None:
        self.criu_bin = criu_bin
        self.cuda_checkpoint_bin = cuda_checkpoint_bin
        self.runner = runner or _default_runner
        self._daemons: Dict[str, subprocess.Popen] = {}

    @staticmethod
    def _tls_args(tls: TlsConfig) -> List[str]:
        if not tls.enabled:
            return []
        args = ["--tls"]
        if tls.ca_cert:
            args.extend(["--tls-cacert", tls.ca_cert])
        if tls.cert_file:
            args.extend(["--tls-cert", tls.cert_file])
        if tls.key_file:
            args.extend(["--tls-key", tls.key_file])
        if tls.no_verify:
            args.append("--tls-no-cn-verify")
        return args

    def build_check_cmd(self, all_features: bool = True) -> List[str]:
        cmd = [self.criu_bin, "check"]
        if all_features:
            cmd.append("--all")
        return cmd

    def build_check_extra_cmd(self) -> List[str]:
        return [self.criu_bin, "check", "--extra"]

    def build_check_feature_cmd(self, feature: str) -> List[str]:
        return [self.criu_bin, "check", "--feature", feature]

    def build_check_only_cmd(self, pid: int, images_dir: str) -> List[str]:
        return [self.criu_bin, "pre-dump", "-t", str(pid), "--images-dir", str(images_dir), "--check-only"]

    def build_cpuinfo_dump_cmd(self, images_dir: str) -> List[str]:
        return [self.criu_bin, "cpuinfo", "dump", "--images-dir", images_dir]

    def build_cpuinfo_check_cmd(self, images_dir: str) -> List[str]:
        return [self.criu_bin, "cpuinfo", "check", "--images-dir", images_dir]

    def build_page_server_cmd(
        self,
        images_dir: str,
        port: int,
        tls: TlsConfig,
        prev_images_dir: Optional[str] = None,
        pidfile: Optional[str] = None,
    ) -> List[str]:
        """
        Build `criu page-server --daemon` command so the RPC call returns immediately
        while the page-server listens in the background for incoming pages from Source A.
        """
        resolved_pidfile = pidfile or str(Path(images_dir) / "page-server.pid")
        cmd = [
            self.criu_bin,
            "page-server",
            "--daemon",
            "--pidfile",
            resolved_pidfile,
            "--images-dir",
            images_dir,
            "--port",
            str(port),
        ]
        if prev_images_dir:
            cmd.extend(["--prev-images-dir", prev_images_dir])
        cmd.extend(self._tls_args(tls))
        return cmd

    def build_pre_dump_cmd(
        self,
        config: MigrationConfig,
        images_dir: str,
        prev_images_dir: Optional[str] = None,
        dest_host: Optional[str] = None,
    ) -> List[str]:
        cmd = [
            self.criu_bin,
            "pre-dump",
            "-t",
            str(config.pid),
            "--images-dir",
            images_dir,
            "--track-mem",
        ]
        if prev_images_dir:
            cmd.extend(["--prev-images-dir", prev_images_dir])
        if dest_host:
            cmd.extend(
                [
                    "--page-server",
                    "--address",
                    dest_host,
                    "--port",
                    str(config.page_server_port),
                ]
            )
            cmd.extend(self._tls_args(config.tls))
        return cmd

    def build_dump_cmd(
        self,
        config: MigrationConfig,
        images_dir: str,
        prev_images_dir: Optional[str] = None,
        dest_host: Optional[str] = None,
    ) -> List[str]:
        cmd = [
            self.criu_bin,
            "dump",
            "-t",
            str(config.pid),
            "--images-dir",
            images_dir,
            "--leave-stopped",
            "--ghost-limit",
            str(config.ghost_limit_bytes),
        ]
        if prev_images_dir:
            cmd.extend(["--prev-images-dir", prev_images_dir, "--track-mem"])
        elif config.strategy in (MigrationStrategy.PRE_COPY, MigrationStrategy.HYBRID):
            cmd.append("--track-mem")

        if config.strategy in (MigrationStrategy.LAZY, MigrationStrategy.HYBRID):
            cmd.extend(
                [
                    "--lazy-pages",
                    "--address",
                    "0.0.0.0",
                    "--port",
                    str(config.lazy_pages_port),
                ]
            )
            cmd.extend(self._tls_args(config.tls))
        elif dest_host and config.strategy == MigrationStrategy.PRE_COPY:
            cmd.extend(
                [
                    "--page-server",
                    "--address",
                    dest_host,
                    "--port",
                    str(config.page_server_port),
                ]
            )
            cmd.extend(self._tls_args(config.tls))

        if config.tcp_established:
            cmd.extend(["--tcp-established", "--network-lock", "nftables"])
        if config.ext_unix_sk:
            cmd.append("--ext-unix-sk")
        for ext_mnt in config.external_mounts:
            cmd.extend(["--external", f"mnt[{ext_mnt}]"])
        if config.unsafe_bare:
            cmd.append("--shell-job")

        return cmd

    def build_lazy_pages_daemon_cmd(
        self,
        config: MigrationConfig,
        images_dir: str,
        source_host: str,
    ) -> List[str]:
        """
        Build `criu lazy-pages` command for background userfaultfd service.
        Note: --daemon and --pidfile are omitted as CRIU only supports --daemon on page-server and service;
        the orchestrator/agent supervises lazy-pages via run_background_daemon.
        """
        cmd = [
            self.criu_bin,
            "lazy-pages",
            "--images-dir",
            images_dir,
            "--page-server",
            "--address",
            source_host,
            "--port",
            str(config.lazy_pages_port),
        ]
        cmd.extend(self._tls_args(config.tls))
        return cmd

    def run_background_daemon(
        self,
        cmd: List[str],
        pidfile: str | Path,
        log_file: Optional[str | Path] = None,
    ) -> int:
        """
        Supervise and launch a background daemon (such as CRIU dump with --lazy-pages or lazy-pages daemon).
        If runner is not _default_runner, calls runner(cmd) and writes synthetic PID.
        Otherwise spawns via subprocess.Popen, verifies it did not exit immediately with error, writes pidfile,
        and tracks proc in self._daemons.
        """
        pidfile_path = Path(pidfile)
        pidfile_path.parent.mkdir(parents=True, exist_ok=True)

        if self.runner is not _default_runner:
            self.runner(cmd)
            if not pidfile_path.exists():
                pidfile_path.write_text("9001\n", encoding="utf-8")
            try:
                return int(pidfile_path.read_text(encoding="utf-8").strip())
            except ValueError:
                return 9001

        stdout_dest = subprocess.DEVNULL
        stderr_dest = subprocess.DEVNULL
        if log_file:
            log_p = Path(log_file)
            log_p.parent.mkdir(parents=True, exist_ok=True)
            log_handle = open(log_p, "a", encoding="utf-8")
            stdout_dest = log_handle
            stderr_dest = log_handle

        proc = subprocess.Popen(
            cmd,
            stdout=stdout_dest,
            stderr=stderr_dest,
            start_new_session=True,
        )
        time.sleep(0.05)
        rc = proc.poll()
        if rc is not None and rc != 0:
            raise RuntimeError(
                f"Background daemon {' '.join(cmd)} failed immediately with returncode {rc}"
            )

        pidfile_path.write_text(f"{proc.pid}\n", encoding="utf-8")
        self._daemons[str(pidfile_path)] = proc
        return proc.pid

    def stop_daemon(self, pidfile: str | Path) -> None:
        """Terminate and clean up a supervised background daemon."""
        p_str = str(pidfile)
        proc = self._daemons.pop(p_str, None)
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=1.0)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        p_path = Path(pidfile)
        if p_path.exists():
            try:
                p_path.unlink()
            except OSError:
                pass

    def build_restore_cmd(
        self,
        config: MigrationConfig,
        images_dir: str,
        pidfile: Optional[str] = None,
    ) -> List[str]:
        cmd = [
            self.criu_bin,
            "restore",
            "--images-dir",
            images_dir,
            "--restore-detached",
            "--leave-stopped",
        ]
        if pidfile:
            cmd.extend(["--pidfile", pidfile])
        if config.strategy in (MigrationStrategy.LAZY, MigrationStrategy.HYBRID):
            cmd.append("--lazy-pages")
        if config.tcp_established:
            cmd.append("--tcp-established")
        if config.ext_unix_sk:
            cmd.append("--ext-unix-sk")
        for ext_mnt in config.external_mounts:
            cmd.extend(["--external", f"mnt[{ext_mnt}]"])
        if config.unsafe_bare:
            cmd.append("--shell-job")
        return cmd

    def build_cuda_checkpoint_cmd(self, pid: int, action: str) -> List[str]:
        """
        Build NVIDIA `cuda-checkpoint` command for GPU state serialization.
        Valid actions: 'lock', 'checkpoint', 'restore', 'unlock'.
        """
        if action not in ("lock", "checkpoint", "restore", "unlock"):
            raise ValueError(f"Unsupported cuda-checkpoint action: {action}")
        return [self.cuda_checkpoint_bin, "--action", action, "--pid", str(pid)]

    def run_gpu_pre_dump_hook(self, config: MigrationConfig) -> None:
        """Lock and checkpoint CUDA context on Source A immediately prior to final CRIU dump."""
        if config.gpu_plugin == GpuPlugin.CUDA:
            self.runner(self.build_cuda_checkpoint_cmd(config.pid, "lock"))
            self.runner(self.build_cuda_checkpoint_cmd(config.pid, "checkpoint"))

    def run_gpu_post_restore_hook(self, config: MigrationConfig, restored_pid: int) -> None:
        """Restore and unlock CUDA context on Destination B after CRIU restore."""
        if config.gpu_plugin == GpuPlugin.CUDA:
            self.runner(self.build_cuda_checkpoint_cmd(restored_pid, "restore"))
            self.runner(self.build_cuda_checkpoint_cmd(restored_pid, "unlock"))

    def run_gpu_rollback_hook(self, config: MigrationConfig) -> None:
        """Restore and unlock CUDA context on Source A if migration rolls back."""
        if config.gpu_plugin == GpuPlugin.CUDA:
            self.runner(self.build_cuda_checkpoint_cmd(config.pid, "restore"))
            self.runner(self.build_cuda_checkpoint_cmd(config.pid, "unlock"))
