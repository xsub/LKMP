"""CRIU command builder, daemon lifecycle manager, and GPU checkpoint plugin hooks."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Callable, List, Optional

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
    ) -> List[str]:
        cmd = [
            self.criu_bin,
            "page-server",
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
