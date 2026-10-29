"""Filesystem synchronization and checkpoint metadata transfer."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Callable, List, Optional

from lkmp.config import FilesystemMode, MigrationConfig


CommandRunner = Callable[[List[str]], subprocess.CompletedProcess]


def _default_runner(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, text=True, capture_output=True)


class FilesystemSyncManager:
    """Handles shared storage verification, rsync pre-sync, final delta sync, and secure wipe."""

    def __init__(self, runner: Optional[CommandRunner] = None) -> None:
        self.runner = runner or _default_runner

    def build_rsync_cmd(self, local_path: str, dest_host: str, dest_path: str) -> List[str]:
        """Build an archive-mode rsync command preserving permissions, xattrs, and hardlinks."""
        src = local_path.rstrip("/") + "/"
        dst = f"{dest_host}:{dest_path.rstrip('/')}/"
        return [
            "rsync",
            "-aHAX",
            "--numeric-ids",
            "--delete",
            "--compress",
            src,
            dst,
        ]

    def pre_sync_writable_paths(self, config: MigrationConfig, dest_host: str) -> List[List[str]]:
        """Run initial rsync pass over writable directories before iterative pre-copy."""
        if config.fs_mode != FilesystemMode.RSYNC:
            return []
        cmds: List[List[str]] = []
        for path in config.writable_paths:
            cmd = self.build_rsync_cmd(path, dest_host, path)
            self.runner(cmd)
            cmds.append(cmd)
        return cmds

    def final_delta_sync(self, config: MigrationConfig, dest_host: str) -> List[List[str]]:
        """Run final rsync delta pass while the source process tree is frozen."""
        if config.fs_mode != FilesystemMode.RSYNC:
            return []
        cmds: List[List[str]] = []
        for path in config.writable_paths:
            cmd = self.build_rsync_cmd(path, dest_host, path)
            self.runner(cmd)
            cmds.append(cmd)
        return cmds

    def sync_metadata_images(self, images_dir: str, dest_host: str) -> List[str]:
        """Sync non-memory metadata `.img` files from Source A to Destination B."""
        src = images_dir.rstrip("/") + "/"
        dst = f"{dest_host}:{images_dir.rstrip('/')}/"
        cmd = [
            "rsync",
            "-a",
            "--numeric-ids",
            "--compress",
            "--exclude=pages-*.img",
            src,
            dst,
        ]
        self.runner(cmd)
        return cmd

    @staticmethod
    def secure_wipe_directory(dir_path: str | Path) -> None:
        """
        Overwrite sensitive checkpoint image files (`pages-*.img`, `core-*.img`) with zeros
        before unlinking so memory secrets (keys, tokens) do not linger on storage.
        """
        root = Path(dir_path)
        if not root.exists():
            return
        for item in root.rglob("*"):
            if item.is_file():
                try:
                    size = item.stat().st_size
                    if size > 0:
                        with item.open("r+b") as f:
                            chunk = b"\x00" * min(size, 65536)
                            remaining = size
                            while remaining > 0:
                                to_write = min(len(chunk), remaining)
                                f.write(chunk[:to_write])
                                remaining -= to_write
                            f.flush()
                except OSError:
                    pass
        shutil.rmtree(root, ignore_errors=True)
