"""Filesystem synchronization and checkpoint image transfer."""

from __future__ import annotations

import hmac
import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, List, Optional

from lkmp.config import FilesystemMode, MigrationConfig, MigrationStrategy

STORAGE_PROBE_FILENAME = ".lkmp_storage_probe.json"


def _strip_endpoint(endpoint: str) -> str:
    h = endpoint.strip()
    if ":" in h:
        if h.startswith("[") and "]" in h:
            return h[1 : h.index("]")]
        parts = h.split(":")
        if len(parts) == 2 and parts[1].isdigit():
            return parts[0]
    return h


def _locate_storage_probe_file(dir_path: Path) -> Optional[Path]:
    """Locate `.lkmp_storage_probe.json` inside `dir_path` or its migration parent when `dir_path.name == 'final'`."""
    direct = dir_path / STORAGE_PROBE_FILENAME
    if direct.is_file():
        return direct
    if dir_path.name == "final":
        parent_probe = dir_path.parent / STORAGE_PROBE_FILENAME
        if parent_probe.is_file():
            return parent_probe
    return None


def is_same_host_or_shared_storage(
    source_host: str = "",
    dest_host: str = "",
    source_dir: Optional[str | Path] = None,
    dest_dir: Optional[str | Path] = None,
    *,
    expected_probe_token: Optional[str] = None,
    source_agent_id: Optional[str] = None,
    expected_migration_id: Optional[str] = None,
) -> bool:
    """
    Verify whether Source A and Destination B genuinely share local/networked storage for
    `source_dir` and `dest_dir`.

    Never relies on IP addresses or loopback hostnames (`127.0.0.1`, `localhost`, `::1`),
    because two distinct VMs or unshared containers may share a forwarded/NAT endpoint.
    Requires both directories to exist on Source A's local VFS AND `dest_dir` (or its
    migration root when `dest_dir.name == 'final'`) to contain a valid `.lkmp_storage_probe.json`
    written by a distinct Destination B agent instance.
    """
    _ = (source_host, dest_host)
    if source_dir is None or dest_dir is None:
        return False

    try:
        s_path = Path(source_dir)
        d_path = Path(dest_dir)
        if not s_path.is_dir() or not d_path.is_dir():
            return False

        probe_file = _locate_storage_probe_file(d_path)
        if probe_file is None:
            return False

        probe_data = json.loads(probe_file.read_text(encoding="utf-8"))
        if not isinstance(probe_data, dict):
            return False

        dest_agent_id = probe_data.get("agent_id")
        probe_token = probe_data.get("token")
        probe_mig_id = probe_data.get("migration_id")
        if (
            not isinstance(dest_agent_id, str)
            or not dest_agent_id
            or not isinstance(probe_token, str)
            or not probe_token
        ):
            return False

        if expected_migration_id is not None and probe_mig_id != expected_migration_id:
            return False
        if probe_file.parent == d_path.parent and d_path.name == "final":
            if probe_mig_id and probe_mig_id != d_path.parent.name:
                return False

        if source_agent_id is not None and dest_agent_id == source_agent_id:
            return False

        if expected_probe_token is not None:
            if not hmac.compare_digest(probe_token, str(expected_probe_token)):
                return False
        else:
            src_probe_file = _locate_storage_probe_file(s_path)
            if src_probe_file is not None:
                try:
                    src_probe = json.loads(src_probe_file.read_text(encoding="utf-8"))
                    if isinstance(src_probe, dict) and src_probe.get("agent_id") == dest_agent_id:
                        return False
                except Exception:
                    return False

        return True
    except Exception:
        return False


CommandRunner = Callable[[List[str]], subprocess.CompletedProcess]


def _default_runner(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, text=True, capture_output=True)


class _CowCloneDescriptor:
    def __init__(self, fn: Callable) -> None:
        self.fn = fn

    def __get__(self, obj: Any, objtype: Any = None) -> Callable:
        if obj is None:
            return lambda *args, **kwargs: self.fn(FilesystemSyncManager(), *args, **kwargs)
        return lambda *args, **kwargs: self.fn(obj, *args, **kwargs)


class FilesystemSyncManager:
    """Handles shared storage verification, rsync pre-sync, final delta sync, and secure wipe."""

    def __init__(self, runner: Optional[CommandRunner] = None) -> None:
        self.runner = runner or _default_runner

    is_same_host_or_shared_storage = staticmethod(is_same_host_or_shared_storage)

    def _cow_clone_impl(
        self,
        src_dir: str | Path,
        dst_dir: str | Path,
        include_pages: bool = True,
    ) -> List[str]:
        """
        Fast local copy for the "Two VMs / Containers on One Host" mode (P2).
        Creates dst_dir. For each file in src_dir (skipping pages-*.img if not include_pages):
        attempts CoW clone (cp --reflink=auto on Linux or cp -c on macOS via self.runner,
        falling back to shutil.copy2 if runner/clonefile is mocked or unsupported).
        Returns list of cloned file paths.
        """
        src = Path(src_dir)
        dst = Path(dst_dir)
        dst.mkdir(parents=True, exist_ok=True)
        cloned: List[str] = []
        if not src.exists():
            return cloned

        for item in sorted(src.iterdir()):
            if item.name.startswith(".lkmp_"):
                continue
            if item.is_symlink():
                dst_link = dst / item.name
                if dst_link.exists() or dst_link.is_symlink():
                    dst_link.unlink()
                os.symlink(os.readlink(item), dst_link)
                cloned.append(str(dst_link))
                continue
            if not item.is_file():
                continue
            if not include_pages and item.name.startswith("pages-") and item.name.endswith(".img"):
                continue
            dst_file = dst / item.name
            if sys.platform == "darwin":
                cmd = ["cp", "-c", str(item), str(dst_file)]
            else:
                cmd = ["cp", "--reflink=auto", str(item), str(dst_file)]
            try:
                self.runner(cmd)
                if not dst_file.exists():
                    shutil.copy2(item, dst_file)
            except Exception:
                shutil.copy2(item, dst_file)
            cloned.append(str(dst_file))
        return cloned

    cow_clone_directory = _CowCloneDescriptor(_cow_clone_impl)

    @staticmethod
    def resolve_snapshot_path(snapshot_dir: str | Path, writable_path: str) -> Path:
        """Resolve the point-in-time frozen snapshot path inside `snapshot_dir` for `writable_path`."""
        snap_p = Path(snapshot_dir)
        wp_path = Path(writable_path)
        rel_candidate = snap_p / writable_path.lstrip("/")
        if rel_candidate.exists():
            return rel_candidate
        return snap_p / wp_path.name

    def snapshot_writable_paths_while_frozen(
        self,
        config: MigrationConfig,
        snapshot_dir: str | Path,
    ) -> List[List[str]]:
        """
        Point-in-time snapshot of writable filesystem state while the process tree is frozen.
        - If config.volume_snapshot_cmd is set, runs it via self.runner.
        - If config.writable_paths are set, copies/snapshots them into snapshot_dir so disk
          state matches the frozen memory checkpoint.
        """
        cmds: List[List[str]] = []
        snap_p = Path(snapshot_dir)
        snap_p.mkdir(parents=True, exist_ok=True)

        if config.volume_snapshot_cmd:
            cmd = shlex.split(config.volume_snapshot_cmd)
            self.runner(cmd)
            cmds.append(cmd)

        if config.writable_paths:
            for wp in config.writable_paths:
                wp_path = Path(wp)
                if not wp_path.exists():
                    raise FileNotFoundError(
                        f"Cannot create frozen snapshot: writable path {wp!r} does not exist"
                    )
                target = snap_p / wp.lstrip("/") if wp.startswith("/") else snap_p / wp_path.name
                target.parent.mkdir(parents=True, exist_ok=True)
                if wp_path.is_dir():
                    if sys.platform == "darwin":
                        cmd = ["cp", "-cR", str(wp_path), str(target)]
                    else:
                        cmd = ["cp", "-a", "--reflink=auto", str(wp_path), str(target)]
                    try:
                        self.runner(cmd)
                        if not target.exists():
                            shutil.copytree(wp_path, target, symlinks=True, dirs_exist_ok=True)
                    except Exception:
                        shutil.copytree(wp_path, target, symlinks=True, dirs_exist_ok=True)
                    cmds.append(cmd)
                else:
                    if sys.platform == "darwin":
                        cmd = ["cp", "-c", str(wp_path), str(target)]
                    else:
                        cmd = ["cp", "--reflink=auto", str(wp_path), str(target)]
                    try:
                        self.runner(cmd)
                        if not target.exists():
                            shutil.copy2(wp_path, target)
                    except Exception:
                        shutil.copy2(wp_path, target)
                    cmds.append(cmd)

        return cmds

    def build_rsync_cmd(self, local_path: str, dest_host: str, dest_path: str) -> List[str]:
        """Build an archive-mode rsync command preserving permissions, xattrs, and hardlinks."""
        local_p = Path(local_path)
        if local_p.exists() and local_p.is_file():
            src = local_path
            dst = f"{dest_host}:{dest_path}"
        else:
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

    def final_delta_sync(
        self,
        config: MigrationConfig,
        dest_host: str,
        snapshot_dir: Optional[str | Path] = None,
    ) -> List[List[str]]:
        """
        Run final rsync delta pass while the source process tree is frozen.
        Requires a frozen point-in-time `snapshot_dir` containing a snapshot of every
        configured `writable_path` so destination disk state matches the memory checkpoint.
        Never falls back to reading live mutable paths.
        """
        if config.fs_mode != FilesystemMode.RSYNC or not config.writable_paths:
            return []
        if snapshot_dir is None:
            raise FileNotFoundError(
                "final_delta_sync requires a frozen snapshot_dir; refusing to fall back to live writable_paths"
            )
        snap_root = Path(snapshot_dir)
        cmds: List[List[str]] = []
        for path in config.writable_paths:
            snap_candidate = self.resolve_snapshot_path(snap_root, path)
            if not snap_candidate.exists():
                raise FileNotFoundError(
                    f"Frozen snapshot missing for writable_path {path!r} at {snap_candidate}; "
                    "refusing to fall back to live filesystem read"
                )
            cmd = self.build_rsync_cmd(str(snap_candidate), dest_host, path)
            self.runner(cmd)
            cmds.append(cmd)
        return cmds

    def sync_checkpoint_images(
        self,
        images_dir: str,
        dest_host: str,
        include_pages: bool = False,
        source_host: Optional[str] = None,
        dest_images_dir: Optional[str] = None,
        dest_probe_token: Optional[str] = None,
        source_agent_id: Optional[str] = None,
        migration_id: Optional[str] = None,
    ) -> List[str]:
        """
        Sync checkpoint `.img` and `manifest.sig.json` files from Source A to Destination B.
        - When `dest_images_dir` is proven via `.lkmp_storage_probe.json` to reside on shared/local
          storage visible to Source A, uses the CoW reflink fast path (`cow_clone_directory`)
          instead of `rsync`. Never relies on IP/loopback equality alone.
        - For COLD migration (`include_pages=True`), transfers all files including `pages-*.img`.
        - For PRE_COPY / LAZY / HYBRID (`include_pages=False`), `pages-*.img` are streamed via
          CRIU page-server / lazy-pages, so only metadata `.img` and `manifest.sig.json` are synced.
        """
        use_cow = bool(
            dest_images_dir is not None
            and self.is_same_host_or_shared_storage(
                source_host or "",
                dest_host,
                source_dir=images_dir,
                dest_dir=dest_images_dir,
                expected_probe_token=dest_probe_token,
                source_agent_id=source_agent_id,
                expected_migration_id=migration_id,
            )
        )
        if use_cow and dest_images_dir is not None:
            if Path(dest_images_dir).resolve() != Path(images_dir).resolve():
                return self.cow_clone_directory(
                    images_dir,
                    dest_images_dir,
                    include_pages=include_pages,
                )
            return [
                str(p)
                for p in sorted(Path(images_dir).iterdir())
                if p.is_file()
                and not p.name.startswith(".lkmp_")
                and (include_pages or not (p.name.startswith("pages-") and p.name.endswith(".img")))
            ]

        src = images_dir.rstrip("/") + "/"
        dst = f"{dest_host}:{images_dir.rstrip('/')}/"
        cmd = [
            "rsync",
            "-a",
            "--numeric-ids",
            "--compress",
        ]
        if not include_pages:
            cmd.append("--exclude=pages-*.img")
        cmd.extend([src, dst])
        self.runner(cmd)
        return cmd

    def sync_metadata_images(self, images_dir: str, dest_host: str) -> List[str]:
        """Backward-compatible alias for `sync_checkpoint_images(..., include_pages=False)`."""
        return self.sync_checkpoint_images(images_dir, dest_host, include_pages=False)

    @staticmethod
    def secure_wipe_directory(
        dir_path: str | Path,
        allowed_parent: Optional[str | Path] = None,
    ) -> None:
        """
        Overwrite sensitive checkpoint image files (`pages-*.img`, `core-*.img`) with zeros
        before unlinking so memory secrets (keys, tokens) do not linger on storage.
        If `allowed_parent` is provided, enforces that `dir_path` resolves strictly inside it.
        """
        root = Path(dir_path).resolve()
        if allowed_parent is not None:
            parent_resolved = Path(allowed_parent).resolve()
            if root == parent_resolved:
                raise ValueError(
                    f"Refusing to wipe directory {root}: cannot be identical to allowed parent {parent_resolved}"
                )
            if not root.is_relative_to(parent_resolved):
                raise ValueError(
                    f"Refusing to wipe directory {root} outside allowed parent {parent_resolved}"
                )
        if not root.exists():
            return
        for item in root.rglob("*"):
            if item.is_file() and not item.is_symlink():
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


def cow_clone_directory(
    src_dir: str | Path,
    dst_dir: str | Path,
    include_pages: bool = True,
    runner: Optional[CommandRunner] = None,
) -> List[str]:
    """Module-level fast CoW clone directory copy."""
    return FilesystemSyncManager(runner=runner).cow_clone_directory(
        src_dir, dst_dir, include_pages=include_pages
    )
