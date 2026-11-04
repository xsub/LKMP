"""Durable Write-Ahead Log (WAL) journal for controller crash recovery."""

from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from lkmp.models import MigrationState

DEFAULT_JOURNAL_DIR = "/var/lib/lkmp/journals"
SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def validate_safe_identifier(identifier: str, field_name: str = "migration_id") -> str:
    """Validate that an identifier cannot escape a directory via `..` or `/`."""
    if not identifier or not SAFE_ID_PATTERN.match(identifier) or ".." in identifier:
        raise ValueError(
            f"Invalid {field_name} {identifier!r}: must match ^[A-Za-z0-9][A-Za-z0-9._-]{{0,63}}$"
        )
    return identifier


@dataclass
class JournalEntry:
    """Single fsynced record in the controller's Write-Ahead Log."""

    seq: int
    timestamp_unix: float
    migration_id: str
    state: str
    commit_decision: str  # "PREPARING" | "COMMITTED" | "ABORTING" | "ROLLED_BACK"
    restored_pid: Optional[int] = None
    config_dict: Optional[Dict[str, Any]] = None
    note: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> JournalEntry:
        return cls(**data)


VOLATILE_FS_TYPES = frozenset({"tmpfs", "ramfs", "devtmpfs", "rootfs"})


def _fsync_directory(dir_path: Path) -> None:
    """Fsync a directory entry so newly created files/subdirectories survive host power loss."""
    dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    dir_fd = os.open(str(dir_path), dir_flags)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)


def _mkdir_durable(target_dir: Path, mode: int = 0o700) -> None:
    """Create missing directories along target_dir and fsync every newly populated parent directory."""
    missing: List[Path] = []
    cur = target_dir.absolute()
    while not cur.exists() and cur != cur.parent:
        missing.append(cur)
        cur = cur.parent

    target_dir.mkdir(parents=True, exist_ok=True, mode=mode)
    if missing:
        # Fsync the first pre-existing parent and each newly created directory from top to bottom
        if cur.exists():
            _fsync_directory(cur)
        for created in reversed(missing):
            _fsync_directory(created)


def _unescape_mount_path(raw_mp: str) -> str:
    """Decode Linux /proc/mounts octal escape sequences (e.g., \\040 for space)."""
    return (
        raw_mp.replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\012", "\n")
        .replace("\\134", "\\")
    )


class MigrationJournal:
    """Append-only, fsynced JSONL Write-Ahead Log for deterministic crash recovery."""

    def __init__(
        self,
        journal_dir: str | Path,
        migration_id: str,
        *,
        require_persistent: bool = True,
    ) -> None:
        validate_safe_identifier(migration_id, "migration_id")
        self.journal_dir = Path(journal_dir)
        self.migration_id = migration_id
        self.path = self.journal_dir / f"{migration_id}.wal.jsonl"
        self.require_persistent = require_persistent
        self._persistence_verified = False
        self._seq = 0
        self.entries: List[JournalEntry] = []

    def append(
        self,
        state: MigrationState,
        commit_decision: str,
        restored_pid: Optional[int] = None,
        config_dict: Optional[Dict[str, Any]] = None,
        note: Optional[str] = None,
    ) -> JournalEntry:
        """Append and fsync a state transition record to the WAL."""
        _mkdir_durable(self.journal_dir, mode=0o700)
        if self.require_persistent and not self._persistence_verified:
            _verify_persistent_filesystem(self.journal_dir)
            self._persistence_verified = True

        created_new = not self.path.exists()
        next_seq = self._seq + 1
        entry = JournalEntry(
            seq=next_seq,
            timestamp_unix=time.time(),
            migration_id=self.migration_id,
            state=state.value,
            commit_decision=commit_decision,
            restored_pid=restored_pid,
            config_dict=config_dict,
            note=note,
        )
        line = (json.dumps(entry.to_dict()) + "\n").encode("utf-8")
        fd = os.open(str(self.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
        if created_new:
            _fsync_directory(self.journal_dir)
        self._seq = next_seq
        self.entries.append(entry)
        return entry

    @classmethod
    def load(cls, journal_path: str | Path) -> MigrationJournal:
        """Load an existing WAL file from disk for crash recovery."""
        path = Path(journal_path)
        if not path.exists():
            raise FileNotFoundError(f"Journal file not found: {path}")
        entries: List[JournalEntry] = []
        for raw_line in path.read_text(encoding="utf-8").splitlines():
            if not raw_line.strip():
                continue
            entries.append(JournalEntry.from_dict(json.loads(raw_line)))
        if not entries:
            raise ValueError(f"Journal file is empty: {path}")
        mig_id = entries[0].migration_id
        journal = cls(journal_dir=path.parent, migration_id=mig_id)
        journal.entries = entries
        journal._seq = entries[-1].seq
        return journal

    @property
    def last_entry(self) -> Optional[JournalEntry]:
        return self.entries[-1] if self.entries else None

    @property
    def has_committed_decision(self) -> bool:
        """Return True if the WAL recorded an irrevocable COMMITTED decision."""
        return any(e.commit_decision == "COMMITTED" for e in self.entries)

    @property
    def initial_config_dict(self) -> Optional[Dict[str, Any]]:
        for e in self.entries:
            if e.config_dict is not None:
                return e.config_dict
        return None


def _probe_journal_writable(journal: MigrationJournal) -> None:
    """Verify that both journal_dir and journal.path are writable by the current UID."""
    _mkdir_durable(journal.journal_dir, mode=0o700)
    if journal.path.exists():
        fd = os.open(str(journal.path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.close(fd)
    else:
        uid_tag = str(os.geteuid()) if hasattr(os, "geteuid") else "default"
        probe_path = (
            journal.journal_dir
            / f".lkmp-probe-{os.getpid()}-{uid_tag}-{time.time_ns()}"
        )
        fd = os.open(str(probe_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.fsync(fd)
            os.close(fd)
        except Exception:
            try:
                os.close(fd)
            except OSError:
                pass
            raise
        finally:
            try:
                probe_path.unlink()
            except OSError:
                pass


def _verify_persistent_filesystem(
    target_dir: Path,
    mounts_file: Optional[Path] = None,
) -> None:
    """Reject volatile tmpfs/ramfs backing storage when durability across host restarts is required."""
    if mounts_file is None:
        if not sys.platform.startswith("linux"):
            return
        mounts_file = Path("/proc/mounts")

    if not mounts_file.exists():
        raise RuntimeError(
            f"Cannot verify persistent filesystem for journal directory {target_dir}: {mounts_file} does not exist"
        )

    resolved = str(target_dir.resolve())
    best_mp = ""
    best_fstype = ""
    for raw in mounts_file.read_text(encoding="utf-8", errors="ignore").splitlines():
        parts = raw.split()
        if len(parts) < 3:
            continue
        mp = _unescape_mount_path(parts[1])
        fstype = parts[2]
        if resolved == mp or resolved.startswith(mp.rstrip("/") + "/") or mp == "/":
            if len(mp) >= len(best_mp):
                best_mp = mp
                best_fstype = fstype
    if not best_mp:
        raise RuntimeError(
            f"Cannot determine backing filesystem for journal directory {target_dir} from {mounts_file}"
        )
    if best_fstype in VOLATILE_FS_TYPES:
        raise RuntimeError(
            f"Journal directory {target_dir} resides on volatile {best_fstype} mount ({best_mp}); "
            f"durable WAL recovery across host restarts requires persistent disk storage"
        )


def open_migration_journal(
    journal_dir: str | Path,
    migration_id: str,
    extra_ids: Sequence[str] = (),
    *,
    require_persistent: bool = True,
) -> MigrationJournal:
    """
    Create a MigrationJournal and verify write access and persistent storage for migration_id
    (and any coupled extra_ids). Fails closed without falling back to temporary directories
    and rejects volatile mounts (such as tmpfs/ramfs) for every journal_dir by default.
    """
    target_dir = Path(journal_dir)
    journal = MigrationJournal(target_dir, migration_id, require_persistent=require_persistent)
    _probe_journal_writable(journal)
    for extra_id in extra_ids:
        _probe_journal_writable(
            MigrationJournal(target_dir, extra_id, require_persistent=require_persistent)
        )

    if require_persistent:
        _verify_persistent_filesystem(target_dir)
        journal._persistence_verified = True

    return journal
