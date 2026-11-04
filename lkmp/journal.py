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


class MigrationJournal:
    """Append-only, fsynced JSONL Write-Ahead Log for deterministic crash recovery."""

    def __init__(self, journal_dir: str | Path, migration_id: str) -> None:
        validate_safe_identifier(migration_id, "migration_id")
        self.journal_dir = Path(journal_dir)
        self.migration_id = migration_id
        self.path = self.journal_dir / f"{migration_id}.wal.jsonl"
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
        self.journal_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        created_new = not self.path.exists()
        self._seq += 1
        entry = JournalEntry(
            seq=self._seq,
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
            dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            try:
                dir_fd = os.open(str(self.journal_dir), dir_flags)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except OSError:
                pass
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
    journal.journal_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
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
            os.close(fd)
        finally:
            try:
                probe_path.unlink()
            except OSError:
                pass


def _verify_persistent_filesystem(target_dir: Path, mounts_file: Path = Path("/proc/mounts")) -> None:
    """Reject volatile tmpfs/ramfs backing storage when durability across host restarts is required."""
    if not sys.platform.startswith("linux") or not mounts_file.exists():
        return
    try:
        resolved = str(target_dir.resolve())
        best_mp = ""
        best_fstype = ""
        for raw in mounts_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            parts = raw.split()
            if len(parts) < 3:
                continue
            mp, fstype = parts[1], parts[2]
            if resolved == mp or resolved.startswith(mp.rstrip("/") + "/") or mp == "/":
                if len(mp) >= len(best_mp):
                    best_mp = mp
                    best_fstype = fstype
        if best_fstype in ("tmpfs", "ramfs"):
            raise RuntimeError(
                f"Journal directory {target_dir} resides on volatile {best_fstype} mount ({best_mp}); "
                f"durable WAL recovery across host restarts requires persistent disk storage"
            )
    except RuntimeError:
        raise
    except OSError:
        pass


def open_migration_journal(
    journal_dir: str | Path,
    migration_id: str,
    extra_ids: Sequence[str] = (),
    *,
    require_persistent: Optional[bool] = None,
) -> MigrationJournal:
    """
    Create a MigrationJournal and verify write access for migration_id (and any coupled extra_ids).
    Fails closed without falling back to temporary directories so WAL durability across host
    restarts is never silently degraded.
    """
    target_dir = Path(journal_dir)
    journal = MigrationJournal(target_dir, migration_id)
    _probe_journal_writable(journal)
    for extra_id in extra_ids:
        _probe_journal_writable(MigrationJournal(target_dir, extra_id))

    enforce_persistent = (
        require_persistent
        if require_persistent is not None
        else (target_dir == Path(DEFAULT_JOURNAL_DIR))
    )
    if enforce_persistent:
        _verify_persistent_filesystem(target_dir)

    return journal
