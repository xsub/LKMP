"""Durable Write-Ahead Log (WAL) journal for controller crash recovery."""

from __future__ import annotations

import json
import os
import re
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from lkmp.models import MigrationState

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
        self.journal_dir.mkdir(parents=True, exist_ok=True)
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
