"""Durable Write-Ahead Log (WAL) journal for controller crash recovery."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, fields
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
    commit_decision: str  # "PREPARING" | "PREPARED_STOPPED" | "COMMITTED" | "ABORTING" | "ROLLED_BACK"
    restored_pid: Optional[int] = None
    config_dict: Optional[Dict[str, Any]] = None
    note: Optional[str] = None
    gang_id: Optional[str] = None
    checksum: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> JournalEntry:
        allowed = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in allowed}
        return cls(**filtered)


def _compute_entry_checksum(data: Dict[str, Any]) -> str:
    """Compute canonical SHA-256 digest over a JournalEntry dictionary excluding `checksum`."""
    payload = {k: v for k, v in data.items() if k != "checksum"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


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
        gang_id: Optional[str] = None,
    ) -> None:
        validate_safe_identifier(migration_id, "migration_id")
        if gang_id is not None:
            validate_safe_identifier(gang_id, "gang_id")
        self.journal_dir = Path(journal_dir)
        self.migration_id = migration_id
        self.path = self.journal_dir / f"{migration_id}.wal.jsonl"
        self.require_persistent = require_persistent
        self.gang_id = gang_id
        self._persistence_verified = False
        self._seq = 0
        self.entries: List[JournalEntry] = []
        self.discarded_torn_tail = False

    def append(
        self,
        state: MigrationState,
        commit_decision: str,
        restored_pid: Optional[int] = None,
        config_dict: Optional[Dict[str, Any]] = None,
        note: Optional[str] = None,
        gang_id: Optional[str] = None,
    ) -> JournalEntry:
        """Append and fsync a state transition record to the WAL."""
        _mkdir_durable(self.journal_dir, mode=0o700)
        if self.require_persistent and not self._persistence_verified:
            _verify_persistent_filesystem(self.journal_dir)
            self._persistence_verified = True

        resolved_gang_id = gang_id if gang_id is not None else self.gang_id
        if resolved_gang_id is not None:
            validate_safe_identifier(resolved_gang_id, "gang_id")

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
            gang_id=resolved_gang_id,
        )
        raw_dict = entry.to_dict()
        entry.checksum = _compute_entry_checksum(raw_dict)
        raw_dict["checksum"] = entry.checksum
        line = (json.dumps(raw_dict) + "\n").encode("utf-8")
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
        """
        Load an existing WAL file from disk for crash recovery.
        - Validates JSON syntax, monotonic sequence numbers, migration_id consistency, and
          per-entry SHA-256 checksums across the log.
        - Any corruption in the middle of the file raises `ValueError` (fail-closed).
        - If the final record at EOF was partially written/torn before `os.fsync` completed
          (missing newline on checksummed record, NUL bytes, truncated JSON, or bad checksum)
          and at least one valid prior committed entry exists, discards the uncommitted torn tail
          and sets `journal.discarded_torn_tail = True`.
        """
        path = Path(journal_path)
        if not path.exists():
            raise FileNotFoundError(f"Journal file not found: {path}")

        raw_bytes = path.read_bytes()
        if not raw_bytes.strip(b" \t\r\n\x00"):
            raise ValueError(f"Journal file is empty: {path}")

        raw_lines = [
            ln for ln in raw_bytes.splitlines(keepends=True) if ln.strip(b" \t\r\n")
        ]
        if not raw_lines:
            raise ValueError(f"Journal file is empty: {path}")

        entries: List[JournalEntry] = []
        discarded_torn_tail = False
        expected_mig_id: Optional[str] = None

        for idx, raw_line_bytes in enumerate(raw_lines):
            is_last = idx == len(raw_lines) - 1
            has_newline = raw_line_bytes.endswith(b"\n")
            has_nul = b"\x00" in raw_line_bytes

            try:
                if has_nul:
                    raise ValueError("NUL bytes detected in WAL record")
                decoded = raw_line_bytes.decode("utf-8").strip()
                parsed = json.loads(decoded)
                if not isinstance(parsed, dict):
                    raise ValueError("WAL record is not a JSON object")
                entry = JournalEntry.from_dict(parsed)

                if entry.checksum is not None:
                    if not has_newline:
                        raise ValueError("Unterminated checksummed WAL record (missing newline)")
                    expected_csum = _compute_entry_checksum(entry.to_dict())
                    if entry.checksum != expected_csum:
                        raise ValueError(
                            f"WAL checksum mismatch at seq={entry.seq}: "
                            f"expected {expected_csum}, got {entry.checksum}"
                        )

                if expected_mig_id is None:
                    validate_safe_identifier(entry.migration_id, "migration_id")
                    expected_mig_id = entry.migration_id
                elif entry.migration_id != expected_mig_id:
                    raise ValueError(
                        f"Mismatched migration_id in WAL at line {idx + 1}: "
                        f"expected {expected_mig_id!r}, got {entry.migration_id!r}"
                    )

                if entries and entry.seq <= entries[-1].seq:
                    raise ValueError(
                        f"Non-monotonic WAL seq at line {idx + 1}: {entry.seq} <= {entries[-1].seq}"
                    )

                entries.append(entry)
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
                if is_last and len(entries) >= 1:
                    # Un-fsynced torn trailing record at EOF; safe to discard
                    discarded_torn_tail = True
                    break
                raise ValueError(
                    f"Corrupted WAL record at line {idx + 1} of {path}: {exc}"
                ) from exc

        if not entries or expected_mig_id is None:
            raise ValueError(f"Journal file contains no valid committed entries: {path}")

        coupled_gang = next((e.gang_id for e in entries if e.gang_id), None)
        journal = cls(
            journal_dir=path.parent,
            migration_id=expected_mig_id,
            gang_id=coupled_gang,
        )
        journal.entries = entries
        journal._seq = entries[-1].seq
        journal.discarded_torn_tail = discarded_torn_tail
        return journal

    @property
    def coupled_gang_id(self) -> Optional[str]:
        if self.gang_id:
            return self.gang_id
        for e in self.entries:
            if e.gang_id:
                return e.gang_id
        return None

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
    gang_id: Optional[str] = None,
) -> MigrationJournal:
    """
    Create a MigrationJournal and verify write access and persistent storage for migration_id
    (and any coupled extra_ids). Fails closed without falling back to temporary directories
    and rejects volatile mounts (such as tmpfs/ramfs) for every journal_dir by default.
    """
    target_dir = Path(journal_dir)
    journal = MigrationJournal(
        target_dir,
        migration_id,
        require_persistent=require_persistent,
        gang_id=gang_id,
    )
    _probe_journal_writable(journal)
    for extra_id in extra_ids:
        _probe_journal_writable(
            MigrationJournal(target_dir, extra_id, require_persistent=require_persistent)
        )

    if require_persistent:
        _verify_persistent_filesystem(target_dir)
        journal._persistence_verified = True

    return journal
