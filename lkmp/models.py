"""Domain models for process state, preflight analysis, and migration telemetry."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class MigrationState(str, Enum):
    """States of the LKMP migration state machine."""

    INIT = "INIT"
    PREFLIGHT = "PREFLIGHT"
    ABORTED = "ABORTED"
    PREPARE = "PREPARE"
    PRE_COPY = "PRE_COPY"
    FREEZE = "FREEZE"
    FINAL_DUMP = "FINAL_DUMP"
    TRANSFER = "TRANSFER"
    RESTORE = "RESTORE"
    SWITCHOVER = "SWITCHOVER"
    VERIFY = "VERIFY"
    COMMIT = "COMMIT"
    ROLLBACK = "ROLLBACK"


class ResourceClassification(str, Enum):
    """Classification of a process resource discovered during preflight."""

    OK = "ok"
    NEEDS_FLAG = "needs_flag"
    BLOCKER = "blocker"


@dataclass
class FileArtifact:
    """Metadata for a mapped binary, library, or open regular file."""

    path: str
    size: int
    sha256: Optional[str] = None
    build_id: Optional[str] = None
    is_deleted: bool = False
    is_mapped_executable: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FileArtifact:
        return cls(**data)


@dataclass
class ResourceFinding:
    """A single resource finding during preflight inspection."""

    resource_type: str  # e.g., "fd", "mmap", "cpu", "kernel", "ghost_file"
    identifier: str
    classification: ResourceClassification
    reason: str
    suggested_flag: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["classification"] = self.classification.value
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ResourceFinding:
        d = dict(data)
        d["classification"] = ResourceClassification(d["classification"])
        return cls(**d)


@dataclass
class HostCapabilities:
    """Capabilities and CPU/kernel characteristics of a host node."""

    arch: str
    kernel_release: str
    cpu_vendor: str
    cpu_flags: Set[str] = field(default_factory=set)
    criu_available: bool = False
    criu_version: Optional[str] = None
    has_userfaultfd: bool = False
    has_soft_dirty: bool = False
    has_time_ns: bool = False
    has_cgroup_v2: bool = False

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["cpu_flags"] = sorted(self.cpu_flags)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> HostCapabilities:
        d = dict(data)
        d["cpu_flags"] = set(d.get("cpu_flags", []))
        return cls(**d)


@dataclass
class ProcessSnapshotInfo:
    """Summary of the running process tree collected on Source A during preflight."""

    root_pid: int
    child_pids: List[int] = field(default_factory=list)
    rss_bytes: int = 0
    dirty_rate_bytes_per_sec: int = 0
    files: List[FileArtifact] = field(default_factory=list)
    findings: List[ResourceFinding] = field(default_factory=list)
    in_envelope: bool = False
    cgroup_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_pid": self.root_pid,
            "child_pids": self.child_pids,
            "rss_bytes": self.rss_bytes,
            "dirty_rate_bytes_per_sec": self.dirty_rate_bytes_per_sec,
            "files": [f.to_dict() for f in self.files],
            "findings": [f.to_dict() for f in self.findings],
            "in_envelope": self.in_envelope,
            "cgroup_path": self.cgroup_path,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ProcessSnapshotInfo:
        return cls(
            root_pid=data["root_pid"],
            child_pids=list(data.get("child_pids", [])),
            rss_bytes=int(data.get("rss_bytes", 0)),
            dirty_rate_bytes_per_sec=int(data.get("dirty_rate_bytes_per_sec", 0)),
            files=[FileArtifact.from_dict(f) for f in data.get("files", [])],
            findings=[ResourceFinding.from_dict(f) for f in data.get("findings", [])],
            in_envelope=bool(data.get("in_envelope", False)),
            cgroup_path=data.get("cgroup_path"),
        )


@dataclass
class PreflightReport:
    """Combined preflight compatibility report between Source A and Destination B."""

    compatible: bool
    estimated_cold_downtime_ms: float
    estimated_live_downtime_ms: float
    required_criu_flags: List[str] = field(default_factory=list)
    findings: List[ResourceFinding] = field(default_factory=list)

    @property
    def blockers(self) -> List[ResourceFinding]:
        return [
            f for f in self.findings
            if f.classification == ResourceClassification.BLOCKER
        ]


@dataclass
class PreCopyIterationStats:
    """Metrics for a single iterative pre-dump round."""

    iteration: int
    dirty_bytes: int
    duration_ms: float
    converged: bool
    stop_reason: Optional[str] = None


@dataclass
class MigrationResult:
    """Final outcome and metrics of a migration attempt."""

    migration_id: str
    success: bool
    final_state: MigrationState
    restored_pid: Optional[int] = None
    total_duration_ms: float = 0.0
    freeze_downtime_ms: float = 0.0
    precopy_iterations: List[PreCopyIterationStats] = field(default_factory=list)
    rolled_back: bool = False
    error_message: Optional[str] = None
    state_history: List[MigrationState] = field(default_factory=list)
