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


class PortabilityStatus(str, Enum):
    """Four-state portability confidence level across migration domains."""

    BLOCKED = "BLOCKED"
    PREPARE = "PREPARE"
    NEEDS_PREPARATION = "PREPARE"  # Alias
    UNKNOWN = "UNKNOWN"
    VERIFIED = "VERIFIED"


class ResourceClassification(str, Enum):
    """Classification of a process resource discovered during preflight."""

    OK = "ok"
    NEEDS_FLAG = "needs_flag"
    BLOCKER = "blocker"
    UNKNOWN = "unknown"


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
    criu_check_extra_ok: Optional[bool] = None
    criu_checked_features: Dict[str, bool] = field(default_factory=dict)
    host_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["cpu_flags"] = sorted(self.cpu_flags)
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> HostCapabilities:
        d = dict(data)
        d["cpu_flags"] = set(d.get("cpu_flags", []))
        d["criu_checked_features"] = dict(d.get("criu_checked_features", {}))
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
    dirty_rate_actively_sampled: bool = False

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
            "dirty_rate_actively_sampled": self.dirty_rate_actively_sampled,
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
            dirty_rate_actively_sampled=bool(data.get("dirty_rate_actively_sampled", False)),
        )


@dataclass
class DomainPortabilityAssessment:
    """Portability evaluation for one of the 5 migration domains."""

    domain: str  # "memory_and_cpu" | "files" | "network" | "devices" | "external_resources"
    status: PortabilityStatus
    summary: str
    findings: List[ResourceFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "domain": self.domain,
            "status": self.status.value,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DomainPortabilityAssessment:
        return cls(
            domain=data["domain"],
            status=PortabilityStatus(data["status"]),
            summary=data.get("summary", ""),
            findings=[ResourceFinding.from_dict(f) for f in data.get("findings", [])],
        )


@dataclass
class PortabilityReport:
    """Comprehensive 4-state portability report across all 5 domains."""

    overall_status: PortabilityStatus
    compatible: bool
    domains: Dict[str, DomainPortabilityAssessment] = field(default_factory=dict)
    estimated_cold_downtime_ms: float = 0.0
    estimated_live_downtime_ms: float = 0.0
    required_criu_flags: List[str] = field(default_factory=list)
    findings: List[ResourceFinding] = field(default_factory=list)
    check_only_executed: bool = False
    trial_restore_executed: bool = False
    same_host_fast_path_available: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_status": self.overall_status.value,
            "compatible": self.compatible,
            "domains": {k: v.to_dict() for k, v in self.domains.items()},
            "estimated_cold_downtime_ms": self.estimated_cold_downtime_ms,
            "estimated_live_downtime_ms": self.estimated_live_downtime_ms,
            "required_criu_flags": list(self.required_criu_flags),
            "findings": [f.to_dict() for f in self.findings],
            "check_only_executed": self.check_only_executed,
            "trial_restore_executed": self.trial_restore_executed,
            "same_host_fast_path_available": self.same_host_fast_path_available,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PortabilityReport:
        return cls(
            overall_status=PortabilityStatus(data["overall_status"]),
            compatible=bool(data["compatible"]),
            domains={
                k: DomainPortabilityAssessment.from_dict(v)
                for k, v in data.get("domains", {}).items()
            },
            estimated_cold_downtime_ms=float(data.get("estimated_cold_downtime_ms", 0.0)),
            estimated_live_downtime_ms=float(data.get("estimated_live_downtime_ms", 0.0)),
            required_criu_flags=list(data.get("required_criu_flags", [])),
            findings=[ResourceFinding.from_dict(f) for f in data.get("findings", [])],
            check_only_executed=bool(data.get("check_only_executed", False)),
            trial_restore_executed=bool(data.get("trial_restore_executed", False)),
            same_host_fast_path_available=bool(data.get("same_host_fast_path_available", False)),
        )

    @property
    def blockers(self) -> List[ResourceFinding]:
        return [
            f for f in self.findings
            if f.classification == ResourceClassification.BLOCKER
        ]

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, (PortabilityStatus, str)):
            return self.overall_status.value == (other.value if isinstance(other, PortabilityStatus) else other)
        if isinstance(other, PortabilityReport):
            return (
                self.overall_status == other.overall_status
                and self.compatible == other.compatible
                and self.domains == other.domains
                and self.estimated_cold_downtime_ms == other.estimated_cold_downtime_ms
                and self.estimated_live_downtime_ms == other.estimated_live_downtime_ms
                and self.required_criu_flags == other.required_criu_flags
                and self.findings == other.findings
                and self.check_only_executed == other.check_only_executed
                and self.trial_restore_executed == other.trial_restore_executed
                and self.same_host_fast_path_available == other.same_host_fast_path_available
            )
        return False


@dataclass
class PreflightReport:
    """Combined preflight compatibility report between Source A and Destination B."""

    compatible: bool
    estimated_cold_downtime_ms: float
    estimated_live_downtime_ms: float
    required_criu_flags: List[str] = field(default_factory=list)
    findings: List[ResourceFinding] = field(default_factory=list)
    portability_status: PortabilityStatus = PortabilityStatus.UNKNOWN
    domains: Dict[str, DomainPortabilityAssessment] = field(default_factory=dict)

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


# ---------------------------------------------------------------------------
# LKMP v2.0 Multi-Process Set Models
# ---------------------------------------------------------------------------


class CouplingScope(str, Enum):
    """Scope of a shared kernel resource (pipe, socket, shm, file)."""

    INTRA_TREE = "INTRA_TREE"
    INTER_TREE_CLOSED = "INTER_TREE_CLOSED"
    EXTERNAL_UNCLOSED_PEER = "EXTERNAL_UNCLOSED_PEER"


@dataclass
class CouplingEdge:
    """Coupling relationship between processes via shared kernel resources."""

    resource_type: str  # "pipe", "unix_socket", "shm", "shared_file"
    resource_id: str  # e.g., "pipe:[12345]"
    source_pid: int
    source_root_pid: int
    peer_pid: int
    peer_root_pid: Optional[int] = None
    peer_comm: str = ""
    scope: CouplingScope = CouplingScope.INTRA_TREE

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "source_pid": self.source_pid,
            "source_root_pid": self.source_root_pid,
            "peer_pid": self.peer_pid,
            "peer_root_pid": self.peer_root_pid,
            "peer_comm": self.peer_comm,
            "scope": self.scope.value if isinstance(self.scope, CouplingScope) else str(self.scope),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CouplingEdge:
        d = dict(data)
        if "scope" in d and isinstance(d["scope"], str):
            d["scope"] = CouplingScope(d["scope"])
        return cls(**d)


@dataclass
class ProcessForestTopology:
    """Minimal disjoint process forest topology computed from pointed PIDs."""

    pointed_pids: List[int]
    root_pids: List[int]  # Minimal disjoint roots after pruning descendants
    all_pids: List[int]  # Union of all PIDs across all trees
    trees_by_root: Dict[int, List[int]] = field(default_factory=dict)
    absorbed_pids: Dict[int, int] = field(default_factory=dict)  # pointed child PID -> absorbing ancestor root PID
    starttimes_by_pid: Dict[int, int] = field(default_factory=dict)
    shared_anchor_pid: Optional[int] = None
    execution_mode: str = "LOCKSTEP_FOREST"  # "SHARED_ANCHOR" | "LOCKSTEP_FOREST"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pointed_pids": list(self.pointed_pids),
            "root_pids": list(self.root_pids),
            "all_pids": list(self.all_pids),
            "trees_by_root": {int(k): list(v) for k, v in self.trees_by_root.items()},
            "absorbed_pids": {int(k): int(v) for k, v in self.absorbed_pids.items()},
            "starttimes_by_pid": {int(k): int(v) for k, v in self.starttimes_by_pid.items()},
            "shared_anchor_pid": self.shared_anchor_pid,
            "execution_mode": self.execution_mode,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ProcessForestTopology:
        return cls(
            pointed_pids=[int(x) for x in data.get("pointed_pids", [])],
            root_pids=[int(x) for x in data.get("root_pids", [])],
            all_pids=[int(x) for x in data.get("all_pids", [])],
            trees_by_root={int(k): [int(x) for x in v] for k, v in data.get("trees_by_root", {}).items()},
            absorbed_pids={int(k): int(v) for k, v in data.get("absorbed_pids", {}).items()},
            starttimes_by_pid={int(k): int(v) for k, v in data.get("starttimes_by_pid", {}).items()},
            shared_anchor_pid=int(data["shared_anchor_pid"]) if data.get("shared_anchor_pid") is not None else None,
            execution_mode=str(data.get("execution_mode", "LOCKSTEP_FOREST")),
        )


@dataclass
class ProcessSetPortabilityReport:
    """Preflight portability assessment for a set of processes."""

    set_id: str
    topology: ProcessForestTopology
    overall_status: PortabilityStatus
    coupling_edges: List[CouplingEdge] = field(default_factory=list)
    unclosed_external_peers: List[CouplingEdge] = field(default_factory=list)
    inter_tree_closed_edges: List[CouplingEdge] = field(default_factory=list)
    member_reports: Dict[int, PortabilityReport] = field(default_factory=dict)
    recommended_additional_pids: List[int] = field(default_factory=list)
    summary_notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "set_id": self.set_id,
            "topology": self.topology.to_dict(),
            "overall_status": self.overall_status.value if isinstance(self.overall_status, PortabilityStatus) else str(self.overall_status),
            "coupling_edges": [e.to_dict() for e in self.coupling_edges],
            "unclosed_external_peers": [e.to_dict() for e in self.unclosed_external_peers],
            "inter_tree_closed_edges": [e.to_dict() for e in self.inter_tree_closed_edges],
            "member_reports": {int(k): v.to_dict() for k, v in self.member_reports.items()},
            "recommended_additional_pids": list(self.recommended_additional_pids),
            "summary_notes": list(self.summary_notes),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ProcessSetPortabilityReport:
        return cls(
            set_id=data["set_id"],
            topology=ProcessForestTopology.from_dict(data["topology"]),
            overall_status=PortabilityStatus(data["overall_status"]),
            coupling_edges=[CouplingEdge.from_dict(e) for e in data.get("coupling_edges", [])],
            unclosed_external_peers=[CouplingEdge.from_dict(e) for e in data.get("unclosed_external_peers", [])],
            inter_tree_closed_edges=[CouplingEdge.from_dict(e) for e in data.get("inter_tree_closed_edges", [])],
            member_reports={int(k): PortabilityReport.from_dict(v) for k, v in data.get("member_reports", {}).items()},
            recommended_additional_pids=[int(x) for x in data.get("recommended_additional_pids", [])],
            summary_notes=list(data.get("summary_notes", [])),
        )


@dataclass
class ProcessSetMigrationResult:
    """End-to-end outcome of a multi-process set live migration."""

    set_id: str
    pointed_pids: List[int]
    root_pids: List[int]
    absorbed_pids: Dict[int, int] = field(default_factory=dict)
    auto_included_pids: List[int] = field(default_factory=list)
    all_committed: bool = False
    atomic_rollback_triggered: bool = False
    co_freeze_barrier_achieved: bool = False
    co_freeze_duration_ms: float = 0.0
    set_merkle_root: str = ""
    member_results: List[MigrationResult] = field(default_factory=list)
    restored_pids_by_root: Dict[int, int] = field(default_factory=dict)
    coupling_edges: List[CouplingEdge] = field(default_factory=list)
    partial_commit_error: bool = False
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "set_id": self.set_id,
            "pointed_pids": list(self.pointed_pids),
            "root_pids": list(self.root_pids),
            "absorbed_pids": {int(k): int(v) for k, v in self.absorbed_pids.items()},
            "auto_included_pids": list(self.auto_included_pids),
            "all_committed": self.all_committed,
            "atomic_rollback_triggered": self.atomic_rollback_triggered,
            "co_freeze_barrier_achieved": self.co_freeze_barrier_achieved,
            "co_freeze_duration_ms": self.co_freeze_duration_ms,
            "set_merkle_root": self.set_merkle_root,
            "member_results": [asdict(r) for r in self.member_results],
            "restored_pids_by_root": {int(k): int(v) for k, v in self.restored_pids_by_root.items()},
            "coupling_edges": [e.to_dict() for e in self.coupling_edges],
            "partial_commit_error": self.partial_commit_error,
            "error_message": self.error_message,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ProcessSetMigrationResult:
        mem_results: List[MigrationResult] = []
        for r in data.get("member_results", []):
            if isinstance(r, dict):
                pre_stats = [
                    PreCopyIterationStats(**s) if isinstance(s, dict) else s
                    for s in r.get("precopy_iterations", [])
                ]
                sh = [
                    MigrationState(s) if isinstance(s, str) else s
                    for s in r.get("state_history", [])
                ]
                mem_results.append(
                    MigrationResult(
                        migration_id=r["migration_id"],
                        success=bool(r["success"]),
                        final_state=MigrationState(r["final_state"]) if isinstance(r["final_state"], str) else r["final_state"],
                        restored_pid=r.get("restored_pid"),
                        total_duration_ms=float(r.get("total_duration_ms", 0.0)),
                        freeze_downtime_ms=float(r.get("freeze_downtime_ms", 0.0)),
                        precopy_iterations=pre_stats,
                        rolled_back=bool(r.get("rolled_back", False)),
                        error_message=r.get("error_message"),
                        state_history=sh,
                    )
                )
            elif isinstance(r, MigrationResult):
                mem_results.append(r)

        return cls(
            set_id=data["set_id"],
            pointed_pids=[int(p) for p in data.get("pointed_pids", [])],
            root_pids=[int(p) for p in data.get("root_pids", [])],
            absorbed_pids={int(k): int(v) for k, v in data.get("absorbed_pids", {}).items()},
            auto_included_pids=[int(p) for p in data.get("auto_included_pids", [])],
            all_committed=bool(data.get("all_committed", False)),
            atomic_rollback_triggered=bool(data.get("atomic_rollback_triggered", False)),
            co_freeze_barrier_achieved=bool(data.get("co_freeze_barrier_achieved", False)),
            co_freeze_duration_ms=float(data.get("co_freeze_duration_ms", 0.0)),
            set_merkle_root=str(data.get("set_merkle_root", "")),
            member_results=mem_results,
            restored_pids_by_root={int(k): int(v) for k, v in data.get("restored_pids_by_root", {}).items()},
            coupling_edges=[CouplingEdge.from_dict(e) if isinstance(e, dict) else e for e in data.get("coupling_edges", [])],
            partial_commit_error=bool(data.get("partial_commit_error", False)),
            error_message=data.get("error_message"),
        )
