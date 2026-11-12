"""Base protocol for pluggable workload runtime migration drivers."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional, Protocol, runtime_checkable

from lkmp.config import MigrationConfig
from lkmp.drivers.detector import WorkloadKind


@runtime_checkable
class WorkloadMigrationDriver(Protocol):
    """
    Unified 2PC lifecycle contract implemented by hypervisor and container migration engines
    (`QemuQmpDriver`, `OciContainerDriver`, `MicroVmDriver`, and native `CriuDriver`).

    Every driver maps its runtime's native memory/device state engine onto LKMP's
    Two-Phase Commit state machine, guaranteeing an explicit `PREPARED_STOPPED` barrier
    on Destination B while keeping Source A paused and recoverable until WAL `COMMITTED`.
    """

    kind: WorkloadKind

    def prepare_dest(
        self,
        migration_id: str,
        mig_dir: Path,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        ...

    def start_pre_copy_target(
        self,
        migration_id: str,
        mig_dir: Path,
        round_name: str,
        prev_round_name: Optional[str],
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        ...

    def run_pre_copy_source(
        self,
        migration_id: str,
        mig_dir: Path,
        round_name: str,
        prev_round_name: Optional[str],
        dest_host: str,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        ...

    def freeze_and_dump_source(
        self,
        migration_id: str,
        mig_dir: Path,
        prev_round_name: Optional[str],
        dest_host: str,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        ...

    def restore_stopped_dest(
        self,
        migration_id: str,
        mig_dir: Path,
        source_host: str,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        ...

    def verify_stopped_dest(
        self,
        migration_id: str,
        mig_dir: Path,
        restored_pid: int,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        ...

    def verify_running_dest(
        self,
        migration_id: str,
        mig_dir: Path,
        restored_pid: int,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        ...

    def resume_dest(
        self,
        migration_id: str,
        mig_dir: Path,
        restored_pid: int,
        target_host: str,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        ...

    def commit_source(
        self,
        migration_id: str,
        mig_dir: Path,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        ...

    def rollback_dest(
        self,
        migration_id: str,
        mig_dir: Path,
        restored_pid: Optional[int],
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        ...

    def rollback_source(
        self,
        migration_id: str,
        mig_dir: Path,
        source_host: str,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        ...
