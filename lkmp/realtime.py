"""Mission-critical real-time OS scheduling, memory locking, and time-namespace continuity."""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from lkmp.logging_utils import get_logger

logger = get_logger("realtime")

# Linux <sys/mman.h> mlockall flags
MCL_CURRENT = 1
MCL_FUTURE = 2
MCL_ONFAULT = 4


@dataclass
class RealtimeTuningStatus:
    """Result of applying real-time OS tuning (`SCHED_FIFO`, `mlockall`, CPU affinity)."""

    scheduler_applied: bool = False
    scheduler_policy: str = "SCHED_OTHER"
    rt_priority: int = 0
    mlockall_applied: bool = False
    cpu_affinity_applied: bool = False
    pinned_cpus: List[int] = None  # type: ignore[assignment]
    warnings: List[str] = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.pinned_cpus is None:
            self.pinned_cpus = []
        if self.warnings is None:
            self.warnings = []

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TimeNamespaceOffset:
    """Parsed entry from `/proc/<pid>/timens_offsets` (`monotonic` / `boottime`)."""

    clock_id: str
    offset_sec: int
    offset_nsec: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def apply_realtime_agent_tuning(
    rt_priority: int = 0,
    lock_memory: bool = False,
    cpu_affinity: Optional[Iterable[int]] = None,
) -> RealtimeTuningStatus:
    """
    Apply deterministic real-time scheduling (`SCHED_FIFO`), page-lock (`mlockall`),
    and CPU core pinning for `lkmp-agent` so host load spikes cannot preempt switchover.
    Degrades gracefully with recorded warnings when invoked without `CAP_SYS_NICE`/`CAP_IPC_LOCK`
    or on non-Linux platforms.
    """
    status = RealtimeTuningStatus()

    if cpu_affinity is not None:
        cpus = sorted({int(c) for c in cpu_affinity if int(c) >= 0})
        if cpus:
            sched_setaffinity = getattr(os, "sched_setaffinity", None)
            if callable(sched_setaffinity):
                try:
                    sched_setaffinity(0, set(cpus))
                    status.cpu_affinity_applied = True
                    status.pinned_cpus = cpus
                except OSError as exc:
                    msg = f"sched_setaffinity({cpus}) failed: {exc}"
                    status.warnings.append(msg)
                    logger.warning(msg)
            else:
                status.warnings.append("os.sched_setaffinity not supported on this platform")

    if lock_memory:
        if sys.platform.startswith("linux"):
            try:
                libc_name = ctypes.util.find_library("c") or "libc.so.6"
                libc = ctypes.CDLL(libc_name, use_errno=True)
                rc = libc.mlockall(MCL_CURRENT | MCL_FUTURE)
                if rc == 0:
                    status.mlockall_applied = True
                else:
                    err = ctypes.get_errno()
                    msg = f"mlockall(MCL_CURRENT|MCL_FUTURE) failed: errno={err} ({os.strerror(err)})"
                    status.warnings.append(msg)
                    logger.warning(msg)
            except Exception as exc:
                msg = f"mlockall invocation failed: {exc}"
                status.warnings.append(msg)
                logger.warning(msg)
        else:
            status.warnings.append(f"mlockall real-time pinning skipped on {sys.platform}")

    if rt_priority > 0:
        clamped_prio = max(1, min(99, int(rt_priority)))
        sched_fifo = getattr(os, "SCHED_FIFO", None)
        sched_setscheduler = getattr(os, "sched_setscheduler", None)
        sched_param_cls = getattr(os, "sched_param", None)
        if sched_fifo is not None and callable(sched_setscheduler) and sched_param_cls is not None:
            try:
                sched_setscheduler(0, sched_fifo, sched_param_cls(clamped_prio))
                status.scheduler_applied = True
                status.scheduler_policy = "SCHED_FIFO"
                status.rt_priority = clamped_prio
            except OSError as exc:
                msg = f"sched_setscheduler(SCHED_FIFO, {clamped_prio}) failed: {exc}"
                status.warnings.append(msg)
                logger.warning(msg)
        else:
            status.warnings.append("POSIX real-time SCHED_FIFO unavailable on this platform")

    return status


def read_timens_offsets(pid: int, proc_root: str = "/proc") -> List[TimeNamespaceOffset]:
    """
    Read `/proc/<pid>/timens_offsets` to verify `CLOCK_MONOTONIC` and `CLOCK_BOOTTIME`
    virtualization across hosts (preventing timer jumps after live migration).
    """
    offsets_file = Path(proc_root) / str(pid) / "timens_offsets"
    if not offsets_file.exists():
        return []
    entries: List[TimeNamespaceOffset] = []
    try:
        for line in offsets_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            parts = line.split()
            if len(parts) >= 3:
                clock_id = parts[0]
                sec = int(parts[1])
                nsec = int(parts[2])
                entries.append(
                    TimeNamespaceOffset(
                        clock_id=clock_id,
                        offset_sec=sec,
                        offset_nsec=nsec,
                    )
                )
    except (OSError, ValueError) as exc:
        logger.debug("Unable to read timens_offsets for pid=%s: %s", pid, exc)
    return entries


def resolve_tmpfs_work_dir(
    requested_work_dir: str | Path,
    prefer_tmpfs: bool = False,
    min_free_bytes: int = 64 * 1024 * 1024,
) -> Tuple[Path, bool]:
    """
    Resolve checkpoint staging directory. When `prefer_tmpfs=True` and `/dev/shm` is a
    writable RAM-backed tmpfs with at least `min_free_bytes` available, returns
    `(/dev/shm/lkmp-migrations, True)` so checkpoint `.img` I/O never touches SSD/NVMe.
    """
    req = Path(requested_work_dir)
    if not prefer_tmpfs:
        return req, False

    shm = Path("/dev/shm")
    if sys.platform.startswith("linux") and shm.is_dir() and os.access(shm, os.W_OK):
        try:
            st = os.statvfs(shm)
            free_bytes = st.f_bavail * st.f_frsize
            if free_bytes >= min_free_bytes:
                tmpfs_dir = shm / "lkmp-migrations"
                tmpfs_dir.mkdir(parents=True, exist_ok=True)
                return tmpfs_dir, True
        except OSError as exc:
            logger.warning("Unable to allocate tmpfs staging in /dev/shm: %s", exc)

    return req, False
