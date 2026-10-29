"""Phase 1: Preflight inspection, ELF build-id parser, and host compatibility verifier."""

from __future__ import annotations

import hashlib
import os
import platform
import struct
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from lkmp.config import FilesystemMode, GpuPlugin, MigrationConfig, MigrationStrategy
from lkmp.models import (
    FileArtifact,
    HostCapabilities,
    PreflightReport,
    ProcessSnapshotInfo,
    ResourceClassification,
    ResourceFinding,
)
from lkmp.pagemap import sample_process_dirty_rate

# Critical instruction-set flags selected by glibc IFUNC / runtime dispatchers.
CRITICAL_ISA_FLAGS: Set[str] = {
    "sse2",
    "ssse3",
    "sse4_1",
    "sse4_2",
    "avx",
    "avx2",
    "avx512f",
    "avx512dq",
    "avx512ifma",
    "avx512cd",
    "avx512bw",
    "avx512vl",
    "avx512vbmi",
    "bmi1",
    "bmi2",
    "fma",
    "f16c",
    "xsave",
    "xsaveopt",
    "xsavec",
    "xsaves",
    "aes",
    "pclmulqdq",
    "neon",
    "asimd",
    "sve",
    "sve2",
}

ALLOWED_DEVICE_PREFIXES = (
    "/dev/null",
    "/dev/zero",
    "/dev/full",
    "/dev/random",
    "/dev/urandom",
    "/dev/tty",
    "/dev/console",
    "/dev/ptmx",
    "/dev/pts/",
    "/dev/net/tun",
    "/dev/shm/",
)


def parse_elf_build_id(file_path: str | Path) -> Optional[str]:
    """Extract the hexadecimal GNU build-id from an ELF binary's PT_NOTE segment."""
    path = Path(file_path)
    try:
        with path.open("rb") as f:
            ident = f.read(16)
            if len(ident) < 16 or ident[:4] != b"\x7fELF":
                return None

            ei_class = ident[4]  # 1 = 32-bit, 2 = 64-bit
            ei_data = ident[5]   # 1 = little-endian, 2 = big-endian
            endian = "<" if ei_data == 1 else ">"

            if ei_class == 2:
                # 64-bit ELF header after e_ident (48 bytes)
                hdr = f.read(48)
                if len(hdr) < 48:
                    return None
                (
                    _e_type,
                    _e_machine,
                    _e_version,
                    _e_entry,
                    e_phoff,
                    _e_shoff,
                    _e_flags,
                    _e_ehsize,
                    e_phentsize,
                    e_phnum,
                    _e_shentsize,
                    _e_shnum,
                    _e_shstrndx,
                ) = struct.unpack(f"{endian}HHIQQQIHHHHHH", hdr)
                phdr_fmt = f"{endian}IIQQQQQQ"
                phdr_size = 56
            elif ei_class == 1:
                # 32-bit ELF header after e_ident (36 bytes)
                hdr = f.read(36)
                if len(hdr) < 36:
                    return None
                (
                    _e_type,
                    _e_machine,
                    _e_version,
                    _e_entry,
                    e_phoff,
                    _e_shoff,
                    _e_flags,
                    _e_ehsize,
                    e_phentsize,
                    e_phnum,
                    _e_shentsize,
                    _e_shnum,
                    _e_shstrndx,
                ) = struct.unpack(f"{endian}HHIIIIIHHHHHH", hdr)
                phdr_fmt = f"{endian}IIIIIIII"
                phdr_size = 32
            else:
                return None

            PT_NOTE = 4
            NT_GNU_BUILD_ID = 3

            for i in range(min(e_phnum, 128)):
                f.seek(e_phoff + i * e_phentsize)
                ph_raw = f.read(phdr_size)
                if len(ph_raw) < phdr_size:
                    break
                if ei_class == 2:
                    p_type, _p_flags, p_offset, _p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_align = (
                        struct.unpack(phdr_fmt, ph_raw)
                    )
                else:
                    p_type, p_offset, _p_vaddr, _p_paddr, p_filesz, _p_memsz, _p_flags, _p_align = (
                        struct.unpack(phdr_fmt, ph_raw)
                    )

                if p_type != PT_NOTE or p_filesz == 0 or p_filesz > 1024 * 1024:
                    continue

                f.seek(p_offset)
                note_data = f.read(p_filesz)
                pos = 0
                while pos + 12 <= len(note_data):
                    namesz, descsz, n_type = struct.unpack(
                        f"{endian}III", note_data[pos : pos + 12]
                    )
                    pos += 12
                    name_aligned = (namesz + 3) & ~3
                    desc_aligned = (descsz + 3) & ~3
                    if pos + name_aligned + desc_aligned > len(note_data):
                        break
                    name = note_data[pos : pos + namesz]
                    pos += name_aligned
                    desc = note_data[pos : pos + descsz]
                    pos += desc_aligned
                    if n_type == NT_GNU_BUILD_ID and name in (b"GNU\x00", b"GNU"):
                        return desc.hex()
    except OSError:
        return None
    return None


def compute_file_sha256(file_path: str | Path, max_bytes: int = 16 * 1024 * 1024) -> Optional[str]:
    """Compute SHA-256 digest of a file (bounded to max_bytes for fast preflight)."""
    path = Path(file_path)
    try:
        h = hashlib.sha256()
        remaining = max_bytes
        with path.open("rb") as f:
            while remaining > 0:
                chunk = f.read(min(65536, remaining))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
        return h.hexdigest()
    except OSError:
        return None


def parse_proc_cpuinfo(cpuinfo_text: str) -> tuple[str, Set[str]]:
    """Parse `/proc/cpuinfo` content to extract vendor and CPU feature flags."""
    vendor = "unknown"
    flags: Set[str] = set()
    for line in cpuinfo_text.splitlines():
        if ":" not in line:
            continue
        key, val = [part.strip() for part in line.split(":", 1)]
        key_lower = key.lower()
        if key_lower in ("vendor_id", "cpu implementer"):
            vendor = val
        elif key_lower in ("flags", "features"):
            flags.update(val.lower().split())
    return vendor, flags


def collect_host_capabilities(proc_root: str = "/proc") -> HostCapabilities:
    """Inspect local host architecture, kernel, and CPU capabilities."""
    arch = platform.machine()
    kernel_release = platform.release()
    cpuinfo_path = Path(proc_root) / "cpuinfo"
    vendor = "unknown"
    flags: Set[str] = set()
    if cpuinfo_path.exists():
        try:
            vendor, flags = parse_proc_cpuinfo(cpuinfo_path.read_text(encoding="utf-8", errors="ignore"))
        except OSError:
            pass

    has_uffd = Path("/proc/sys/vm/unprivileged_userfaultfd").exists() or Path("/dev/userfaultfd").exists()
    has_time_ns = Path("/proc/self/ns/time").exists()
    has_cgroup_v2 = Path("/sys/fs/cgroup/cgroup.controllers").exists()

    return HostCapabilities(
        arch=arch,
        kernel_release=kernel_release,
        cpu_vendor=vendor,
        cpu_flags=flags,
        criu_available=False,
        has_userfaultfd=has_uffd,
        has_soft_dirty=True,
        has_time_ns=has_time_ns,
        has_cgroup_v2=has_cgroup_v2,
    )


def inspect_process_tree(
    pid: int,
    proc_root: str = "/proc",
    ghost_limit_bytes: int = 64 * 1024 * 1024,
) -> ProcessSnapshotInfo:
    """Inspect `/proc/<pid>` to gather memory, open fds, mapped binaries, and blockers."""
    proc_dir = Path(proc_root) / str(pid)
    if not proc_dir.exists():
        raise FileNotFoundError(f"Process {pid} does not exist in {proc_root}")

    findings: List[ResourceFinding] = []
    files_by_path: Dict[str, FileArtifact] = {}
    rss_bytes = 0
    in_envelope = False
    cgroup_path: Optional[str] = None

    # 1. Inspect /proc/<pid>/status for VmRSS and TracerPid
    status_file = proc_dir / "status"
    if status_file.exists():
        for line in status_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("VmRSS:"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit():
                    rss_bytes = int(parts[1]) * 1024
            elif line.startswith("TracerPid:"):
                parts = line.split()
                if len(parts) >= 2 and parts[1].isdigit() and int(parts[1]) != 0:
                    findings.append(
                        ResourceFinding(
                            resource_type="ptrace",
                            identifier=f"TracerPid:{parts[1]}",
                            classification=ResourceClassification.BLOCKER,
                            reason=f"Process {pid} is currently traced by PID {parts[1]}",
                        )
                    )
            elif line.startswith("NSpid:"):
                parts = line.split()[1:]
                # If NSpid has > 1 entry or its innermost PID is 1, it is inside a child PID namespace
                if len(parts) > 1 or (len(parts) == 1 and parts[0] == "1"):
                    in_envelope = True

    # 2. Inspect /proc/<pid>/cgroup
    cg_file = proc_dir / "cgroup"
    if cg_file.exists():
        for line in cg_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("0::"):
                cgroup_path = line.split("0::", 1)[1].strip()
                if "/lkmp/" in cgroup_path:
                    in_envelope = True

    # 3. Inspect /proc/<pid>/maps for memory-mapped executables and libraries
    maps_file = proc_dir / "maps"
    if maps_file.exists():
        for line in maps_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            parts = line.split(None, 5)
            if len(parts) < 6:
                continue
            perms = parts[1]
            pathname = parts[5].strip()
            if not pathname or pathname.startswith("["):
                continue

            is_deleted = pathname.endswith(" (deleted)")
            clean_path = pathname[:-10] if is_deleted else pathname

            if clean_path.startswith("/dev/"):
                _classify_device(clean_path, "mmap", findings)
                continue

            if clean_path not in files_by_path:
                artifact = _build_file_artifact(
                    clean_path,
                    is_deleted=is_deleted,
                    is_mapped_executable=("x" in perms),
                )
                files_by_path[clean_path] = artifact
                if is_deleted and artifact.size > ghost_limit_bytes:
                    findings.append(
                        ResourceFinding(
                            resource_type="ghost_file",
                            identifier=clean_path,
                            classification=ResourceClassification.NEEDS_FLAG,
                            reason=(
                                f"Deleted mapped file ({artifact.size} bytes) exceeds default "
                                f"ghost limit ({ghost_limit_bytes} bytes)"
                            ),
                            suggested_flag=f"--ghost-limit {artifact.size + 1024 * 1024}",
                        )
                    )

    # 4. Inspect /proc/<pid>/fd for open files, sockets, pipes, and special fds
    fd_dir = proc_dir / "fd"
    if fd_dir.exists():
        try:
            for fd_entry in fd_dir.iterdir():
                try:
                    target = os.readlink(fd_entry)
                except OSError:
                    continue
                _classify_fd_target(
                    fd_entry.name,
                    target,
                    files_by_path,
                    findings,
                    ghost_limit_bytes,
                )
        except OSError:
            pass

    # 5. Discover child PIDs via /proc/<pid>/task/*/children
    child_pids: List[int] = []
    task_dir = proc_dir / "task"
    if task_dir.exists():
        for tid_dir in task_dir.iterdir():
            children_file = tid_dir / "children"
            if children_file.exists():
                for token in children_file.read_text(encoding="utf-8", errors="ignore").split():
                    if token.isdigit():
                        cpid = int(token)
                        if cpid not in child_pids:
                            child_pids.append(cpid)

    dirty_rate_bps = 0
    if (proc_dir / "pagemap").exists() and maps_file.exists():
        try:
            heat = sample_process_dirty_rate(pid, proc_root=proc_root, sample_ms=0)
            dirty_rate_bps = heat.dirty_rate_bytes_per_sec
            if rss_bytes == 0 and heat.rss_bytes > 0:
                rss_bytes = heat.rss_bytes
        except Exception:
            dirty_rate_bps = 0

    return ProcessSnapshotInfo(
        root_pid=pid,
        child_pids=child_pids,
        rss_bytes=rss_bytes,
        dirty_rate_bytes_per_sec=dirty_rate_bps,
        files=list(files_by_path.values()),
        findings=findings,
        in_envelope=in_envelope,
        cgroup_path=cgroup_path,
    )


def _build_file_artifact(
    clean_path: str,
    is_deleted: bool,
    is_mapped_executable: bool,
) -> FileArtifact:
    size = 0
    sha256: Optional[str] = None
    build_id: Optional[str] = None
    if not is_deleted and os.path.exists(clean_path):
        try:
            st = os.stat(clean_path)
            size = st.st_size
            if is_mapped_executable:
                build_id = parse_elf_build_id(clean_path)
            if build_id is None and size <= 16 * 1024 * 1024:
                sha256 = compute_file_sha256(clean_path)
        except OSError:
            pass
    return FileArtifact(
        path=clean_path,
        size=size,
        sha256=sha256,
        build_id=build_id,
        is_deleted=is_deleted,
        is_mapped_executable=is_mapped_executable,
    )


def _classify_device(
    dev_path: str,
    source_kind: str,
    findings: List[ResourceFinding],
) -> None:
    if any(dev_path.startswith(prefix) for prefix in ALLOWED_DEVICE_PREFIXES):
        return
    if dev_path.startswith("/dev/nvidia"):
        findings.append(
            ResourceFinding(
                resource_type="gpu_device",
                identifier=dev_path,
                classification=ResourceClassification.NEEDS_FLAG,
                reason="NVIDIA GPU device open; requires cuda-checkpoint plugin",
                suggested_flag="--gpu-plugin cuda-checkpoint",
            )
        )
    elif dev_path.startswith("/dev/dri/") or dev_path.startswith("/dev/kfd"):
        findings.append(
            ResourceFinding(
                resource_type="gpu_device",
                identifier=dev_path,
                classification=ResourceClassification.NEEDS_FLAG,
                reason="AMD/DRI GPU device open; requires CRIU amdgpu_plugin",
                suggested_flag="--gpu-plugin amdgpu",
            )
        )
    else:
        findings.append(
            ResourceFinding(
                resource_type=source_kind,
                identifier=dev_path,
                classification=ResourceClassification.BLOCKER,
                reason=f"Non-migratable hardware device {dev_path}",
            )
        )


def _classify_fd_target(
    fd_num: str,
    target: str,
    files_by_path: Dict[str, FileArtifact],
    findings: List[ResourceFinding],
    ghost_limit_bytes: int,
) -> None:
    if "io_uring" in target:
        findings.append(
            ResourceFinding(
                resource_type="fd",
                identifier=f"fd:{fd_num}->{target}",
                classification=ResourceClassification.BLOCKER,
                reason="Kernel io_uring rings cannot be safely checkpointed by CRIU",
            )
        )
        return

    if target.startswith(("pipe:", "socket:", "anon_inode:")):
        return

    is_deleted = target.endswith(" (deleted)")
    clean_path = target[:-10] if is_deleted else target

    if clean_path.startswith("/dev/"):
        _classify_device(clean_path, "fd", findings)
        return

    if clean_path.startswith(("/run/dbus/", "/run/systemd/", "/var/run/dbus/")):
        findings.append(
            ResourceFinding(
                resource_type="fd",
                identifier=f"fd:{fd_num}->{clean_path}",
                classification=ResourceClassification.NEEDS_FLAG,
                reason=f"External host service socket {clean_path}",
                suggested_flag="--ext-unix-sk",
            )
        )
        return

    if clean_path.startswith("/") and clean_path not in files_by_path:
        artifact = _build_file_artifact(
            clean_path,
            is_deleted=is_deleted,
            is_mapped_executable=False,
        )
        files_by_path[clean_path] = artifact
        if is_deleted and artifact.size > ghost_limit_bytes:
            findings.append(
                ResourceFinding(
                    resource_type="ghost_file",
                    identifier=clean_path,
                    classification=ResourceClassification.NEEDS_FLAG,
                    reason=(
                        f"Deleted open file ({artifact.size} bytes) exceeds "
                        f"ghost limit ({ghost_limit_bytes} bytes)"
                    ),
                    suggested_flag=f"--ghost-limit {artifact.size + 1024 * 1024}",
                )
            )


def evaluate_compatibility(
    config: MigrationConfig,
    source_caps: HostCapabilities,
    dest_caps: HostCapabilities,
    snapshot: ProcessSnapshotInfo,
    dest_files: Dict[str, FileArtifact],
) -> PreflightReport:
    """Compare Source A and Destination B capabilities and files to produce a PreflightReport."""
    findings: List[ResourceFinding] = list(snapshot.findings)
    required_flags: List[str] = []

    # 1. Architecture check
    if source_caps.arch != dest_caps.arch:
        findings.append(
            ResourceFinding(
                resource_type="arch",
                identifier=f"{source_caps.arch}->{dest_caps.arch}",
                classification=ResourceClassification.BLOCKER,
                reason=(
                    f"Cross-architecture process migration ({source_caps.arch} -> "
                    f"{dest_caps.arch}) is not supported"
                ),
            )
        )

    # 2. CPU instruction-set superset check (Destination B must be a superset of Source A)
    missing_isa = (source_caps.cpu_flags & CRITICAL_ISA_FLAGS) - dest_caps.cpu_flags
    if missing_isa:
        missing_str = ", ".join(sorted(missing_isa))
        findings.append(
            ResourceFinding(
                resource_type="cpu",
                identifier=missing_str,
                classification=ResourceClassification.BLOCKER,
                reason=(
                    f"Destination CPU is missing critical instruction flags present on "
                    f"source ({missing_str}); restored process may crash with SIGILL"
                ),
            )
        )

    # 3. Kernel feature checks for chosen migration strategy
    if config.strategy in (MigrationStrategy.LAZY, MigrationStrategy.HYBRID):
        if not dest_caps.has_userfaultfd:
            findings.append(
                ResourceFinding(
                    resource_type="kernel",
                    identifier="userfaultfd",
                    classification=ResourceClassification.BLOCKER,
                    reason="Destination host lacks userfaultfd support required for lazy pages",
                )
            )

    if config.strategy in (MigrationStrategy.PRE_COPY, MigrationStrategy.HYBRID):
        if not source_caps.has_soft_dirty:
            findings.append(
                ResourceFinding(
                    resource_type="kernel",
                    identifier="soft_dirty",
                    classification=ResourceClassification.BLOCKER,
                    reason="Source host lacks MEM_SOFT_DIRTY page tracking required for pre-copy",
                )
            )

    # 4. Envelope check
    if not snapshot.in_envelope and not config.unsafe_bare:
        findings.append(
            ResourceFinding(
                resource_type="namespace",
                identifier=f"pid:{snapshot.root_pid}",
                classification=ResourceClassification.BLOCKER,
                reason=(
                    "Process is not isolated inside an lkmp migration envelope; "
                    "pass --unsafe-bare to migrate a bare host process"
                ),
                suggested_flag="--unsafe-bare",
            )
        )

    # 5. GPU device findings vs configured plugin
    upgraded_findings: List[ResourceFinding] = []
    for f in findings:
        if f.resource_type == "gpu_device":
            if "nvidia" in f.identifier and config.gpu_plugin != GpuPlugin.CUDA:
                upgraded_findings.append(
                    ResourceFinding(
                        resource_type=f.resource_type,
                        identifier=f.identifier,
                        classification=ResourceClassification.BLOCKER,
                        reason="Process uses NVIDIA GPU but --gpu-plugin cuda-checkpoint is not enabled",
                        suggested_flag="--gpu-plugin cuda-checkpoint",
                    )
                )
                continue
            if ("dri" in f.identifier or "kfd" in f.identifier) and config.gpu_plugin != GpuPlugin.AMDGPU:
                upgraded_findings.append(
                    ResourceFinding(
                        resource_type=f.resource_type,
                        identifier=f.identifier,
                        classification=ResourceClassification.BLOCKER,
                        reason="Process uses AMD GPU but --gpu-plugin amdgpu is not enabled",
                        suggested_flag="--gpu-plugin amdgpu",
                    )
                )
                continue
        upgraded_findings.append(f)
    findings = upgraded_findings

    # 6. File presence, size, and ELF build-id / SHA-256 verification on Destination B
    for src_file in snapshot.files:
        if src_file.is_deleted:
            continue
        # If rsync mode is used and the file is inside one of the synced writable paths,
        # it will be synchronized during Prepare/Freeze, so skip strict preflight mismatch.
        if config.fs_mode == FilesystemMode.RSYNC and any(
            src_file.path.startswith(wp.rstrip("/") + "/") or src_file.path == wp
            for wp in config.writable_paths
        ):
            continue

        dst_file = dest_files.get(src_file.path)
        if dst_file is None:
            findings.append(
                ResourceFinding(
                    resource_type="file",
                    identifier=src_file.path,
                    classification=ResourceClassification.BLOCKER,
                    reason=f"Required file {src_file.path} is missing on destination host",
                )
            )
            continue

        if src_file.size != dst_file.size:
            findings.append(
                ResourceFinding(
                    resource_type="file",
                    identifier=src_file.path,
                    classification=ResourceClassification.BLOCKER,
                    reason=(
                        f"File size mismatch for {src_file.path}: "
                        f"source={src_file.size} bytes, dest={dst_file.size} bytes"
                    ),
                )
            )
            continue

        if src_file.build_id and dst_file.build_id and src_file.build_id != dst_file.build_id:
            findings.append(
                ResourceFinding(
                    resource_type="file",
                    identifier=src_file.path,
                    classification=ResourceClassification.BLOCKER,
                    reason=(
                        f"ELF build-id mismatch for {src_file.path}: "
                        f"source={src_file.build_id}, dest={dst_file.build_id}"
                    ),
                )
            )
        elif src_file.sha256 and dst_file.sha256 and src_file.sha256 != dst_file.sha256:
            findings.append(
                ResourceFinding(
                    resource_type="file",
                    identifier=src_file.path,
                    classification=ResourceClassification.BLOCKER,
                    reason=f"File SHA-256 mismatch for {src_file.path}",
                )
            )

    # Collect required CRIU flags from NEEDS_FLAG findings
    for f in findings:
        if f.classification == ResourceClassification.NEEDS_FLAG and f.suggested_flag:
            if f.suggested_flag not in required_flags:
                required_flags.append(f.suggested_flag)

    # 7. Downtime estimation
    bw_bytes_per_sec = max(1.0, (config.estimated_bandwidth_mbps * 1_000_000.0) / 8.0)
    cold_downtime_ms = (snapshot.rss_bytes / bw_bytes_per_sec) * 1000.0 + 50.0
    if config.strategy == MigrationStrategy.COLD:
        live_downtime_ms = cold_downtime_ms
    elif config.strategy in (MigrationStrategy.LAZY, MigrationStrategy.HYBRID):
        live_downtime_ms = 35.0
    else:
        # Pre-copy: estimated final delta + restore overhead
        estimated_final_dirty = min(
            snapshot.rss_bytes,
            max(snapshot.dirty_rate_bytes_per_sec * 0.2, snapshot.rss_bytes * 0.05),
        )
        live_downtime_ms = (estimated_final_dirty / bw_bytes_per_sec) * 1000.0 + 40.0

    compatible = not any(
        f.classification == ResourceClassification.BLOCKER for f in findings
    )

    return PreflightReport(
        compatible=compatible,
        estimated_cold_downtime_ms=round(cold_downtime_ms, 2),
        estimated_live_downtime_ms=round(live_downtime_ms, 2),
        required_criu_flags=required_flags,
        findings=findings,
    )
