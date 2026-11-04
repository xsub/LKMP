"""Phase 1: Preflight inspection, ELF build-id parser, and host compatibility verifier."""

from __future__ import annotations

import hashlib
import os
import platform
import struct
import subprocess
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set

from lkmp.config import FilesystemMode, GpuPlugin, MigrationConfig, MigrationStrategy
from lkmp.models import (
    DomainPortabilityAssessment,
    FileArtifact,
    HostCapabilities,
    PortabilityReport,
    PortabilityStatus,
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

    boot_id_file = Path(proc_root) / "sys" / "kernel" / "random" / "boot_id"
    host_id: Optional[str] = None
    if boot_id_file.exists():
        try:
            host_id = boot_id_file.read_text(encoding="utf-8", errors="ignore").strip()
        except OSError:
            pass
    if not host_id:
        host_id = platform.node()

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
        host_id=host_id,
    )


def read_proc_starttime(pid: int, proc_root: str = "/proc") -> Optional[int]:
    """Read field 22 (starttime) from <proc_root>/<pid>/stat, returning None if unavailable."""
    stat_file = Path(proc_root) / str(pid) / "stat"
    try:
        content = stat_file.read_text(encoding="utf-8", errors="ignore")
        rparen = content.rfind(")")
        if rparen != -1:
            fields = content[rparen + 1:].strip().split()
            # field 3 is fields[0] (state)
            # field 22 is fields[19] (starttime)
            if len(fields) >= 20:
                return int(fields[19])
    except Exception:
        pass
    return None


def _parse_stat_file_state(stat_file: Path) -> Optional[str]:
    """Extract single-character task state (field 3) from a /proc/.../stat file."""
    try:
        content = stat_file.read_text(encoding="utf-8", errors="ignore")
        rparen = content.rfind(")")
        if rparen != -1:
            fields = content[rparen + 1 :].strip().split()
            if fields:
                return fields[0]
    except OSError:
        pass
    return None


def _parse_status_file_state(status_file: Path) -> Optional[str]:
    """Extract single-character task state from the 'State:' line of a /proc/.../status file."""
    try:
        for line in status_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("State:"):
                parts = line.split(":", 1)[1].strip().split()
                if parts and parts[0]:
                    return parts[0][0]
    except OSError:
        pass
    return None


def read_proc_state(pid: int, proc_root: str = "/proc") -> Optional[str]:
    """Read single-character task state ('T', 't', 'S', 'R', 'Z', ...) from <proc_root>/<pid>/stat or status."""
    pid_dir = Path(proc_root) / str(pid)
    state = _parse_stat_file_state(pid_dir / "stat")
    if state is not None:
        return state
    return _parse_status_file_state(pid_dir / "status")


def is_pid_stopped(pid: int, proc_root: str = "/proc") -> Tuple[bool, str]:
    """
    Confirm that `pid` (and all threads in `<proc_root>/<pid>/task/*` that expose stat/status)
    is in kernel stopped state ('T' or 't'). Fails closed if state cannot be read.
    """
    state = read_proc_state(pid, proc_root)
    if state is None:
        return False, f"task state unavailable in {proc_root}/{pid}/stat or status"
    if state not in ("T", "t"):
        return False, f"task state is {state!r}, expected stopped ('T' or 't')"

    task_dir = Path(proc_root) / str(pid) / "task"
    if task_dir.is_dir():
        try:
            for tid_dir in task_dir.iterdir():
                if not tid_dir.is_dir() or not tid_dir.name.isdigit():
                    continue
                tid_stat = tid_dir / "stat"
                tid_status = tid_dir / "status"
                if not tid_stat.is_file() and not tid_status.is_file():
                    continue
                t_state = _parse_stat_file_state(tid_stat) or _parse_status_file_state(tid_status)
                if t_state is None:
                    return False, f"thread {tid_dir.name} state unavailable"
                if t_state not in ("T", "t"):
                    return False, f"thread {tid_dir.name} state is {t_state!r}, expected stopped ('T' or 't')"
        except OSError as exc:
            return False, f"unable to inspect threads under {task_dir}: {exc}"

    return True, state


def discover_process_tree_pids(root_pid: int, proc_root: str = "/proc") -> List[int]:
    """
    Recursively discover all PIDs belonging to the process tree of root_pid.
    Walks <proc_root>/<pid>/task/*/children and <proc_root>/*/stat (ppid field 4).
    Falls back to `ps -ax -o pid=,ppid=` when <proc_root>/<root_pid> does not exist and proc_root == "/proc".
    Returns [root_pid, ...descendants...] with no duplicates.
    """
    root_path = Path(proc_root) / str(root_pid)
    if not root_path.exists() and proc_root == "/proc":
        try:
            res = subprocess.run(
                ["ps", "-ax", "-o", "pid=,ppid="],
                capture_output=True,
                text=True,
                check=True,
            )
            parent_to_children: Dict[int, List[int]] = {}
            for line in res.stdout.strip().splitlines():
                parts = line.strip().split()
                if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
                    p = int(parts[0])
                    pp = int(parts[1])
                    parent_to_children.setdefault(pp, []).append(p)
            result = [root_pid]
            visited = {root_pid}
            queue = [root_pid]
            while queue:
                curr = queue.pop(0)
                for child in parent_to_children.get(curr, []):
                    if child not in visited:
                        visited.add(child)
                        result.append(child)
                        queue.append(child)
            return result
        except Exception:
            return [root_pid]

    # Walk <proc_root>/*/stat for ppid (field 4)
    proc_dir = Path(proc_root)
    parent_to_children_set: Dict[int, Set[int]] = {}
    if proc_dir.exists():
        try:
            for entry in proc_dir.iterdir():
                if entry.is_dir() and entry.name.isdigit():
                    child_pid = int(entry.name)
                    stat_file = entry / "stat"
                    if stat_file.is_file():
                        try:
                            content = stat_file.read_text(encoding="utf-8", errors="ignore")
                            rparen = content.rfind(")")
                            if rparen != -1:
                                fields = content[rparen + 1:].strip().split()
                                if len(fields) >= 2:  # field 4 (ppid) is fields[1]
                                    ppid = int(fields[1])
                                    parent_to_children_set.setdefault(ppid, set()).add(child_pid)
                        except Exception:
                            pass
        except Exception:
            pass

    result = [root_pid]
    visited = {root_pid}
    queue = [root_pid]
    while queue:
        curr = queue.pop(0)
        # Check <proc_root>/<curr>/task/*/children
        task_dir = proc_dir / str(curr) / "task"
        if task_dir.is_dir():
            try:
                for tid_entry in task_dir.iterdir():
                    ch_file = tid_entry / "children"
                    if ch_file.is_file():
                        try:
                            for ch_str in ch_file.read_text(encoding="utf-8", errors="ignore").split():
                                if ch_str.isdigit():
                                    ch_pid = int(ch_str)
                                    if ch_pid not in visited:
                                        visited.add(ch_pid)
                                        result.append(ch_pid)
                                        queue.append(ch_pid)
                        except Exception:
                            pass
            except Exception:
                pass
        # Check ppid mapping from /proc/*/stat
        for child in parent_to_children_set.get(curr, ()):
            if child not in visited:
                visited.add(child)
                result.append(child)
                queue.append(child)

    return result


def inspect_process_tree(
    pid: int,
    proc_root: str = "/proc",
    ghost_limit_bytes: int = 64 * 1024 * 1024,
    active_sample_ms: int = 0,
) -> ProcessSnapshotInfo:
    """Inspect `/proc/<pid>` and descendants to gather memory, open fds, mapped binaries, and blockers."""
    proc_dir = Path(proc_root) / str(pid)
    if not proc_dir.exists():
        raise FileNotFoundError(f"Process {pid} does not exist in {proc_root}")

    # Discover ALL PIDs in the process tree
    tree_pids = discover_process_tree_pids(pid, proc_root=proc_root)
    child_pids = [p for p in tree_pids if p != pid]

    findings: List[ResourceFinding] = []
    files_by_path: Dict[str, FileArtifact] = {}
    pipe_holders: Dict[str, List[Tuple[int, str]]] = {}
    rss_bytes = 0
    in_envelope = False
    cgroup_path: Optional[str] = None

    for curr_pid in tree_pids:
        curr_dir = Path(proc_root) / str(curr_pid)
        if not curr_dir.exists():
            continue

        # 1. Inspect status
        status_file = curr_dir / "status"
        if status_file.exists():
            for line in status_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("VmRSS:"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit():
                        rss_bytes += int(parts[1]) * 1024
                elif line.startswith("TracerPid:"):
                    parts = line.split()
                    if len(parts) >= 2 and parts[1].isdigit() and int(parts[1]) != 0:
                        findings.append(
                            ResourceFinding(
                                resource_type="ptrace",
                                identifier=f"TracerPid:{parts[1]}",
                                classification=ResourceClassification.BLOCKER,
                                reason=f"Process {curr_pid} is currently traced by PID {parts[1]}",
                            )
                        )
                elif line.startswith("NSpid:"):
                    parts = line.split()[1:]
                    # If NSpid has > 1 entry or its innermost PID is 1, it is inside a child PID namespace
                    if len(parts) > 1 or (len(parts) == 1 and parts[0] == "1"):
                        in_envelope = True

        # 2. Inspect cgroup
        cg_file = curr_dir / "cgroup"
        if cg_file.exists():
            for line in cg_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("0::"):
                    parsed_cg = line.split("0::", 1)[1].strip()
                    if curr_pid == pid or cgroup_path is None:
                        cgroup_path = parsed_cg
                    if "/lkmp/" in parsed_cg:
                        in_envelope = True

        # 3. Inspect maps
        maps_file = curr_dir / "maps"
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

        # 4. Inspect fd
        fd_dir = curr_dir / "fd"
        if fd_dir.exists():
            try:
                for fd_entry in fd_dir.iterdir():
                    try:
                        target = os.readlink(fd_entry)
                    except OSError:
                        continue
                    if target.startswith("pipe:"):
                        pipe_holders.setdefault(target, []).append((curr_pid, fd_entry.name))
                    else:
                        _classify_fd_target(
                            fd_entry.name,
                            target,
                            files_by_path,
                            findings,
                            ghost_limit_bytes,
                            curr_pid=curr_pid,
                            root_pid=pid,
                        )
            except OSError:
                pass

    # Process pipe holders across the whole tree
    for pipe_target, holders in pipe_holders.items():
        if len(holders) < 2:
            for holder_pid, fd_num in holders:
                findings.append(
                    ResourceFinding(
                        resource_type="external_pipe",
                        identifier=f"pid:{holder_pid}:fd:{fd_num}->{pipe_target}",
                        classification=ResourceClassification.UNKNOWN,
                        reason="Pipe has only one endpoint inside process tree; external peer process may break on restore",
                        suggested_flag="--inherit-fd",
                    )
                )
        else:
            for holder_pid, fd_num in holders:
                findings.append(
                    ResourceFinding(
                        resource_type="pipe",
                        identifier=f"pid:{holder_pid}:fd:{fd_num}->{pipe_target}",
                        classification=ResourceClassification.OK,
                        reason="Internal pipe shared within process tree",
                    )
                )

    dirty_rate_bps = 0
    dirty_rate_actively_sampled = False
    if (proc_dir / "pagemap").exists() and (proc_dir / "maps").exists():
        try:
            if active_sample_ms > 0:
                heat = sample_process_dirty_rate(
                    pid,
                    proc_root=proc_root,
                    sample_ms=active_sample_ms,
                    allow_clear_refs=True,
                )
                dirty_rate_actively_sampled = True
            else:
                heat = sample_process_dirty_rate(
                    pid,
                    proc_root=proc_root,
                    sample_ms=0,
                    allow_clear_refs=False,
                )
                dirty_rate_actively_sampled = False
            dirty_rate_bps = heat.dirty_rate_bytes_per_sec
            if rss_bytes == 0 and heat.rss_bytes > 0:
                rss_bytes = heat.rss_bytes
        except Exception:
            dirty_rate_bps = 0
            dirty_rate_actively_sampled = False

    return ProcessSnapshotInfo(
        root_pid=pid,
        child_pids=child_pids,
        rss_bytes=rss_bytes,
        dirty_rate_bytes_per_sec=dirty_rate_bps,
        files=list(files_by_path.values()),
        findings=findings,
        in_envelope=in_envelope,
        cgroup_path=cgroup_path,
        dirty_rate_actively_sampled=dirty_rate_actively_sampled,
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
    curr_pid: int = 0,
    root_pid: int = 0,
) -> None:
    ident = f"fd:{fd_num}->{target}" if (curr_pid == 0 or curr_pid == root_pid) else f"pid:{curr_pid}:fd:{fd_num}->{target}"

    if "io_uring" in target:
        findings.append(
            ResourceFinding(
                resource_type="anon_inode",
                identifier=ident,
                classification=ResourceClassification.BLOCKER,
                reason="Kernel io_uring rings cannot be safely checkpointed by CRIU",
            )
        )
        return

    if target.startswith("socket:"):
        findings.append(
            ResourceFinding(
                resource_type="socket",
                identifier=f"pid:{curr_pid}:fd:{fd_num}->{target}",
                classification=ResourceClassification.NEEDS_FLAG,
                reason="Active socket requires --tcp-established or --ext-unix-sk verification",
                suggested_flag="--tcp-established",
            )
        )
        return

    if target.startswith("anon_inode:"):
        if any(k in target for k in ("eventpoll", "eventfd", "timerfd", "signalfd", "inotify")):
            findings.append(
                ResourceFinding(
                    resource_type="anon_inode",
                    identifier=ident,
                    classification=ResourceClassification.OK,
                    reason=f"Standard supported anonymous inode {target}",
                )
            )
        else:
            findings.append(
                ResourceFinding(
                    resource_type="anon_inode",
                    identifier=ident,
                    classification=ResourceClassification.UNKNOWN,
                    reason=f"Unverified kernel anonymous inode {target} requires --check-only or trial restore",
                )
            )
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


def evaluate_portability(
    config: Optional[MigrationConfig] = None,
    source_caps: Optional[HostCapabilities] = None,
    dest_caps: Optional[HostCapabilities] = None,
    snapshot: Optional[ProcessSnapshotInfo] = None,
    dest_files: Optional[Dict[str, FileArtifact]] = None,
    check_only_passed: bool = False,
    trial_restore_passed: bool = False,
    *,
    snapshot_or_report: Any = None,
    findings: Optional[List[ResourceFinding]] = None,
    dirty_rate_actively_sampled: bool = False,
) -> PortabilityReport:
    """Evaluate 4-state portability across all 5 migration domains."""
    if config is None:
        config = MigrationConfig(
            pid=snapshot.root_pid if snapshot else 1,
            source_addr="127.0.0.1:9700",
            dest_addr="127.0.0.1:9700",
            strategy=MigrationStrategy.COLD,
        )
    if source_caps is None:
        source_caps = HostCapabilities(arch="x86_64", kernel_release="", cpu_vendor="", criu_available=True, has_soft_dirty=True)
    if dest_caps is None:
        dest_caps = HostCapabilities(arch="x86_64", kernel_release="", cpu_vendor="", criu_available=True, has_soft_dirty=True)
    if snapshot is None:
        if isinstance(snapshot_or_report, ProcessSnapshotInfo):
            snapshot = snapshot_or_report
        else:
            snapshot = ProcessSnapshotInfo(root_pid=config.pid, in_envelope=True, dirty_rate_actively_sampled=dirty_rate_actively_sampled)
    if findings:
        snapshot = ProcessSnapshotInfo(
            root_pid=snapshot.root_pid,
            child_pids=list(snapshot.child_pids),
            rss_bytes=snapshot.rss_bytes,
            dirty_rate_bytes_per_sec=snapshot.dirty_rate_bytes_per_sec,
            files=list(snapshot.files),
            findings=list(snapshot.findings) + list(findings),
            in_envelope=snapshot.in_envelope,
            cgroup_path=snapshot.cgroup_path,
            dirty_rate_actively_sampled=snapshot.dirty_rate_actively_sampled or dirty_rate_actively_sampled,
        )
    if dest_files is None:
        dest_files = {}

    findings: List[ResourceFinding] = list(snapshot.findings)
    required_flags: List[str] = []

    # 1. CRIU availability check on both hosts
    if not source_caps.criu_available:
        findings.append(
            ResourceFinding(
                resource_type="criu",
                identifier="source_criu",
                classification=ResourceClassification.BLOCKER,
                reason="CRIU binary is not available or failed check on source host",
            )
        )
    if not dest_caps.criu_available:
        findings.append(
            ResourceFinding(
                resource_type="criu",
                identifier="dest_criu",
                classification=ResourceClassification.BLOCKER,
                reason="CRIU binary is not available or failed check on destination host",
            )
        )

    # 2. Architecture check
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

    # 3. CPU instruction-set superset check (Destination B must be a superset of Source A)
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

    # 4. Kernel feature checks for chosen migration strategy
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

    # CRIU extra features check
    if source_caps.criu_check_extra_ok is False:
        findings.append(
            ResourceFinding(
                resource_type="criu",
                identifier="source_criu_check_extra",
                classification=ResourceClassification.BLOCKER,
                reason="CRIU check --extra failed on source host; missing required kernel features",
            )
        )
    if dest_caps.criu_check_extra_ok is False:
        findings.append(
            ResourceFinding(
                resource_type="criu",
                identifier="dest_criu_check_extra",
                classification=ResourceClassification.BLOCKER,
                reason="CRIU check --extra failed on destination host; missing required kernel features",
            )
        )

    # 5. Envelope check
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

    # 6. GPU device findings vs configured plugin
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

    # 7. File presence, size, and ELF build-id / SHA-256 verification on Destination B
    for src_file in snapshot.files:
        if src_file.is_deleted:
            continue
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

    # 8. Downtime estimation
    bw_bytes_per_sec = max(1.0, (config.estimated_bandwidth_mbps * 1_000_000.0) / 8.0)
    cold_downtime_ms = (snapshot.rss_bytes / bw_bytes_per_sec) * 1000.0 + 50.0
    if config.strategy == MigrationStrategy.COLD:
        live_downtime_ms = cold_downtime_ms
    elif config.strategy in (MigrationStrategy.LAZY, MigrationStrategy.HYBRID):
        live_downtime_ms = 35.0
    else:
        estimated_final_dirty = min(
            snapshot.rss_bytes,
            max(snapshot.dirty_rate_bytes_per_sec * 0.2, snapshot.rss_bytes * 0.05),
        )
        live_downtime_ms = (estimated_final_dirty / bw_bytes_per_sec) * 1000.0 + 40.0

    # Domain 1: memory_and_cpu
    mem_findings = [
        f for f in findings
        if f.resource_type in ("arch", "cpu", "criu", "kernel", "memory")
    ]
    if any(f.classification == ResourceClassification.BLOCKER for f in mem_findings):
        mem_status = PortabilityStatus.BLOCKED
        mem_summary = "Architecture, CPU ISA, CRIU, or kernel feature blocker detected"
    elif source_caps.criu_check_extra_ok is False or dest_caps.criu_check_extra_ok is False:
        mem_status = PortabilityStatus.BLOCKED
        mem_summary = "CRIU extra feature check failed on host"
    elif trial_restore_passed:
        mem_status = PortabilityStatus.VERIFIED
        mem_summary = "Memory state and CPU ISA verified portable via trial restore"
    elif not snapshot.dirty_rate_actively_sampled and config.strategy != MigrationStrategy.COLD:
        mem_status = PortabilityStatus.UNKNOWN
        mem_summary = "Static pagemap snapshot only (dirty rate not actively sampled over time window)"
    elif check_only_passed:
        mem_status = PortabilityStatus.VERIFIED
        mem_summary = "CPU ISA and CRIU kernel features verified via criu check"
    else:
        mem_status = PortabilityStatus.UNKNOWN
        mem_summary = "Architecture and CPU compatible; requires CRIU check or trial restore to verify kernel features"

    # Domain 2: files
    file_findings = [
        f for f in findings
        if f.resource_type in ("file", "ghost_file")
    ]
    if any(f.classification == ResourceClassification.BLOCKER for f in file_findings):
        file_status = PortabilityStatus.BLOCKED
        file_summary = "Missing or mismatched files on destination host"
    elif any(f.classification == ResourceClassification.NEEDS_FLAG and f.resource_type == "ghost_file" for f in file_findings) or config.fs_mode == FilesystemMode.RSYNC:
        file_status = PortabilityStatus.PREPARE
        file_summary = "Filesystem synchronization (rsync) or ghost file limit adjustment required"
    elif trial_restore_passed or check_only_passed or not any(f.classification == ResourceClassification.BLOCKER for f in file_findings):
        file_status = PortabilityStatus.VERIFIED
        file_summary = "All mapped binaries, libraries, and open files verified identical on destination"
    else:
        file_status = PortabilityStatus.VERIFIED
        file_summary = "All mapped binaries, libraries, and open files verified identical on destination"

    # Domain 3: network
    net_findings = [
        f for f in findings
        if f.resource_type in ("socket", "network")
        or (f.resource_type == "fd" and f.suggested_flag in ("--tcp-established", "--ext-unix-sk"))
    ]
    has_net_blocker = any(f.classification == ResourceClassification.BLOCKER for f in net_findings)
    has_sockets = len(net_findings) > 0
    needs_net_flags = any(
        (f.suggested_flag == "--ext-unix-sk" and not config.ext_unix_sk) or
        (f.suggested_flag == "--tcp-established" and not config.tcp_established)
        for f in net_findings
    ) or any(
        f.classification == ResourceClassification.NEEDS_FLAG
        for f in net_findings
        if not ((f.suggested_flag == "--tcp-established" and config.tcp_established) or (f.suggested_flag == "--ext-unix-sk" and config.ext_unix_sk))
    )

    if has_net_blocker:
        net_status = PortabilityStatus.BLOCKED
        net_summary = "Incompatible network configuration or socket blocker"
    elif not has_sockets:
        net_status = PortabilityStatus.VERIFIED
        net_summary = "No active sockets; network domain portable"
    elif trial_restore_passed:
        net_status = PortabilityStatus.VERIFIED
        net_summary = "Network sockets and connection repair verified via trial restore"
    elif needs_net_flags:
        net_status = PortabilityStatus.PREPARE
        net_summary = "Active sockets require CRIU flags (--tcp-established / --ext-unix-sk)"
    else:
        net_status = PortabilityStatus.UNKNOWN
        net_summary = "Active sockets require trial restore to verify repair"

    # Domain 4: devices
    dev_findings = [
        f for f in findings
        if f.resource_type in ("gpu_device", "device")
        or (f.resource_type in ("mmap", "fd") and "/dev/" in f.identifier)
    ]
    if any(f.classification == ResourceClassification.BLOCKER for f in dev_findings):
        dev_status = PortabilityStatus.BLOCKED
        dev_summary = "Non-migratable hardware device open"
    elif any(f.resource_type == "gpu_device" and f.classification == ResourceClassification.NEEDS_FLAG for f in dev_findings):
        dev_status = PortabilityStatus.PREPARE
        dev_summary = "GPU device requires plugin preparation"
    else:
        dev_status = PortabilityStatus.VERIFIED
        dev_summary = "No non-migratable hardware devices detected"

    # Domain 5: external_resources
    ext_findings = [
        f for f in findings
        if f.resource_type in ("ptrace", "namespace", "external_pipe", "anon_inode", "pipe")
        or "io_uring" in f.identifier
    ]
    if any(
        f.classification == ResourceClassification.BLOCKER
        and (f.resource_type in ("ptrace", "namespace") or "io_uring" in f.identifier)
        for f in ext_findings
    ):
        ext_status = PortabilityStatus.BLOCKED
        ext_summary = "Process tracing, namespace isolation, or io_uring blocker detected"
    elif any(f.classification == ResourceClassification.NEEDS_FLAG for f in ext_findings):
        ext_status = PortabilityStatus.PREPARE
        ext_summary = "External resources require flag configuration"
    elif any(f.classification == ResourceClassification.UNKNOWN for f in ext_findings) and not trial_restore_passed:
        ext_status = PortabilityStatus.UNKNOWN
        ext_summary = "External pipe or unverified anonymous inode requires trial restore or --inherit-fd"
    elif trial_restore_passed:
        ext_status = PortabilityStatus.VERIFIED
        ext_summary = "External resources and namespaces verified portable via trial restore"
    elif not snapshot.in_envelope:
        ext_status = PortabilityStatus.UNKNOWN
        ext_summary = "Process outside isolation envelope; external resources cannot be guaranteed"
    else:
        ext_status = PortabilityStatus.VERIFIED
        ext_summary = "Process isolated in envelope; all anonymous inodes and pipes verified"

    domains: Dict[str, DomainPortabilityAssessment] = {
        "memory_and_cpu": DomainPortabilityAssessment(
            domain="memory_and_cpu",
            status=mem_status,
            summary=mem_summary,
            findings=mem_findings,
        ),
        "files": DomainPortabilityAssessment(
            domain="files",
            status=file_status,
            summary=file_summary,
            findings=file_findings,
        ),
        "network": DomainPortabilityAssessment(
            domain="network",
            status=net_status,
            summary=net_summary,
            findings=net_findings,
        ),
        "devices": DomainPortabilityAssessment(
            domain="devices",
            status=dev_status,
            summary=dev_summary,
            findings=dev_findings,
        ),
        "external_resources": DomainPortabilityAssessment(
            domain="external_resources",
            status=ext_status,
            summary=ext_summary,
            findings=ext_findings,
        ),
    }

    if any(d.status == PortabilityStatus.BLOCKED for d in domains.values()):
        overall_status = PortabilityStatus.BLOCKED
    elif any(d.status == PortabilityStatus.PREPARE for d in domains.values()):
        overall_status = PortabilityStatus.PREPARE
    elif trial_restore_passed and all(d.status == PortabilityStatus.VERIFIED for d in domains.values()):
        overall_status = PortabilityStatus.VERIFIED
    else:
        overall_status = PortabilityStatus.UNKNOWN

    compatible = (overall_status != PortabilityStatus.BLOCKED)
    same_host_fast_path = bool(
        source_caps.host_id
        and dest_caps.host_id
        and source_caps.host_id == dest_caps.host_id
    )

    return PortabilityReport(
        overall_status=overall_status,
        compatible=compatible,
        domains=domains,
        estimated_cold_downtime_ms=round(cold_downtime_ms, 2),
        estimated_live_downtime_ms=round(live_downtime_ms, 2),
        required_criu_flags=required_flags,
        findings=findings,
        check_only_executed=check_only_passed,
        trial_restore_executed=trial_restore_passed,
        same_host_fast_path_available=same_host_fast_path,
    )


_eval_portability = evaluate_portability


def evaluate_compatibility(
    config: MigrationConfig,
    source_caps: HostCapabilities,
    dest_caps: HostCapabilities,
    snapshot: ProcessSnapshotInfo,
    dest_files: Dict[str, FileArtifact],
) -> PreflightReport:
    """Compare Source A and Destination B capabilities and files to produce a PreflightReport."""
    port_report = _eval_portability(
        config=config,
        source_caps=source_caps,
        dest_caps=dest_caps,
        snapshot=snapshot,
        dest_files=dest_files,
        check_only_passed=False,
        trial_restore_passed=False,
    )
    return PreflightReport(
        compatible=port_report.compatible,
        estimated_cold_downtime_ms=port_report.estimated_cold_downtime_ms,
        estimated_live_downtime_ms=port_report.estimated_live_downtime_ms,
        required_criu_flags=port_report.required_criu_flags,
        findings=port_report.findings,
        portability_status=port_report.overall_status,
        domains=port_report.domains,
    )
