"""Automatic process-tree fingerprinter and porting advisor for VMs, MicroVMs, and OCI containers."""

from __future__ import annotations

import os
import re
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class WorkloadKind(str, Enum):
    """Runtime engine category for a target process tree."""

    AUTO = "auto"
    POSIX_TREE = "posix"
    QEMU_VM = "qemu"
    OCI_CONTAINER = "oci"
    MICROVM = "microvm"


def read_proc_starttime(pid: int, proc_root: str = "/proc") -> Optional[int]:
    """Read field 22 (`starttime`) from `<proc_root>/<pid>/stat`, returning `None` if unavailable."""
    stat_file = Path(proc_root) / str(pid) / "stat"
    try:
        content = stat_file.read_text(encoding="utf-8", errors="ignore")
        rparen = content.rfind(")")
        if rparen != -1:
            fields = content[rparen + 1 :].strip().split()
            if len(fields) >= 20:
                return int(fields[19])
    except Exception:
        pass
    return None


_OCI_CGROUP_PATTERNS = (
    ("podman", re.compile(r"libpod-([0-9a-fA-F]{12,64})\.scope")),
    ("podman", re.compile(r"libpod-conmon-([0-9a-fA-F]{12,64})\.scope")),
    ("docker", re.compile(r"docker-([0-9a-fA-F]{12,64})\.scope")),
    ("docker", re.compile(r"/docker/([0-9a-fA-F]{12,64})(?:/|$)")),
    ("containerd", re.compile(r"cri-containerd-([0-9a-fA-F]{12,64})\.scope")),
    ("containerd", re.compile(r"/containerd/([0-9a-fA-F]{12,64})(?:/|$)")),
)


@dataclass
class WorkloadProfile:
    """Detected runtime identity, control handles, and porting diagnostics for a PID."""

    pid: int
    kind: WorkloadKind = WorkloadKind.POSIX_TREE
    subkind: Optional[str] = None  # e.g., "qemu-kvm", "qemu-tcg", "podman", "firecracker", "cloud-hypervisor"
    exe_path: Optional[str] = None
    comm: Optional[str] = None
    cmdline: List[str] = field(default_factory=list)
    cgroup_path: Optional[str] = None
    control_socket: Optional[str] = None
    container_id: Optional[str] = None
    container_engine: Optional[str] = None
    overlay_upperdir: Optional[str] = None
    overlay_lowerdir: Optional[str] = None
    uses_kvm: bool = False
    uses_vhost: bool = False
    uses_vfio: bool = False
    uses_io_uring: bool = False
    cpu_model: Optional[str] = None
    memory_backend: Optional[str] = None  # "memfd-shared", "memfd", "file", "anon-ram"
    disk_paths: List[str] = field(default_factory=list)
    migratable_ready: bool = True
    blockers: List[str] = field(default_factory=list)
    advisories: List[str] = field(default_factory=list)
    recommended_flags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["kind"] = self.kind.value
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WorkloadProfile:
        d = dict(data)
        d["kind"] = WorkloadKind(d.get("kind", "posix"))
        return cls(**d)


def _read_cmdline(pid_dir: Path) -> List[str]:
    cmdline_file = pid_dir / "cmdline"
    if not cmdline_file.exists():
        return []
    try:
        raw = cmdline_file.read_bytes()
        if not raw:
            return []
        parts = [p.decode("utf-8", errors="replace") for p in raw.split(b"\x00")]
        while parts and parts[-1] == "":
            parts.pop()
        return parts
    except OSError:
        return []


def _read_unix_socket_inode_map(pid_dir: Path, proc_root: Path) -> Dict[str, str]:
    """Map `socket:[<inode>]` -> UNIX filesystem path from `<proc>/<pid>/net/unix` or `<proc>/net/unix`."""
    mapping: Dict[str, str] = {}
    for candidate in (pid_dir / "net" / "unix", proc_root / "net" / "unix"):
        if not candidate.exists():
            continue
        try:
            lines = candidate.read_text(encoding="utf-8", errors="ignore").splitlines()
            for line in lines[1:]:
                cols = line.split(None, 7)
                if len(cols) >= 8:
                    inode = cols[6].strip()
                    sock_path = cols[7].strip().lstrip("@")
                    if inode.isdigit() and sock_path.startswith("/"):
                        mapping[f"socket:[{inode}]"] = sock_path
            if mapping:
                break
        except OSError:
            continue
    return mapping


def _parse_qemu_args(
    cmdline: List[str],
    open_unix_paths: List[str],
) -> Dict[str, Any]:
    """Extract QMP control endpoint, CPU model, memory backend, and virtual disk paths from QEMU argv."""
    qmp_endpoint: Optional[str] = None
    cpu_model: Optional[str] = None
    memory_backend = "anon-ram"
    chardevs: Dict[str, str] = {}
    mon_chardevs: Set[str] = set()
    disks: List[str] = []

    i = 0
    while i < len(cmdline):
        arg = cmdline[i]
        nxt = cmdline[i + 1] if i + 1 < len(cmdline) else ""

        if arg in ("-qmp", "-qmp-pretty") and nxt:
            spec = nxt.split(",", 1)[0].strip()
            if spec.startswith("unix:"):
                qmp_endpoint = spec[5:]
            elif spec.startswith("tcp:"):
                qmp_endpoint = spec
            i += 2
            continue

        if arg == "-chardev" and nxt:
            kv = dict(
                item.split("=", 1)
                for item in nxt.split(",")
                if "=" in item
            )
            cid = kv.get("id")
            if cid and "path" in kv:
                chardevs[cid] = kv["path"]
            elif cid and "host" in kv and "port" in kv:
                chardevs[cid] = f"tcp:{kv['host']}:{kv['port']}"
            i += 2
            continue

        if arg == "-mon" and nxt:
            kv = dict(
                item.split("=", 1)
                for item in nxt.split(",")
                if "=" in item
            )
            if kv.get("mode") == "control" and "chardev" in kv:
                mon_chardevs.add(kv["chardev"])
            elif "chardev" in kv and ("qmp" in kv["chardev"].lower()):
                mon_chardevs.add(kv["chardev"])
            i += 2
            continue

        if arg == "-cpu" and nxt:
            cpu_model = nxt.strip()
            i += 2
            continue

        if arg == "-object" and nxt:
            if nxt.startswith("memory-backend-memfd"):
                memory_backend = "memfd-shared" if "share=on" in nxt or "share=true" in nxt else "memfd"
            elif nxt.startswith("memory-backend-file"):
                memory_backend = "file"
            i += 2
            continue

        if arg in ("-hda", "-hdb", "-hdc", "-hdd", "-cdrom") and nxt and not nxt.startswith("-"):
            disks.append(nxt)
            i += 2
            continue

        if arg in ("-drive", "-blockdev") and nxt:
            for item in nxt.split(","):
                if item.startswith("file=") or item.startswith("filename="):
                    val = item.split("=", 1)[1].strip()
                    if val and not val.startswith(("nbd:", "rbd:", "json:")):
                        disks.append(val)
            i += 2
            continue

        i += 1

    if qmp_endpoint is None:
        for mcid in mon_chardevs:
            if mcid in chardevs:
                qmp_endpoint = chardevs[mcid]
                break
    if qmp_endpoint is None:
        for cid, path in chardevs.items():
            if "qmp" in cid.lower():
                qmp_endpoint = path
                break
    if qmp_endpoint is None:
        for upath in open_unix_paths:
            if "qmp" in upath.lower():
                qmp_endpoint = upath
                break

    return {
        "qmp_endpoint": qmp_endpoint,
        "cpu_model": cpu_model,
        "memory_backend": memory_backend,
        "disks": disks,
    }


def _parse_overlay_mountinfo(pid_dir: Path) -> tuple[Optional[str], Optional[str]]:
    """Extract root `overlay` `upperdir` and `lowerdir` from `<proc>/<pid>/mountinfo`."""
    mi_file = pid_dir / "mountinfo"
    if not mi_file.exists():
        return None, None
    try:
        for line in mi_file.read_text(encoding="utf-8", errors="ignore").splitlines():
            if " - overlay " not in line:
                continue
            parts = line.split(" - ", 1)
            if len(parts) != 2:
                continue
            left_cols = parts[0].split()
            mount_point = left_cols[4] if len(left_cols) >= 5 else ""
            right_cols = parts[1].split()
            super_opts = right_cols[2] if len(right_cols) >= 3 else ""
            upper: Optional[str] = None
            lower: Optional[str] = None
            for opt in super_opts.split(","):
                if opt.startswith("upperdir="):
                    upper = opt.split("=", 1)[1]
                elif opt.startswith("lowerdir="):
                    lower = opt.split("=", 1)[1]
            if mount_point == "/" or upper is not None:
                return upper, lower
    except OSError:
        pass
    return None, None


def detect_workload_profile(pid: int, proc_root: str = "/proc") -> WorkloadProfile:
    """
    Inspect `/proc/<pid>` to classify whether `pid` is a QEMU VM, MicroVM (Firecracker /
    Cloud-Hypervisor), OCI Container (`podman` / `docker` / `containerd`), or POSIX process tree.
    """
    proc_base = Path(proc_root)
    pid_dir = proc_base / str(pid)
    if not pid_dir.exists():
        raise FileNotFoundError(f"Process {pid} does not exist in {proc_root}")

    cmdline = _read_cmdline(pid_dir)
    exe_path: Optional[str] = None
    exe_link = pid_dir / "exe"
    try:
        if exe_link.exists() or exe_link.is_symlink():
            exe_path = os.readlink(exe_link)
            if exe_path.endswith(" (deleted)"):
                exe_path = exe_path[:-10]
    except OSError:
        exe_path = None

    comm: Optional[str] = None
    comm_file = pid_dir / "comm"
    if comm_file.exists():
        try:
            comm = comm_file.read_text(encoding="utf-8", errors="ignore").strip()
        except OSError:
            comm = None

    cgroup_path: Optional[str] = None
    cg_file = pid_dir / "cgroup"
    if cg_file.exists():
        try:
            for line in cg_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if "::" in line:
                    cgroup_path = line.split("::", 1)[1].strip()
                    if cgroup_path:
                        break
        except OSError:
            pass

    fd_targets: List[str] = []
    fd_dir = pid_dir / "fd"
    if fd_dir.exists():
        try:
            for entry in fd_dir.iterdir():
                try:
                    fd_targets.append(os.readlink(entry))
                except OSError:
                    continue
        except OSError:
            pass

    unix_map = _read_unix_socket_inode_map(pid_dir, proc_base)
    open_unix_paths = [unix_map[t] for t in fd_targets if t in unix_map]

    uses_kvm = any(
        t == "/dev/kvm" or "kvm-vm" in t or "kvm-vcpu" in t
        for t in fd_targets
    )
    uses_vhost = any(t.startswith("/dev/vhost") for t in fd_targets)
    uses_vfio = any(t.startswith("/dev/vfio/") and t != "/dev/vfio/vfio" for t in fd_targets)
    uses_io_uring = any("io_uring" in t for t in fd_targets)

    arg0_base = Path(cmdline[0]).name.lower() if cmdline else ""
    exe_base = Path(exe_path).name.lower() if exe_path else ""
    comm_lower = (comm or "").lower()
    binary_names = {arg0_base, exe_base, comm_lower} - {""}

    # 1. Check QEMU hypervisor (`qemu-system-*` or `qemu-kvm` / `kvm`)
    is_qemu = any(
        b.startswith("qemu-system-") or b in ("qemu-kvm", "kvm")
        for b in binary_names
    )
    if is_qemu:
        qinfo = _parse_qemu_args(cmdline, open_unix_paths)
        qmp_sock = qinfo["qmp_endpoint"]
        cpu_model = qinfo["cpu_model"]
        mem_backend = qinfo["memory_backend"]
        disks = qinfo["disks"]
        blockers: List[str] = []
        advisories: List[str] = []
        rec_flags: List[str] = ["--workload-kind qemu"]

        if not qmp_sock:
            blockers.append(
                "QEMU process has no QMP control socket; add `-qmp unix:/run/lkmp/<id>.qmp,server=on,wait=off`"
            )
        if uses_vfio and not any("failover=on" in a for a in cmdline):
            blockers.append(
                "Direct VFIO PCIe passthrough device open without virtio-net `failover=on`; "
                "configure net_failover or migratable VFIOv2"
            )
        if cpu_model and cpu_model.split(",")[0] == "host":
            advisories.append(
                "QEMU launched with `-cpu host`; cross-host live migration requires identical CPU stepping. "
                "Prefer a named baseline CPU model (e.g. `-cpu max,migratable=on` or `-cpu Cascadelake-Server`)."
            )
        if mem_backend != "memfd-shared":
            advisories.append(
                "Use `-object memory-backend-memfd,id=mem0,size=...,share=on` to unlock zero-copy "
                "`MSG_ZEROCOPY` (`zero-copy-send`) and `vhost-user` DMA."
            )
        if disks:
            advisories.append(
                f"Detected {len(disks)} local disk image(s); use `--fs-mode shared` on NFS/Ceph or "
                "enable QMP NBD blockdev-mirror for zero-downtime local storage migration."
            )

        return WorkloadProfile(
            pid=pid,
            kind=WorkloadKind.QEMU_VM,
            subkind="qemu-kvm" if uses_kvm else "qemu-tcg",
            exe_path=exe_path or (cmdline[0] if cmdline else None),
            comm=comm,
            cmdline=cmdline,
            cgroup_path=cgroup_path,
            control_socket=qmp_sock,
            uses_kvm=uses_kvm,
            uses_vhost=uses_vhost,
            uses_vfio=uses_vfio,
            uses_io_uring=uses_io_uring,
            cpu_model=cpu_model,
            memory_backend=mem_backend,
            disk_paths=disks,
            migratable_ready=len(blockers) == 0,
            blockers=blockers,
            advisories=advisories,
            recommended_flags=rec_flags,
        )

    # 2. Check MicroVM (`firecracker` or `cloud-hypervisor`)
    is_fc = any("firecracker" in b for b in binary_names)
    is_ch = any("cloud-hypervisor" in b for b in binary_names)
    if is_fc or is_ch:
        subkind = "firecracker" if is_fc else "cloud-hypervisor"
        api_sock: Optional[str] = None
        for idx, tok in enumerate(cmdline):
            if tok in ("--api-sock", "--http-socket") and idx + 1 < len(cmdline):
                api_sock = cmdline[idx + 1]
                break
            if tok.startswith("--api-sock="):
                api_sock = tok.split("=", 1)[1]
                break
        if api_sock is None and open_unix_paths:
            api_sock = open_unix_paths[0]

        blockers = []
        advisories = []
        if not api_sock:
            blockers.append(f"{subkind} has no API UNIX socket (`--api-sock`); cannot issue live snapshot/migration RPCs")
        if uses_vfio:
            blockers.append(f"{subkind} holds open VFIO passthrough device")
        if is_fc:
            advisories.append(
                "Ensure `/machine-config` has `track_dirty_pages: true` for sub-15ms incremental Diff snapshots + CoW reflink."
            )
        return WorkloadProfile(
            pid=pid,
            kind=WorkloadKind.MICROVM,
            subkind=subkind,
            exe_path=exe_path or (cmdline[0] if cmdline else None),
            comm=comm,
            cmdline=cmdline,
            cgroup_path=cgroup_path,
            control_socket=api_sock,
            uses_kvm=uses_kvm,
            uses_vhost=uses_vhost,
            uses_vfio=uses_vfio,
            uses_io_uring=uses_io_uring,
            migratable_ready=len(blockers) == 0,
            blockers=blockers,
            advisories=advisories,
            recommended_flags=["--workload-kind microvm"],
        )

    # 3. Check OCI Container (`podman` / `docker` / `containerd`)
    if cgroup_path:
        for engine, pat in _OCI_CGROUP_PATTERNS:
            m = pat.search(cgroup_path)
            if m:
                cid = m.group(1)
                upper, lower = _parse_overlay_mountinfo(pid_dir)
                blockers = []
                advisories = [
                    f"Detected {engine} OCI container `{cid[:12]}`; LKMP `OciContainerDriver` will fence "
                    "restart policies (`--restart=no`), pre-checkpoint via runtime, and sync only overlay `upperdir`."
                ]
                if uses_io_uring:
                    blockers.append("Container process holds open kernel `io_uring` ring")
                return WorkloadProfile(
                    pid=pid,
                    kind=WorkloadKind.OCI_CONTAINER,
                    subkind=engine,
                    exe_path=exe_path,
                    comm=comm,
                    cmdline=cmdline,
                    cgroup_path=cgroup_path,
                    container_id=cid,
                    container_engine=engine,
                    overlay_upperdir=upper,
                    overlay_lowerdir=lower,
                    uses_kvm=uses_kvm,
                    uses_vhost=uses_vhost,
                    uses_vfio=uses_vfio,
                    uses_io_uring=uses_io_uring,
                    migratable_ready=len(blockers) == 0,
                    blockers=blockers,
                    advisories=advisories,
                    recommended_flags=["--workload-kind oci"],
                )

    # 4. Default: Native POSIX process tree (`CriuDriver`)
    in_lkmp_env = bool(cgroup_path and "/lkmp/" in cgroup_path)
    blockers = []
    advisories = []
    rec_flags = ["--tmpfs-staging"]
    if uses_kvm:
        blockers.append("Raw `/dev/kvm` open on non-QEMU/MicroVM process; CRIU cannot dump kernel KVM anon_inodes")
    if uses_io_uring:
        blockers.append("Process holds open `io_uring` fd; disable io_uring or use standard epoll/AIO")
    if not in_lkmp_env:
        advisories.append(
            "Process is outside an `lkmp run` namespace envelope; launch via `lkmp run --id <name> -- ...` "
            "for isolated PID/net/time namespaces, or pass `--unsafe-bare`."
        )
        rec_flags.append("--unsafe-bare")

    return WorkloadProfile(
        pid=pid,
        kind=WorkloadKind.POSIX_TREE,
        subkind="lkmp-envelope" if in_lkmp_env else "posix-bare",
        exe_path=exe_path,
        comm=comm,
        cmdline=cmdline,
        cgroup_path=cgroup_path,
        uses_kvm=uses_kvm,
        uses_vhost=uses_vhost,
        uses_vfio=uses_vfio,
        uses_io_uring=uses_io_uring,
        migratable_ready=len(blockers) == 0,
        blockers=blockers,
        advisories=advisories,
        recommended_flags=rec_flags,
    )


def diagnose_workload_porting(pid: int, proc_root: str = "/proc") -> Dict[str, Any]:
    """Produce a structured `lkmp doctor` porting diagnostic and launch/migration recipe."""
    profile = detect_workload_profile(pid, proc_root=proc_root)
    prof_dict = profile.to_dict()
    data = dict(prof_dict)
    data["profile"] = prof_dict
    data["ready"] = profile.migratable_ready
    data["warnings"] = list(profile.advisories)
    data["recommended_launch_flags"] = list(profile.recommended_flags)

    if profile.kind == WorkloadKind.QEMU_VM:
        data["driver_key"] = "qemu"
        data["recommended_driver"] = "QemuQmpDriver (QMP multifd + zero-copy-send + pause-before-switchover 2PC)"
        data["zero_copy_capable"] = profile.memory_backend == "memfd-shared" and profile.migratable_ready
    elif profile.kind == WorkloadKind.OCI_CONTAINER:
        data["driver_key"] = "oci"
        data["recommended_driver"] = f"OciContainerDriver ({profile.container_engine} native checkpoint/restore)"
        data["zero_copy_capable"] = bool(profile.overlay_lowerdir) and profile.migratable_ready
    elif profile.kind == WorkloadKind.MICROVM:
        data["driver_key"] = "microvm"
        data["recommended_driver"] = f"MicroVmDriver ({profile.subkind} API live snapshot/migration)"
        data["zero_copy_capable"] = profile.migratable_ready
    else:
        data["driver_key"] = "criu"
        data["recommended_driver"] = "CriuDriver (CRIU iterative page-server + tmpfs zero-disk staging)"
        data["zero_copy_capable"] = profile.migratable_ready
    return data
