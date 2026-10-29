"""Configuration models and enums for LKMP."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class MigrationStrategy(str, Enum):
    """Memory transfer strategy during process migration."""

    AUTO = "auto"            # Auto-select based on RSS & /proc/<pid>/pagemap soft-dirty rate
    COLD = "cold"            # Stop -> dump -> transfer -> restore
    PRE_COPY = "pre-copy"    # Iterative pre-dump + final dump
    LAZY = "lazy"            # Post-copy demand paging via userfaultfd
    HYBRID = "hybrid"        # Iterative pre-dump followed by lazy post-copy


class FilesystemMode(str, Enum):
    """How workload filesystem state is shared or synchronized between hosts."""

    SHARED = "shared"        # Shared storage (NFS/Ceph) mounted at identical paths
    RSYNC = "rsync"          # Pre-sync before migration + final delta while frozen


class IpMobilityMode(str, Enum):
    """How the workload's IP address moves from Source A to Destination B."""

    NONE = "none"            # Do not move IP (e.g., clients reconnect to new host)
    GARP = "garp"            # L2 Gratuitous ARP (IPv4) / Unsolicited NA (IPv6)
    BGP = "bgp"              # L3 BGP /32 route announce on B and withdraw on A
    CLOUD = "cloud"          # Custom cloud secondary-IP reassignment webhook/command


class GpuPlugin(str, Enum):
    """Optional GPU checkpoint/restore integration."""

    NONE = "none"
    AMDGPU = "amdgpu"                # CRIU native amdgpu_plugin
    CUDA = "cuda-checkpoint"         # NVIDIA cuda-checkpoint utility


@dataclass
class TlsConfig:
    """TLS / mTLS configuration for controller-agent and CRIU page-server channels."""

    enabled: bool = True
    ca_cert: Optional[str] = None
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    no_verify: bool = False


@dataclass
class EnvelopeConfig:
    """Configuration for the isolated migration envelope (`lkmp run`)."""

    workload_id: str
    command: List[str]
    rootfs: Optional[str] = None
    bind_mounts: List[str] = field(default_factory=list)
    ip_address: Optional[str] = None
    net_interface: str = "eth0"
    veth_host: Optional[str] = None
    cgroup_root: str = "/sys/fs/cgroup/lkmp"
    hostname: Optional[str] = None
    use_time_ns: bool = True
    state_dir: str = "/var/lib/lkmp/envelopes"


@dataclass
class MigrationConfig:
    """Full configuration for a single process tree migration."""

    pid: int
    source_addr: str
    dest_addr: str
    workload_id: Optional[str] = None
    strategy: MigrationStrategy = MigrationStrategy.PRE_COPY
    fs_mode: FilesystemMode = FilesystemMode.SHARED
    writable_paths: List[str] = field(default_factory=list)
    ip_mobility: IpMobilityMode = IpMobilityMode.GARP
    workload_ip: Optional[str] = None
    net_interface: str = "eth0"
    bgp_daemon_cmd: Optional[str] = None
    cloud_move_cmd: Optional[str] = None
    tcp_established: bool = True
    unsafe_bare: bool = False
    gpu_plugin: GpuPlugin = GpuPlugin.NONE

    # Pre-copy convergence tuning
    max_precopy_iterations: int = 8
    target_downtime_ms: int = 200
    min_shrink_ratio: float = 0.10
    estimated_bandwidth_mbps: float = 1000.0

    # CRIU & storage settings
    work_dir: str = "/var/lib/lkmp/migrations"
    page_server_port: int = 27000
    lazy_pages_port: int = 27001
    ghost_limit_bytes: int = 64 * 1024 * 1024  # 64 MiB
    ext_unix_sk: bool = False
    external_mounts: List[str] = field(default_factory=list)

    # Verification & security
    health_check_cmd: Optional[str] = None
    health_check_timeout_sec: float = 5.0
    wipe_images_on_commit: bool = True
    tls: TlsConfig = field(default_factory=TlsConfig)
