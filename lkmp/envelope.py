"""Migration Envelope (`lkmp run`): namespace isolation and cgroup v2 management."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import asdict
from pathlib import Path
from typing import Callable, List, Optional

from lkmp.config import EnvelopeConfig


CommandRunner = Callable[[List[str]], subprocess.CompletedProcess]


def _default_runner(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, text=True, capture_output=True)


class EnvelopeManager:
    """Manages isolated Linux namespaces and cgroup v2 envelopes for migratable processes."""

    def __init__(
        self,
        state_dir: str = "/var/lib/lkmp/envelopes",
        cgroup_root: str = "/sys/fs/cgroup/lkmp",
        runner: Optional[CommandRunner] = None,
    ) -> None:
        self.state_dir = Path(state_dir)
        self.cgroup_root = Path(cgroup_root)
        self.runner = runner or _default_runner

    def build_unshare_command(self, config: EnvelopeConfig) -> List[str]:
        """Build the `unshare` command line for launching a process in a migration envelope."""
        cmd: List[str] = [
            "unshare",
            "--pid",
            "--fork",
            "--mount-proc",
            "--net",
            "--mount",
            "--ipc",
            "--uts",
        ]
        if config.use_time_ns:
            cmd.append("--time")
        if config.rootfs:
            cmd.extend(["--root", config.rootfs])
        cmd.append("--")
        cmd.extend(config.command)
        return cmd

    def setup_cgroup(self, workload_id: str, pid: Optional[int] = None) -> Path:
        """Create a dedicated cgroup v2 directory for the workload and optionally attach a PID."""
        cg_path = self.cgroup_root / workload_id
        cg_path.mkdir(parents=True, exist_ok=True)
        if pid is not None:
            procs_file = cg_path / "cgroup.procs"
            procs_file.write_text(f"{pid}\n", encoding="utf-8")
        return cg_path

    def freeze_cgroup(self, workload_id: str) -> None:
        """Atomically freeze all processes in the workload's cgroup v2 (`cgroup.freeze = 1`)."""
        freeze_file = self.cgroup_root / workload_id / "cgroup.freeze"
        if freeze_file.parent.exists():
            freeze_file.write_text("1\n", encoding="utf-8")

    def unfreeze_cgroup(self, workload_id: str) -> None:
        """Atomically thaw all processes in the workload's cgroup v2 (`cgroup.freeze = 0`)."""
        freeze_file = self.cgroup_root / workload_id / "cgroup.freeze"
        if freeze_file.parent.exists():
            freeze_file.write_text("0\n", encoding="utf-8")

    def is_cgroup_frozen(self, workload_id: str) -> bool:
        """Return True if the workload cgroup is currently frozen."""
        freeze_file = self.cgroup_root / workload_id / "cgroup.freeze"
        if not freeze_file.exists():
            return False
        return freeze_file.read_text(encoding="utf-8").strip() == "1"

    def configure_netns_ip(self, pid: int, ip_cidr: str, interface: str = "eth0") -> None:
        """Assign the dedicated migratable IP inside the workload's network namespace."""
        self.runner(["nsenter", "-t", str(pid), "-n", "ip", "link", "set", "lo", "up"])
        self.runner(["nsenter", "-t", str(pid), "-n", "ip", "addr", "add", ip_cidr, "dev", interface])
        self.runner(["nsenter", "-t", str(pid), "-n", "ip", "link", "set", interface, "up"])

    def save_envelope_metadata(self, config: EnvelopeConfig, host_pid: int) -> Path:
        """Persist envelope metadata so `lkmp migrate` can look up workload settings by ID or PID."""
        self.state_dir.mkdir(parents=True, exist_ok=True)
        meta_path = self.state_dir / f"{config.workload_id}.json"
        payload = asdict(config)
        payload["host_pid"] = host_pid
        meta_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return meta_path

    def load_envelope_metadata(self, workload_id: str) -> dict:
        """Load persisted metadata for an envelope."""
        meta_path = self.state_dir / f"{workload_id}.json"
        return json.loads(meta_path.read_text(encoding="utf-8"))

    def launch(self, config: EnvelopeConfig) -> int:
        """Launch a process inside its migration envelope, attach cgroup v2, and record metadata."""
        unshare_cmd = self.build_unshare_command(config)
        proc = subprocess.Popen(
            unshare_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        pid = proc.pid
        try:
            if os.path.exists(str(self.cgroup_root.parent)):
                self.setup_cgroup(config.workload_id, pid=pid)
        except OSError:
            # Non-root or cgroupfs not mounted in test environments
            pass
        if config.ip_address:
            self.configure_netns_ip(pid, config.ip_address, config.net_interface)
        self.save_envelope_metadata(config, pid)
        return pid
