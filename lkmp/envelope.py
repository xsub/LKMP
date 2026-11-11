"""Migration Envelope (`lkmp run`): namespace isolation and cgroup v2 management."""

from __future__ import annotations

import json
import os
import subprocess
import time
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
        if config.hostname or config.bind_mounts:
            import shlex

            setup_steps: List[str] = []
            for bm in config.bind_mounts:
                if ":" not in bm:
                    raise ValueError(f"Invalid bind_mount specification {bm!r}; expected 'src:dst'")
                src_m, dst_m = bm.split(":", 1)
                setup_steps.append(f"mkdir -p {shlex.quote(dst_m)} && mount --bind {shlex.quote(src_m)} {shlex.quote(dst_m)}")
            if config.hostname:
                setup_steps.append(f"hostname {shlex.quote(config.hostname)}")
            exec_cmd = " ".join(shlex.quote(arg) for arg in config.command)
            setup_steps.append(f"exec {exec_cmd}")
            cmd.extend(["/bin/sh", "-c", " && ".join(setup_steps)])
        else:
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

    def freeze_cgroup(self, workload_id: str, timeout_sec: float = 5.0) -> Optional[Path]:
        """Atomically freeze all processes in the workload's cgroup v2 (`cgroup.freeze = 1`)."""
        cg_dir = self.cgroup_root / workload_id
        freeze_file = cg_dir / "cgroup.freeze"
        if not freeze_file.parent.exists():
            return None
        freeze_file.write_text("1\n", encoding="utf-8")
        events_file = cg_dir / "cgroup.events"
        if events_file.exists():
            deadline = time.monotonic() + timeout_sec
            while time.monotonic() < deadline:
                try:
                    for line in events_file.read_text(encoding="utf-8").splitlines():
                        if line.strip() == "frozen 1":
                            return cg_dir
                except OSError:
                    pass
                time.sleep(0.01)
            raise TimeoutError(f"cgroup v2 for workload {workload_id} did not freeze within {timeout_sec}s")
        return cg_dir if freeze_file.exists() else None

    def unfreeze_cgroup(self, workload_id: str, timeout_sec: float = 5.0) -> None:
        """Atomically thaw all processes in the workload's cgroup v2 (`cgroup.freeze = 0`)."""
        cg_dir = self.cgroup_root / workload_id
        freeze_file = cg_dir / "cgroup.freeze"
        if not freeze_file.parent.exists():
            return
        freeze_file.write_text("0\n", encoding="utf-8")
        events_file = cg_dir / "cgroup.events"
        if events_file.exists():
            deadline = time.monotonic() + timeout_sec
            while time.monotonic() < deadline:
                try:
                    for line in events_file.read_text(encoding="utf-8").splitlines():
                        if line.strip() == "frozen 0":
                            return
                except OSError:
                    pass
                time.sleep(0.01)
            raise TimeoutError(f"cgroup v2 for workload {workload_id} did not unfreeze within {timeout_sec}s")

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

    def list_envelopes(self) -> List[dict]:
        """List all persisted workload envelopes sorted by `workload_id`."""
        if not self.state_dir.exists():
            return []
        items: List[dict] = []
        for meta_file in sorted(self.state_dir.glob("*.json")):
            try:
                items.append(json.loads(meta_file.read_text(encoding="utf-8")))
            except Exception:
                continue
        return items

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
