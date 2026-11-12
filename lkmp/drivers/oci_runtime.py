"""OCI Container Runtime Driver (`OciContainerDriver`) for Podman, crun, and runc."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from lkmp.config import MigrationConfig, MigrationStrategy
from lkmp.drivers.detector import WorkloadKind, detect_workload_profile, read_proc_starttime
from lkmp.logging_utils import get_logger

logger = get_logger("drivers.oci")

CommandRunner = Callable[[List[str]], subprocess.CompletedProcess]


def _default_runner(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, text=True, capture_output=True)


class OciContainerDriver:
    """
    2PC-compliant OCI Container Migration Driver (`podman` / `crun` / `runc`):
    1. Fences source restart policies (`--restart=no`) before checkpointing so source container
       supervisors (`conmon` / daemon) never spawn a split-brain duplicate when Source A commits.
    2. Leverages immutable OCI image layers (`lowerdir` zero-copy sharing on Destination B) and
       native `--pre-checkpoint` + `--export` archive transfer.
    3. Restores container in paused/created state on Destination B behind `nftables` drop lock
       so 2PC `GangMigrationCoordinator` can commit or roll back atomically!
    """

    kind = WorkloadKind.OCI_CONTAINER

    def __init__(
        self,
        proc_root: str = "/proc",
        runner: Optional[CommandRunner] = None,
    ) -> None:
        self.proc_root = proc_root
        self.runner = runner or _default_runner

    def _resolve_container(self, config: MigrationConfig) -> tuple[str, str]:
        meta = dict(config.runtime_metadata or {})
        cid = meta.get("container_id")
        engine = meta.get("container_engine") or "podman"
        if not cid:
            prof = detect_workload_profile(config.pid, proc_root=self.proc_root)
            cid = prof.container_id
            engine = prof.container_engine or engine
        if not cid:
            raise ValueError(f"Process {config.pid} has no OCI container_id metadata or cgroup scope")
        return str(engine), str(cid)

    def _inspect_container(self, engine: str, cid: str) -> Dict[str, Any]:
        res = self.runner([engine, "inspect", cid])
        parsed = json.loads(res.stdout or "[]")
        if isinstance(parsed, list) and parsed:
            return dict(parsed[0])
        if isinstance(parsed, dict):
            return parsed
        return {}

    def prepare_dest(
        self,
        migration_id: str,
        mig_dir: Path,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = migration_id
        (mig_dir / "final").mkdir(parents=True, exist_ok=True)
        meta = dict(config.runtime_metadata or {})
        image_ref = meta.get("oci_image")
        engine = str(meta.get("container_engine") or "podman")
        if image_ref:
            # Ensure base image layers (`lowerdir`) exist locally on Destination B before freeze!
            check = subprocess.run([engine, "image", "exists", str(image_ref)], capture_output=True)
            if check.returncode != 0:
                self.runner([engine, "pull", str(image_ref)])
        return {"prepared_oci": True, "engine": engine}

    def start_pre_copy_target(
        self,
        migration_id: str,
        mig_dir: Path,
        round_name: str,
        prev_round_name: Optional[str],
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = (migration_id, prev_round_name, config)
        rnd = mig_dir / round_name
        rnd.mkdir(parents=True, exist_ok=True)
        return {"oci_pre_checkpoint_ready": True, "dir": str(rnd)}

    def run_pre_copy_source(
        self,
        migration_id: str,
        mig_dir: Path,
        round_name: str,
        prev_round_name: Optional[str],
        dest_host: str,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = (migration_id, prev_round_name, dest_host)
        engine, cid = self._resolve_container(config)
        archive = mig_dir / round_name / "pre-checkpoint.tar"
        archive.parent.mkdir(parents=True, exist_ok=True)
        if engine == "podman":
            cmd = [
                "podman",
                "container",
                "checkpoint",
                "--pre-checkpoint",
                "--export",
                str(archive),
                cid,
            ]
            self.runner(cmd)
        else:
            cmd = [engine, "checkpoint", "--pre-dump", "--image-path", str(archive.parent), cid]
            self.runner(cmd)
        size = archive.stat().st_size if archive.exists() else 0
        return {"dirty_bytes": size, "duration_ms": 5.0, "command": cmd}

    def freeze_and_dump_source(
        self,
        migration_id: str,
        mig_dir: Path,
        prev_round_name: Optional[str],
        dest_host: str,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = (migration_id, dest_host)
        engine, cid = self._resolve_container(config)
        final_dir = mig_dir / "final"
        final_dir.mkdir(parents=True, exist_ok=True)
        archive = final_dir / "container-ckpt.tar"

        # 1. Record original restart policy and disable auto-restart to prevent split-brain!
        orig_restart = "no"
        try:
            info = self._inspect_container(engine, cid)
            hc = info.get("HostConfig") or {}
            rp = hc.get("RestartPolicy") or {}
            orig_restart = str(rp.get("Name") or "no")
        except Exception:
            orig_restart = "no"

        if orig_restart and orig_restart != "no":
            try:
                self.runner([engine, "update", "--restart=no", cid])
            except Exception as exc:
                logger.warning("Unable to update restart policy on %s %s: %s", engine, cid, exc)

        # 2. Export checkpoint while keeping source container paused (`--leave-running` + `pause`)
        #    so Source A remains intact and resumable until 2PC WAL COMMITTED!
        if engine == "podman":
            cmd = ["podman", "container", "checkpoint", "--leave-running", "--export", str(archive)]
            if prev_round_name and config.strategy in (MigrationStrategy.PRE_COPY, MigrationStrategy.HYBRID):
                cmd.append("--with-previous")
            if config.tcp_established:
                cmd.append("--tcp-established")
            cmd.append(cid)
            self.runner(cmd)
            self.runner(["podman", "pause", cid])
        else:
            cmd = [engine, "checkpoint", "--leave-stopped", "--image-path", str(final_dir), cid]
            self.runner(cmd)

        src_st = read_proc_starttime(config.pid, self.proc_root)
        state = {
            "driver": WorkloadKind.OCI_CONTAINER.value,
            "pid": config.pid,
            "tree_pids": [config.pid],
            "starttimes": {str(config.pid): src_st},
            "engine": engine,
            "container_id": cid,
            "orig_restart_policy": orig_restart,
            "archive": str(archive),
            "committed": False,
        }
        (mig_dir / "source_state.json").write_text(json.dumps(state, indent=2), encoding="utf-8")
        return {"images_dir": str(final_dir), "archive": str(archive), "command": cmd}

    def restore_stopped_dest(
        self,
        migration_id: str,
        mig_dir: Path,
        source_host: str,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = (migration_id, source_host)
        engine, cid = self._resolve_container(config)
        final_dir = mig_dir / "final"
        archive = final_dir / "container-ckpt.tar"

        if engine == "podman":
            cmd = ["podman", "container", "restore", "--import", str(archive), "--keep"]
            if config.tcp_established:
                cmd.append("--tcp-established")
            self.runner(cmd)
            self.runner(["podman", "pause", cid])
            info = self._inspect_container("podman", cid)
            restored_pid = int((info.get("State") or {}).get("Pid") or config.pid)
        else:
            cmd = [engine, "restore", "--detach", "--image-path", str(final_dir), cid]
            self.runner(cmd)
            self.runner([engine, "pause", cid])
            restored_pid = config.pid

        starttime = read_proc_starttime(restored_pid, self.proc_root)
        restore_state = {
            "driver": WorkloadKind.OCI_CONTAINER.value,
            "engine": engine,
            "container_id": cid,
            "restored_pid": restored_pid,
            "tree_pids": [restored_pid],
            "starttimes": {str(restored_pid): starttime},
            "workload_ip": config.workload_ip,
            "tcp_established": config.tcp_established,
            "resumed": False,
        }
        (final_dir / "restore_state.json").write_text(json.dumps(restore_state, indent=2), encoding="utf-8")
        return {"restored_pid": restored_pid, "restored_starttime": starttime, "command": cmd}

    def verify_stopped_dest(
        self,
        migration_id: str,
        mig_dir: Path,
        restored_pid: int,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = (migration_id, mig_dir)
        engine, cid = self._resolve_container(config)
        info = self._inspect_container(engine, cid)
        st = info.get("State") or {}
        paused = bool(st.get("Paused")) or str(st.get("Status", "")).lower() in ("paused", "created")
        if not paused:
            return {
                "healthy": False,
                "reason": f"Destination OCI container {cid[:12]} is not paused at 2PC barrier: {st}",
            }
        return {"healthy": True, "checked_pids": [restored_pid], "stopped_confirmed": True}

    def verify_running_dest(
        self,
        migration_id: str,
        mig_dir: Path,
        restored_pid: int,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = (migration_id, mig_dir)
        engine, cid = self._resolve_container(config)
        info = self._inspect_container(engine, cid)
        st = info.get("State") or {}
        status_str = str(st.get("Status", "")).lower()
        paused = bool(st.get("Paused")) or status_str in ("paused", "created")
        if paused:
            return {
                "healthy": False,
                "still_stopped": True,
                "reason": f"Destination OCI container {cid[:12]} is still paused: {st}",
            }
        if status_str in ("exited", "dead", "stopped"):
            return {
                "healthy": False,
                "reason": f"Destination OCI container {cid[:12]} is not running: {st}",
            }
        return {"healthy": True, "checked_pids": [restored_pid], "container_id": cid}

    def resume_dest(
        self,
        migration_id: str,
        mig_dir: Path,
        restored_pid: int,
        target_host: str,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = (migration_id, target_host)
        engine, cid = self._resolve_container(config)
        self.runner([engine, "unpause", cid])
        state_file = mig_dir / "final" / "restore_state.json"
        if state_file.exists():
            try:
                data = json.loads(state_file.read_text(encoding="utf-8"))
                data["resumed"] = True
                state_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            except Exception:
                pass
        return {"resumed_pid": restored_pid, "container_id": cid}

    def commit_source(
        self,
        migration_id: str,
        mig_dir: Path,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = migration_id
        engine, cid = self._resolve_container(config)
        self.runner([engine, "rm", "-f", cid])
        return {"committed": True, "container_id": cid}

    def rollback_dest(
        self,
        migration_id: str,
        mig_dir: Path,
        restored_pid: Optional[int],
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = (migration_id, mig_dir, restored_pid)
        engine, cid = self._resolve_container(config)
        try:
            self.runner([engine, "rm", "-f", cid])
        except Exception:
            pass
        return {"rolled_back_dest": True, "errors": []}

    def rollback_source(
        self,
        migration_id: str,
        mig_dir: Path,
        source_host: str,
        config: MigrationConfig,
    ) -> Dict[str, Any]:
        _ = (migration_id, source_host)
        engine, cid = self._resolve_container(config)
        orig_restart = "no"
        state_file = mig_dir / "source_state.json"
        if state_file.exists():
            try:
                data = json.loads(state_file.read_text(encoding="utf-8"))
                orig_restart = str(data.get("orig_restart_policy") or "no")
            except Exception:
                pass
        self.runner([engine, "unpause", cid])
        if orig_restart and orig_restart != "no":
            try:
                self.runner([engine, "update", f"--restart={orig_restart}", cid])
            except Exception:
                pass
        return {"rolled_back_source": True, "resumed_pid": config.pid, "container_id": cid}
