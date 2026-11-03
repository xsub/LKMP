"""Per-migration network locking (nftables) and idempotent IP mobility drivers."""

from __future__ import annotations

import ipaddress
import os
import re
import shlex
import socket
import subprocess
from pathlib import Path
from typing import Callable, List, Optional

from lkmp.config import IpMobilityMode, MigrationConfig

SYS_PIDFD_GETFD: int = 438
SOL_TCP_REPAIR: int = getattr(socket, "TCP_REPAIR", 19)


def set_pid_tcp_repair(pid: int, enable: bool) -> int:
    """
    Toggle Linux kernel TCP_REPAIR (1 = ON, 0 = OFF) on all open TCP sockets of `pid`
    via `pidfd_open` + `pidfd_getfd`.
    - `enable=True` before SIGKILL on an aborted destination prevents kernel FIN/RST emission.
    - `enable=False` before SIGCONT on a `--leave-stopped` source clears the TCP_REPAIR state
      left behind by `criu dump --tcp-established --leave-stopped`.
    Returns the number of sockets updated.
    """
    if not hasattr(os, "pidfd_open"):
        return 0
    try:
        import ctypes

        libc = ctypes.CDLL(None, use_errno=True)
        pfd = os.pidfd_open(pid, 0)
    except Exception:
        return 0

    updated = 0
    val = 1 if enable else 0
    try:
        fd_dir = Path(f"/proc/{pid}/fd")
        if not fd_dir.exists():
            return 0
        for entry in list(fd_dir.iterdir()):
            if not entry.name.isdigit():
                continue
            try:
                target = os.readlink(entry)
            except OSError:
                continue
            if not target.startswith("socket:["):
                continue
            sfd = int(libc.syscall(SYS_PIDFD_GETFD, pfd, int(entry.name), 0))
            if sfd < 0:
                continue
            try:
                sock = socket.socket(fileno=sfd)
                try:
                    sock.setsockopt(socket.SOL_TCP, SOL_TCP_REPAIR, val)
                    updated += 1
                except OSError:
                    pass
                sock.close()
            except Exception:
                try:
                    os.close(sfd)
                except OSError:
                    pass
    finally:
        try:
            os.close(pfd)
        except OSError:
            pass
    return updated


CommandRunner = Callable[[List[str]], subprocess.CompletedProcess]


def _default_runner(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, text=True, capture_output=True)


class NetworkMobilityManager:
    """
    Manages per-migration nftables TCP packet drop locks and idempotent IP mobility
    across Source A and Destination B.
    """

    NFT_TABLE_PREFIX = "lkmp_lock"

    def __init__(self, runner: Optional[CommandRunner] = None) -> None:
        self.runner = runner or _default_runner

    @staticmethod
    def _strip_cidr(ip_str: str) -> str:
        return ip_str.split("/", 1)[0]

    @staticmethod
    def _ensure_cidr(ip_str: str) -> str:
        if "/" in ip_str:
            return ip_str
        addr = ipaddress.ip_address(ip_str)
        return f"{ip_str}/128" if addr.version == 6 else f"{ip_str}/32"

    @classmethod
    def table_name_for(cls, workload_ip: str, migration_id: Optional[str] = None) -> str:
        """
        Build a per-migration / per-IP nftables table name so concurrent migrations on the
        same host never overwrite or delete each other's packet locks.
        """
        bare_ip = cls._strip_cidr(workload_ip)
        safe_ip = re.sub(r"[^A-Za-z0-9_]", "_", bare_ip)
        if migration_id:
            safe_id = re.sub(r"[^A-Za-z0-9_]", "_", migration_id)[:24]
            return f"{cls.NFT_TABLE_PREFIX}_{safe_id}_{safe_ip}"
        return f"{cls.NFT_TABLE_PREFIX}_{safe_ip}"

    @staticmethod
    def tunnel_dev_for(migration_id: Optional[str] = None) -> str:
        """Build a per-migration Linux tunnel interface name (<= 15 chars, IFNAMSIZ)."""
        if migration_id:
            suffix = re.sub(r"[^A-Za-z0-9]", "", migration_id)[-8:]
            return f"lkmp{suffix}"
        return "lkmp0"

    def lock_network(
        self,
        workload_ip: Optional[str],
        migration_id: Optional[str] = None,
    ) -> List[List[str]]:
        """
        Install an isolated, idempotent nftables drop rule for `workload_ip` so the kernel
        never sends TCP RST while the workload is frozen or mid-switchover.
        """
        if not workload_ip:
            return []
        bare_ip = self._strip_cidr(workload_ip)
        addr = ipaddress.ip_address(bare_ip)
        addr_family = "ip6" if addr.version == 6 else "ip"
        table = self.table_name_for(workload_ip, migration_id)
        cmds = [
            ["nft", "add", "table", "inet", table],
            ["nft", "flush", "table", "inet", table],
            [
                "nft",
                "add",
                "chain",
                "inet",
                table,
                "input",
                "{ type filter hook input priority -100 ; }",
            ],
            [
                "nft",
                "add",
                "chain",
                "inet",
                table,
                "output",
                "{ type filter hook output priority -100 ; }",
            ],
            [
                "nft",
                "add",
                "rule",
                "inet",
                table,
                "input",
                addr_family,
                "daddr",
                bare_ip,
                "drop",
            ],
            [
                "nft",
                "add",
                "rule",
                "inet",
                table,
                "output",
                addr_family,
                "saddr",
                bare_ip,
                "drop",
            ],
        ]
        try:
            for idx, cmd in enumerate(cmds):
                try:
                    self.runner(cmd)
                except subprocess.CalledProcessError:
                    # Tolerate pre-existing table on repeated lock_network calls;
                    # the subsequent 'nft flush table' verifies the table is usable
                    # and clears any prior rules idempotently.
                    if idx == 0 and cmd[:3] == ["nft", "add", "table"]:
                        continue
                    raise
        except Exception:
            try:
                self.unlock_network(workload_ip, migration_id)
            except Exception:
                pass
            raise
        return cmds

    def unlock_network(
        self,
        workload_ip: Optional[str],
        migration_id: Optional[str] = None,
    ) -> List[List[str]]:
        """Remove the per-migration nftables lock table."""
        if not workload_ip:
            return []
        table = self.table_name_for(workload_ip, migration_id)
        cmd = ["nft", "delete", "table", "inet", table]
        try:
            self.runner(cmd)
        except subprocess.CalledProcessError:
            pass
        return [cmd]

    def assign_ip_for_restore(self, config: MigrationConfig) -> List[List[str]]:
        """
        Assign `workload_ip` on the target interface BEFORE `criu restore --tcp-established`
        (using idempotent `ip addr replace`) so CRIU can bind and repair established TCP sockets.
        """
        if config.ip_mobility == IpMobilityMode.NONE or not config.workload_ip:
            return []
        if config.ip_mobility not in (
            IpMobilityMode.GARP,
            IpMobilityMode.BGP,
            IpMobilityMode.TUNNEL,
        ):
            return []
        cidr = self._ensure_cidr(config.workload_ip)
        cmd = ["ip", "addr", "replace", cidr, "dev", config.net_interface]
        self.runner(cmd)
        return [cmd]

    def release_ip_on_host(
        self,
        config: MigrationConfig,
        migration_id: Optional[str] = None,
    ) -> List[List[str]]:
        """Remove the workload IP and/or withdraw BGP route on a host."""
        if config.ip_mobility == IpMobilityMode.NONE or not config.workload_ip:
            return []

        cidr = self._ensure_cidr(config.workload_ip)
        bare_ip = self._strip_cidr(config.workload_ip)
        addr = ipaddress.ip_address(bare_ip)
        cmds: List[List[str]] = []

        if config.ip_mobility in (
            IpMobilityMode.GARP,
            IpMobilityMode.BGP,
            IpMobilityMode.TUNNEL,
        ):
            cmds.append(["ip", "addr", "del", cidr, "dev", config.net_interface])

        if config.ip_mobility == IpMobilityMode.BGP:
            af = "ipv6" if addr.version == 6 else "ipv4"
            host_route = f"{bare_ip}/128" if addr.version == 6 else f"{bare_ip}/32"
            cmds.append(["gobgp", "global", "rib", "del", "-a", af, host_route])
        elif config.ip_mobility == IpMobilityMode.TUNNEL:
            dest_host = config.dest_addr.split(":", 1)[0]
            host_route = f"{bare_ip}/128" if addr.version == 6 else f"{bare_ip}/32"
            tun_dev = self.tunnel_dev_for(migration_id)
            cmds.extend(
                [
                    ["ip", "tunnel", "add", tun_dev, "mode", "ipip", "remote", dest_host],
                    ["ip", "link", "set", tun_dev, "up"],
                    ["ip", "route", "replace", host_route, "dev", tun_dev],
                ]
            )

        for cmd in cmds:
            self.runner(cmd)
        return cmds

    def announce_ip_on_host(
        self,
        config: MigrationConfig,
        target_host: str,
        ensure_assigned: bool = True,
    ) -> List[List[str]]:
        """
        Ensure the workload IP is present on `target_host` and announce its location via
        Gratuitous ARP (L2), BGP /32 route (L3), or Cloud API webhook.
        """
        if config.ip_mobility == IpMobilityMode.NONE or not config.workload_ip:
            return []

        cidr = self._ensure_cidr(config.workload_ip)
        bare_ip = self._strip_cidr(config.workload_ip)
        addr = ipaddress.ip_address(bare_ip)
        cmds: List[List[str]] = []

        if ensure_assigned and config.ip_mobility in (
            IpMobilityMode.GARP,
            IpMobilityMode.BGP,
            IpMobilityMode.TUNNEL,
        ):
            cmds.append(["ip", "addr", "replace", cidr, "dev", config.net_interface])

        if config.ip_mobility in (IpMobilityMode.GARP, IpMobilityMode.TUNNEL):
            if addr.version == 6:
                cmds.append(["ndsend", bare_ip, config.net_interface])
            else:
                cmds.append(
                    ["arping", "-U", "-c", "3", "-I", config.net_interface, bare_ip]
                )
        elif config.ip_mobility == IpMobilityMode.BGP:
            af = "ipv6" if addr.version == 6 else "ipv4"
            host_route = f"{bare_ip}/128" if addr.version == 6 else f"{bare_ip}/32"
            cmds.append(["gobgp", "global", "rib", "add", "-a", af, host_route])
        elif config.ip_mobility == IpMobilityMode.CLOUD:
            if not config.cloud_move_cmd:
                raise ValueError("IpMobilityMode.CLOUD requires cloud_move_cmd")
            formatted = config.cloud_move_cmd.format(
                ip=bare_ip, host=target_host, interface=config.net_interface
            )
            cmds.append(shlex.split(formatted))

        for cmd in cmds:
            self.runner(cmd)
        return cmds

    def claim_ip_on_host(self, config: MigrationConfig, target_host: str) -> List[List[str]]:
        """Backward-compatible alias for `announce_ip_on_host`."""
        return self.announce_ip_on_host(config, target_host=target_host, ensure_assigned=True)
