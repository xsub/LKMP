"""Network locking (nftables) and IP mobility drivers (GARP, BGP, Cloud API)."""

from __future__ import annotations

import ipaddress
import shlex
import subprocess
from typing import Callable, List, Optional

from lkmp.config import IpMobilityMode, MigrationConfig


CommandRunner = Callable[[List[str]], subprocess.CompletedProcess]


def _default_runner(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, text=True, capture_output=True)


class NetworkMobilityManager:
    """Manages nftables TCP packet drop locks and IP mobility across Source A and Destination B."""

    NFT_TABLE = "lkmp_migration_lock"

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

    def lock_network(self, workload_ip: Optional[str]) -> List[List[str]]:
        """
        Install an nftables drop rule for `workload_ip` so the kernel never sends TCP RST
        while the workload is frozen or mid-switchover.
        """
        if not workload_ip:
            return []
        bare_ip = self._strip_cidr(workload_ip)
        addr = ipaddress.ip_address(bare_ip)
        addr_family = "ip6" if addr.version == 6 else "ip"
        cmds = [
            ["nft", "add", "table", "inet", self.NFT_TABLE],
            [
                "nft",
                "add",
                "chain",
                "inet",
                self.NFT_TABLE,
                "input",
                "{ type filter hook input priority -100 ; }",
            ],
            [
                "nft",
                "add",
                "chain",
                "inet",
                self.NFT_TABLE,
                "output",
                "{ type filter hook output priority -100 ; }",
            ],
            [
                "nft",
                "add",
                "rule",
                "inet",
                self.NFT_TABLE,
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
                self.NFT_TABLE,
                "output",
                addr_family,
                "saddr",
                bare_ip,
                "drop",
            ],
        ]
        for cmd in cmds:
            self.runner(cmd)
        return cmds

    def unlock_network(self, workload_ip: Optional[str]) -> List[List[str]]:
        """Remove the nftables lock table."""
        if not workload_ip:
            return []
        cmd = ["nft", "delete", "table", "inet", self.NFT_TABLE]
        self.runner(cmd)
        return [cmd]

    def release_ip_on_host(self, config: MigrationConfig) -> List[List[str]]:
        """Remove the workload IP and/or withdraw BGP route on a host."""
        if config.ip_mobility == IpMobilityMode.NONE or not config.workload_ip:
            return []

        cidr = self._ensure_cidr(config.workload_ip)
        bare_ip = self._strip_cidr(config.workload_ip)
        addr = ipaddress.ip_address(bare_ip)
        cmds: List[List[str]] = []

        if config.ip_mobility in (IpMobilityMode.GARP, IpMobilityMode.BGP, IpMobilityMode.EBPF):
            cmds.append(["ip", "addr", "del", cidr, "dev", config.net_interface])

        if config.ip_mobility == IpMobilityMode.BGP:
            af = "ipv6" if addr.version == 6 else "ipv4"
            host_route = f"{bare_ip}/128" if addr.version == 6 else f"{bare_ip}/32"
            cmds.append(["gobgp", "global", "rib", "del", "-a", af, host_route])
        elif config.ip_mobility == IpMobilityMode.EBPF:
            dest_host = config.dest_addr.split(":", 1)[0]
            host_route = f"{bare_ip}/128" if addr.version == 6 else f"{bare_ip}/32"
            # Set up zero-drop tunnel/TC forwarding on Source A so in-flight packets reach B
            cmds.extend(
                [
                    ["ip", "tunnel", "add", "lkmp0", "mode", "ipip", "remote", dest_host],
                    ["ip", "link", "set", "lkmp0", "up"],
                    ["ip", "route", "replace", host_route, "dev", "lkmp0"],
                ]
            )

        for cmd in cmds:
            self.runner(cmd)
        return cmds

    def claim_ip_on_host(self, config: MigrationConfig, target_host: str) -> List[List[str]]:
        """Assign the workload IP and announce its new location via GARP, BGP, eBPF, or Cloud API."""
        if config.ip_mobility == IpMobilityMode.NONE or not config.workload_ip:
            return []

        cidr = self._ensure_cidr(config.workload_ip)
        bare_ip = self._strip_cidr(config.workload_ip)
        addr = ipaddress.ip_address(bare_ip)
        cmds: List[List[str]] = []

        if config.ip_mobility in (IpMobilityMode.GARP, IpMobilityMode.BGP, IpMobilityMode.EBPF):
            cmds.append(["ip", "addr", "add", cidr, "dev", config.net_interface])

        if config.ip_mobility in (IpMobilityMode.GARP, IpMobilityMode.EBPF):
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
