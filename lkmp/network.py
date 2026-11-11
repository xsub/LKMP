"""Per-migration network locking (nftables) and idempotent IP mobility drivers."""

from __future__ import annotations

import errno
import ipaddress
import os
import re
import shlex
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, List, Optional, Sequence

from lkmp.config import IpMobilityMode, MigrationConfig

SYS_PIDFD_GETFD: int = 438
SOL_TCP_REPAIR: int = getattr(socket, "TCP_REPAIR", 19)
SO_ACCEPTCONN_OPT: int = getattr(socket, "SO_ACCEPTCONN", 30)
ETH_P_ARP: int = 0x0806


def build_gratuitous_arp_frame(
    mac_bytes: bytes,
    ipv4_str: str,
    is_reply: bool = False,
) -> bytes:
    """
    Construct a 42-byte Ethernet II broadcast Gratuitous ARP frame (RFC 5227):
    - `dst_mac`: `ff:ff:ff:ff:ff:ff`
    - `ethertype`: `0x0806` (ARP)
    - `sender_mac = mac_bytes`, `sender_ip = target_ip = ipv4_str`
    """
    if len(mac_bytes) != 6:
        raise ValueError(f"Expected 6-byte Ethernet MAC address, got {len(mac_bytes)} bytes")
    ip_bytes = ipaddress.IPv4Address(ipv4_str).packed
    bcast = b"\xff\xff\xff\xff\xff\xff"
    target_hw = bcast if is_reply else b"\x00\x00\x00\x00\x00\x00"
    opcode = 2 if is_reply else 1
    eth_hdr = struct.pack("!6s6sH", bcast, mac_bytes, ETH_P_ARP)
    arp_payload = struct.pack(
        "!HHBBH6s4s6s4s",
        1,          # HTYPE = Ethernet (1)
        0x0800,     # PTYPE = IPv4
        6,          # HLEN = 6
        4,          # PLEN = 4
        opcode,     # OPER = 1 (Request) or 2 (Reply)
        mac_bytes,  # SHA
        ip_bytes,   # SPA
        target_hw,  # THA
        ip_bytes,   # TPA == SPA (Gratuitous ARP)
    )
    return eth_hdr + arp_payload


def _read_iface_mac_bytes(iface: str) -> Optional[bytes]:
    sysfs_addr = Path("/sys/class/net") / iface / "address"
    if sysfs_addr.exists():
        try:
            hex_parts = sysfs_addr.read_text(encoding="utf-8").strip().split(":")
            if len(hex_parts) == 6:
                mac = bytes(int(p, 16) for p in hex_parts)
                if mac != b"\x00\x00\x00\x00\x00\x00":
                    return mac
        except (OSError, ValueError):
            pass
    return None


def send_gratuitous_arp_raw(
    iface: str,
    ipv4_str: str,
    background_followups: bool = True,
) -> bool:
    """
    Sub-millisecond raw `AF_PACKET` Gratuitous ARP transmitter on Linux (`<0.2 ms` vs
    `2,000 ms` synchronous sleep in `arping -c 3`). Transmits an immediate GARP Request +
    Unsolicited ARP Reply pair, then optionally schedules 2 non-blocking follow-up bursts
    on a daemon thread so switchover resumes the workload without waiting on L2 timers.
    """
    af_packet = getattr(socket, "AF_PACKET", None)
    if af_packet is None or not sys.platform.startswith("linux"):
        return False

    mac = _read_iface_mac_bytes(iface)
    if mac is None:
        return False

    req_frame = build_gratuitous_arp_frame(mac, ipv4_str, is_reply=False)
    rep_frame = build_gratuitous_arp_frame(mac, ipv4_str, is_reply=True)

    try:
        with socket.socket(af_packet, socket.SOCK_RAW, socket.htons(ETH_P_ARP)) as sock:
            sock.bind((iface, ETH_P_ARP))
            sock.send(req_frame)
            sock.send(rep_frame)
    except OSError:
        return False

    if background_followups:
        def _followup_burst() -> None:
            for delay_s in (0.025, 0.085):
                time.sleep(delay_s)
                try:
                    with socket.socket(af_packet, socket.SOCK_RAW, socket.htons(ETH_P_ARP)) as s2:
                        s2.bind((iface, ETH_P_ARP))
                        s2.send(req_frame)
                except OSError:
                    return

        threading.Thread(target=_followup_burst, daemon=True).start()

    return True


class TcpRepairError(RuntimeError):
    """Raised when kernel TCP_REPAIR state cannot be applied and confirmed on a target PID."""


def parse_host_port(address: str, default_port: int = 9700) -> tuple[str, int]:
    """
    Parse an endpoint string into `(bare_host, port)` supporting IPv4, hostnames,
    bracketed IPv6 (`[::1]:9700`, `[2001:db8::1]`), and bare IPv6 (`2001:db8::1`, `::1`).
    """
    raw = address.strip()
    if not raw:
        raise ValueError("Endpoint address cannot be empty")

    if raw.startswith("["):
        close_idx = raw.find("]")
        if close_idx == -1:
            raise ValueError(f"Malformed bracketed IPv6 endpoint: {address!r}")
        host = raw[1:close_idx]
        rest = raw[close_idx + 1 :]
        if not rest:
            return host, default_port
        if not rest.startswith(":") or not rest[1:].isdigit():
            raise ValueError(f"Malformed port in endpoint: {address!r}")
        port = int(rest[1:])
        if not (0 <= port <= 65535):
            raise ValueError(f"Port out of range in endpoint: {address!r}")
        return host, port

    if raw.count(":") > 1:
        # Bare IPv6 literal without port (e.g. "2001:db8::1" or "::1")
        ipaddress.ip_address(raw)
        return raw, default_port

    if ":" in raw:
        host_part, port_part = raw.rsplit(":", 1)
        if not port_part.isdigit():
            raise ValueError(f"Invalid numeric port in endpoint: {address!r}")
        port = int(port_part)
        if not (0 <= port <= 65535):
            raise ValueError(f"Port out of range in endpoint: {address!r}")
        return host_part, port

    return raw, default_port


def format_host_port(host: str, port: int) -> str:
    """Format `(host, port)` with RFC 3986 brackets when `host` is an IPv6 literal."""
    clean_host = host.strip("[]")
    if ":" in clean_host:
        return f"[{clean_host}]:{port}"
    return f"{clean_host}:{port}"


@dataclass(frozen=True)
class TcpRepairResult:
    """Verified outcome of applying and reading back TCP_REPAIR across a process's sockets."""

    pid: int
    process_alive: bool
    sockets_inspected: int
    tcp_sockets_found: int
    tcp_sockets_confirmed: int


def _default_pidfd_open(pid: int) -> int:
    if not hasattr(os, "pidfd_open"):
        raise TcpRepairError(
            f"os.pidfd_open is unavailable on platform {sys.platform}; cannot confirm TCP_REPAIR for PID {pid}"
        )
    return os.pidfd_open(pid, 0)


def _default_pidfd_getfd(pfd: int, target_fd: int) -> int:
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    ctypes.set_errno(0)
    sfd = int(libc.syscall(SYS_PIDFD_GETFD, pfd, target_fd, 0))
    if sfd < 0:
        err = ctypes.get_errno() or errno.EPERM
        raise OSError(err, os.strerror(err))
    return sfd


def set_pid_tcp_repair(
    pid: int,
    enable: bool,
    *,
    proc_root: Path = Path("/proc"),
    pidfd_opener: Callable[[int], int] = _default_pidfd_open,
    fd_duplicator: Callable[[int, int], int] = _default_pidfd_getfd,
) -> TcpRepairResult:
    """
    Toggle Linux kernel TCP_REPAIR (1 = ON, 0 = OFF) on all active TCP stream sockets of `pid`
    via `pidfd_open` + `pidfd_getfd`, and confirm via `getsockopt(SOL_TCP, TCP_REPAIR)`.

    - `enable=True` before SIGKILL prevents kernel FIN/RST emission on connected TCP sockets.
    - `enable=False` before SIGCONT clears TCP_REPAIR left behind by `criu dump --tcp-established --leave-stopped`.

    Fails closed by raising `TcpRepairError` on any permission, syscall, or socket confirmation failure.
    """
    pid_dir = proc_root / str(pid)
    if not pid_dir.exists():
        return TcpRepairResult(
            pid=pid,
            process_alive=False,
            sockets_inspected=0,
            tcp_sockets_found=0,
            tcp_sockets_confirmed=0,
        )

    try:
        pfd = pidfd_opener(pid)
    except TcpRepairError:
        raise
    except OSError as exc:
        if exc.errno in (errno.ESRCH, errno.ENOENT):
            return TcpRepairResult(
                pid=pid,
                process_alive=False,
                sockets_inspected=0,
                tcp_sockets_found=0,
                tcp_sockets_confirmed=0,
            )
        raise TcpRepairError(f"pidfd_open({pid}) failed: {exc}") from exc

    sockets_inspected = 0
    tcp_sockets_found = 0
    tcp_sockets_confirmed = 0
    val = 1 if enable else 0

    try:
        fd_dir = pid_dir / "fd"
        try:
            entries = list(fd_dir.iterdir())
        except (FileNotFoundError, ProcessLookupError):
            return TcpRepairResult(
                pid=pid,
                process_alive=False,
                sockets_inspected=0,
                tcp_sockets_found=0,
                tcp_sockets_confirmed=0,
            )
        except OSError as exc:
            raise TcpRepairError(f"Cannot inspect {fd_dir}: {exc}") from exc

        for entry in entries:
            if not entry.name.isdigit():
                continue
            fd_num = int(entry.name)
            try:
                target = os.readlink(entry)
            except (FileNotFoundError, ProcessLookupError):
                continue
            except OSError as exc:
                if exc.errno in (errno.ESRCH, errno.ENOENT):
                    continue
                raise TcpRepairError(f"readlink({entry}) failed: {exc}") from exc

            if not target.startswith("socket:["):
                continue

            sockets_inspected += 1
            try:
                sfd = fd_duplicator(pfd, fd_num)
            except TcpRepairError:
                raise
            except OSError as exc:
                if exc.errno in (errno.ESRCH, errno.EBADF, errno.ENOENT):
                    continue
                raise TcpRepairError(
                    f"pidfd_getfd(pid={pid}, fd={fd_num}) failed: {exc}"
                ) from exc

            sock: Optional[socket.socket] = None
            try:
                sock = socket.socket(fileno=sfd)
                if sock.family not in (socket.AF_INET, socket.AF_INET6):
                    continue
                if (sock.type & 0xFF) != socket.SOCK_STREAM:
                    continue

                if enable:
                    try:
                        is_listening = sock.getsockopt(socket.SOL_SOCKET, SO_ACCEPTCONN_OPT) != 0
                    except OSError:
                        is_listening = False
                    if is_listening:
                        continue
                    try:
                        sock.getpeername()
                    except OSError as exc:
                        if exc.errno == errno.ENOTCONN:
                            continue
                        raise TcpRepairError(
                            f"getpeername(pid={pid}, fd={fd_num}) failed: {exc}"
                        ) from exc

                    tcp_sockets_found += 1
                    try:
                        sock.setsockopt(socket.SOL_TCP, SOL_TCP_REPAIR, val)
                        readback = sock.getsockopt(socket.SOL_TCP, SOL_TCP_REPAIR)
                    except OSError as exc:
                        raise TcpRepairError(
                            f"setsockopt/getsockopt TCP_REPAIR=1 failed on pid={pid} fd={fd_num}: {exc}"
                        ) from exc
                    if readback == 0:
                        raise TcpRepairError(
                            f"Kernel did not confirm TCP_REPAIR=1 on pid={pid} fd={fd_num} (readback={readback})"
                        )
                    tcp_sockets_confirmed += 1
                else:
                    try:
                        cur_repair = sock.getsockopt(socket.SOL_TCP, SOL_TCP_REPAIR)
                    except OSError as exc:
                        raise TcpRepairError(
                            f"getsockopt TCP_REPAIR failed on pid={pid} fd={fd_num}: {exc}"
                        ) from exc
                    if cur_repair != 0:
                        tcp_sockets_found += 1
                        try:
                            sock.setsockopt(socket.SOL_TCP, SOL_TCP_REPAIR, 0)
                            readback = sock.getsockopt(socket.SOL_TCP, SOL_TCP_REPAIR)
                        except OSError as exc:
                            raise TcpRepairError(
                                f"setsockopt/getsockopt TCP_REPAIR=0 failed on pid={pid} fd={fd_num}: {exc}"
                            ) from exc
                        if readback != 0:
                            raise TcpRepairError(
                                f"Kernel did not confirm TCP_REPAIR=0 on pid={pid} fd={fd_num} (readback={readback})"
                            )
                        tcp_sockets_confirmed += 1
            finally:
                if sock is not None:
                    sock.close()
                else:
                    try:
                        os.close(sfd)
                    except OSError:
                        pass
    finally:
        try:
            os.close(pfd)
        except OSError:
            pass

    if tcp_sockets_confirmed != tcp_sockets_found:
        raise TcpRepairError(
            f"Incomplete TCP_REPAIR confirmation for pid={pid}: {tcp_sockets_confirmed}/{tcp_sockets_found}"
        )

    return TcpRepairResult(
        pid=pid,
        process_alive=True,
        sockets_inspected=sockets_inspected,
        tcp_sockets_found=tcp_sockets_found,
        tcp_sockets_confirmed=tcp_sockets_confirmed,
    )


def set_tree_tcp_repair(
    pids: Sequence[int],
    enable: bool,
    *,
    proc_root: Path = Path("/proc"),
    pidfd_opener: Callable[[int], int] = _default_pidfd_open,
    fd_duplicator: Callable[[int, int], int] = _default_pidfd_getfd,
) -> List[TcpRepairResult]:
    """Apply and verify TCP_REPAIR across every PID in a process tree, failing closed on any error."""
    seen: set[int] = set()
    results: List[TcpRepairResult] = []
    for raw_pid in pids:
        p = int(raw_pid)
        if p in seen:
            continue
        seen.add(p)
        res = set_pid_tcp_repair(
            p,
            enable=enable,
            proc_root=proc_root,
            pidfd_opener=pidfd_opener,
            fd_duplicator=fd_duplicator,
        )
        results.append(res)
    return results


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
        Executes table creation, flush, chain setup, and drop rules in a single atomic
        `nft` netlink transaction so repeated calls never open a packet-leak window.
        """
        if not workload_ip:
            return []
        bare_ip = self._strip_cidr(workload_ip)
        addr = ipaddress.ip_address(bare_ip)
        addr_family = "ip6" if addr.version == 6 else "ip"
        table = self.table_name_for(workload_ip, migration_id)
        batch = (
            f"add table inet {table}; "
            f"flush table inet {table}; "
            f"add chain inet {table} input {{ type filter hook input priority -100; policy accept; }}; "
            f"add chain inet {table} output {{ type filter hook output priority -100; policy accept; }}; "
            f"add rule inet {table} input {addr_family} daddr {bare_ip} drop; "
            f"add rule inet {table} output {addr_family} saddr {bare_ip} drop;"
        )
        cmd = ["nft", batch]
        try:
            self.runner(cmd)
        except Exception:
            # Preserve any pre-existing protective drop ruleset if already active in the kernel;
            # only clean up when no active lock is protecting `workload_ip`.
            try:
                if not self.verify_network_locked(workload_ip, migration_id):
                    self.unlock_network(workload_ip, migration_id)
            except Exception:
                pass
            raise
        return [cmd]

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

    def verify_network_locked(
        self,
        workload_ip: Optional[str],
        migration_id: Optional[str] = None,
    ) -> bool:
        """
        Confirm via `nft list table inet <table>` that the per-migration packet lock table
        exists in the kernel and actively enforces both `input` (`daddr <ip> drop`) and
        `output` (`saddr <ip> drop`) filter chains for `workload_ip`.
        """
        if not workload_ip:
            return False
        bare_ip = self._strip_cidr(workload_ip)
        try:
            addr = ipaddress.ip_address(bare_ip)
        except ValueError:
            return False
        norm_ip = str(addr)
        addr_family = "ip6" if addr.version == 6 else "ip"
        table = self.table_name_for(workload_ip, migration_id)
        try:
            res = self.runner(["nft", "list", "table", "inet", table])
        except (subprocess.CalledProcessError, OSError):
            return False
        if res.returncode != 0:
            return False

        stdout = res.stdout or ""
        if f"table inet {table}" not in stdout:
            return False

        m_in = re.search(r"chain\s+input\s*\{([^}]*)\}", stdout, re.DOTALL)
        m_out = re.search(r"chain\s+output\s*\{([^}]*)\}", stdout, re.DOTALL)
        if not m_in or not m_out:
            return False

        in_body = m_in.group(1)
        out_body = m_out.group(1)
        if "hook input" not in in_body or "hook output" not in out_body:
            return False

        ip_candidates = {re.escape(bare_ip), re.escape(norm_ip)}
        ip_pat = "(?:" + "|".join(sorted(ip_candidates)) + ")"
        in_rule_ok = bool(re.search(rf"\b{addr_family}\s+daddr\s+{ip_pat}\s+drop\b", in_body))
        out_rule_ok = bool(re.search(rf"\b{addr_family}\s+saddr\s+{ip_pat}\s+drop\b", out_body))
        return in_rule_ok and out_rule_ok

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
            if config.bgp_daemon_cmd:
                src_host, _ = parse_host_port(config.source_addr)
                formatted = config.bgp_daemon_cmd.format(
                    action="del",
                    op="withdraw",
                    ip=bare_ip,
                    prefix=host_route,
                    af=af,
                    host=src_host,
                    interface=config.net_interface,
                )
                cmds.append(shlex.split(formatted))
            else:
                cmds.append(["gobgp", "global", "rib", "del", "-a", af, host_route])
        elif config.ip_mobility == IpMobilityMode.TUNNEL:
            dest_host, _ = parse_host_port(config.dest_addr)
            host_route = f"{bare_ip}/128" if addr.version == 6 else f"{bare_ip}/32"
            tun_dev = self.tunnel_dev_for(migration_id)
            use_v6_tun = addr.version == 6
            if not use_v6_tun:
                try:
                    use_v6_tun = ipaddress.ip_address(dest_host).version == 6
                except ValueError:
                    use_v6_tun = False
            if use_v6_tun:
                tun_add_cmd = ["ip", "-6", "tunnel", "add", tun_dev, "mode", "ip6ip6", "remote", dest_host]
                route_cmd = ["ip", "-6", "route", "replace", host_route, "dev", tun_dev]
            else:
                tun_add_cmd = ["ip", "tunnel", "add", tun_dev, "mode", "ipip", "remote", dest_host]
                route_cmd = ["ip", "route", "replace", host_route, "dev", tun_dev]
            cmds.extend(
                [
                    tun_add_cmd,
                    ["ip", "link", "set", tun_dev, "up"],
                    route_cmd,
                ]
            )

        for cmd in cmds:
            try:
                self.runner(cmd)
            except subprocess.CalledProcessError as exc:
                err_text = f"{exc.stderr or ''} {exc.stdout or ''}"
                if cmd[:3] == ["ip", "addr", "del"] and "Cannot assign requested address" in err_text:
                    continue
                if "tunnel" in cmd and "add" in cmd and ("File exists" in err_text or "exist" in err_text.lower()):
                    tun_dev = self.tunnel_dev_for(migration_id)
                    try:
                        self.runner(["ip", "link", "del", tun_dev])
                    except subprocess.CalledProcessError:
                        pass
                    self.runner(cmd)
                    continue
                raise
        return cmds

    def teardown_tunnel(
        self,
        config: MigrationConfig,
        migration_id: Optional[str] = None,
    ) -> List[List[str]]:
        """Idempotently remove any temporary IPIP/IP6IP6 forwarding tunnel device for `migration_id`."""
        if config.ip_mobility != IpMobilityMode.TUNNEL:
            return []
        tun_dev = self.tunnel_dev_for(migration_id)
        cmd = ["ip", "link", "del", tun_dev]
        try:
            self.runner(cmd)
        except subprocess.CalledProcessError as exc:
            err_text = f"{exc.stderr or ''} {exc.stdout or ''}".lower()
            if (
                "cannot find device" in err_text
                or "does not exist" in err_text
                or "no such device" in err_text
                or exc.returncode in (1, 2)
            ):
                return [cmd]
            raise
        return [cmd]

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
            elif self.runner is _default_runner and sys.platform.startswith("linux"):
                # Execute IP assignment first if needed before emitting raw AF_PACKET GARP
                for pre_cmd in cmds:
                    self.runner(pre_cmd)
                executed_cmds = list(cmds)
                cmds.clear()
                if send_gratuitous_arp_raw(config.net_interface, bare_ip, background_followups=True):
                    executed_cmds.append(["af_packet_garp", config.net_interface, bare_ip])
                else:
                    cmds.append(["arping", "-U", "-c", "1", "-w", "0", "-I", config.net_interface, bare_ip])
                for rem_cmd in cmds:
                    self.runner(rem_cmd)
                    executed_cmds.append(rem_cmd)
                return executed_cmds
            else:
                cmds.append(
                    ["arping", "-U", "-c", "3", "-I", config.net_interface, bare_ip]
                )
        elif config.ip_mobility == IpMobilityMode.BGP:
            af = "ipv6" if addr.version == 6 else "ipv4"
            host_route = f"{bare_ip}/128" if addr.version == 6 else f"{bare_ip}/32"
            if config.bgp_daemon_cmd:
                clean_target, _ = parse_host_port(target_host)
                formatted = config.bgp_daemon_cmd.format(
                    action="add",
                    op="announce",
                    ip=bare_ip,
                    prefix=host_route,
                    af=af,
                    host=clean_target,
                    interface=config.net_interface,
                )
                cmds.append(shlex.split(formatted))
            else:
                cmds.append(["gobgp", "global", "rib", "add", "-a", af, host_route])
        elif config.ip_mobility == IpMobilityMode.CLOUD:
            if not config.cloud_move_cmd:
                raise ValueError("IpMobilityMode.CLOUD requires cloud_move_cmd")
            formatted = config.cloud_move_cmd.format(
                ip=bare_ip, host=target_host, interface=config.net_interface
            )
            cmds.append(shlex.split(formatted))

        for cmd in cmds:
            try:
                self.runner(cmd)
            except subprocess.CalledProcessError as exc:
                err_text = f"{exc.stderr or ''} {exc.stdout or ''}"
                if cmd[:3] == ["ip", "addr", "del"] and "Cannot assign requested address" in err_text:
                    continue
                raise
        return cmds

    def claim_ip_on_host(self, config: MigrationConfig, target_host: str) -> List[List[str]]:
        """Backward-compatible alias for `announce_ip_on_host`."""
        return self.announce_ip_on_host(config, target_host=target_host, ensure_assigned=True)
