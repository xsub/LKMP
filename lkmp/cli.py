"""Command-line interface for `lkmp` (run, agent, preflight, migrate, demo)."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from typing import List, Optional

from lkmp.agent import AgentClient, AgentServer, AgentService
from lkmp.config import (
    EnvelopeConfig,
    FilesystemMode,
    GpuPlugin,
    IpMobilityMode,
    MigrationConfig,
    MigrationStrategy,
    TlsConfig,
)
from lkmp.demo import run_live_demo, run_sota_benchmark_suite
from lkmp.envelope import EnvelopeManager
from lkmp.orchestrator import MigrationOrchestrator
from lkmp.telemetry import render_migration_report, render_preflight_scorecard


def _add_common_migration_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--pid", type=int, required=True, help="Root PID of process tree on Source A")
    parser.add_argument("--source", required=True, help="Source A agent address (host:port)")
    parser.add_argument("--dest", required=True, help="Destination B agent address (host:port)")
    parser.add_argument("--workload-id", help="Envelope workload ID (for cgroup v2 freeze)")
    parser.add_argument(
        "--strategy",
        choices=[s.value for s in MigrationStrategy],
        default=MigrationStrategy.PRE_COPY.value,
        help="Memory migration strategy: auto, cold, pre-copy, lazy, hybrid (default: pre-copy)",
    )
    parser.add_argument(
        "--fs-mode",
        choices=[m.value for m in FilesystemMode],
        default=FilesystemMode.SHARED.value,
        help="Filesystem synchronization mode (default: shared)",
    )
    parser.add_argument(
        "--writable-path",
        action="append",
        default=[],
        dest="writable_paths",
        help="Writable path to rsync when --fs-mode=rsync (repeatable)",
    )
    parser.add_argument(
        "--ip-mobility",
        choices=[m.value for m in IpMobilityMode],
        default=IpMobilityMode.GARP.value,
        help="IP mobility mechanism during switchover (default: garp)",
    )
    parser.add_argument("--workload-ip", help="Dedicated workload IP (e.g. 10.10.0.50/24)")
    parser.add_argument("--iface", default="eth0", help="Network interface for IP mobility")
    parser.add_argument("--cloud-move-cmd", help="Command template for cloud IP reassignment")
    parser.add_argument(
        "--no-tcp-established",
        action="store_true",
        help="Disable active TCP socket preservation (--tcp-established)",
    )
    parser.add_argument(
        "--unsafe-bare",
        action="store_true",
        help="Allow migrating a bare host process outside an lkmp namespace envelope",
    )
    parser.add_argument(
        "--gpu-plugin",
        choices=[g.value for g in GpuPlugin],
        default=GpuPlugin.NONE.value,
        help="GPU checkpoint plugin (default: none)",
    )
    parser.add_argument(
        "--max-iter",
        type=int,
        default=8,
        help="Maximum iterative pre-copy rounds (default: 8)",
    )
    parser.add_argument(
        "--target-downtime-ms",
        type=int,
        default=200,
        help="Target downtime budget in ms for pre-copy convergence (default: 200)",
    )
    parser.add_argument(
        "--bandwidth-mbps",
        type=float,
        default=1000.0,
        help="Estimated network bandwidth in Mbps between hosts (default: 1000)",
    )
    parser.add_argument("--health-cmd", help="Health check command to run on Destination B before commit")
    parser.add_argument("--no-tls", action="store_true", help="Disable TLS on agent & page-server links")
    parser.add_argument("--tls-ca", help="Path to CA certificate bundle")
    parser.add_argument("--tls-cert", help="Path to TLS certificate")
    parser.add_argument("--tls-key", help="Path to TLS private key")
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON output")


def _build_migration_config(args: argparse.Namespace) -> MigrationConfig:
    tls = TlsConfig(
        enabled=not args.no_tls,
        ca_cert=args.tls_ca,
        cert_file=args.tls_cert,
        key_file=args.tls_key,
    )
    return MigrationConfig(
        pid=args.pid,
        source_addr=args.source,
        dest_addr=args.dest,
        workload_id=args.workload_id,
        strategy=MigrationStrategy(args.strategy),
        fs_mode=FilesystemMode(args.fs_mode),
        writable_paths=list(args.writable_paths),
        ip_mobility=IpMobilityMode(args.ip_mobility),
        workload_ip=args.workload_ip,
        net_interface=args.iface,
        cloud_move_cmd=args.cloud_move_cmd,
        tcp_established=not args.no_tcp_established,
        unsafe_bare=args.unsafe_bare,
        gpu_plugin=GpuPlugin(args.gpu_plugin),
        max_precopy_iterations=args.max_iter,
        target_downtime_ms=args.target_downtime_ms,
        estimated_bandwidth_mbps=args.bandwidth_mbps,
        health_check_cmd=args.health_cmd,
        tls=tls,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lkmp",
        description="LKMP: Linux Process Migration Orchestrator on top of CRIU",
    )
    sub = parser.add_subparsers(dest="subcommand", required=True)

    # 1. `lkmp run`
    run_p = sub.add_parser("run", help="Launch a workload inside an isolated migration envelope")
    run_p.add_argument("--id", required=True, dest="workload_id", help="Unique workload identifier")
    run_p.add_argument("--rootfs", help="Optional chroot/pivot_root directory")
    run_p.add_argument("--ip", dest="ip_address", help="Dedicated IP/CIDR inside netns")
    run_p.add_argument("--iface", default="eth0", help="Network interface inside netns")
    run_p.add_argument("--no-time-ns", action="store_true", help="Disable time namespace isolation")
    run_p.add_argument("--dry-run", action="store_true", help="Print unshare command without executing")
    run_p.add_argument("command", nargs=argparse.REMAINDER, help="Command to run (prefix with --)")

    # 2. `lkmp agent`
    agent_p = sub.add_parser("agent", help="Run the privileged lkmp-agent daemon on a host")
    agent_p.add_argument("--host", default="0.0.0.0", help="Listen address (default: 0.0.0.0)")
    agent_p.add_argument("--port", type=int, default=9700, help="Listen port (default: 9700)")
    agent_p.add_argument(
        "--work-dir",
        default="/var/lib/lkmp/migrations",
        help="Directory for CRIU checkpoint images",
    )
    agent_p.add_argument("--no-tls", action="store_true", help="Disable TLS")
    agent_p.add_argument("--tls-ca", help="Path to mTLS CA certificate")
    agent_p.add_argument("--tls-cert", help="Path to server certificate")
    agent_p.add_argument("--tls-key", help="Path to server private key")

    # 3. `lkmp preflight`
    pre_p = sub.add_parser("preflight", help="Run non-destructive compatibility & blocker checks")
    _add_common_migration_args(pre_p)

    # 4. `lkmp migrate`
    mig_p = sub.add_parser("migrate", help="Execute live or cold process migration from A to B")
    _add_common_migration_args(mig_p)

    # 5. `lkmp demo`
    demo_p = sub.add_parser(
        "demo",
        help="Run a self-contained two-node live migration simulation over loopback TCP RPC",
    )
    demo_p.add_argument(
        "--strategy",
        choices=[s.value for s in MigrationStrategy],
        default=MigrationStrategy.AUTO.value,
        help="Migration strategy (default: auto)",
    )
    demo_p.add_argument("--rss-mb", type=int, default=256, help="Simulated process RSS in MiB (default: 256)")
    demo_p.add_argument(
        "--dirty-mbps",
        type=int,
        default=40,
        help="Simulated memory write rate in MiB/s (default: 40)",
    )
    demo_p.add_argument(
        "--inject-fault",
        choices=["none", "restore", "verify", "corrupt-image"],
        default="none",
        help="Inject a destination failure or image bitflip to test rollback (default: none)",
    )
    demo_p.add_argument("--prometheus", action="store_true", help="Print Prometheus OpenMetrics output")
    demo_p.add_argument("--json", action="store_true", help="Emit JSON output")

    # 6. `lkmp benchmark`
    sub.add_parser(
        "benchmark",
        help="Run comparative SOTA benchmark across workload profiles & Merkle tamper defense",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.subcommand == "run":
        cmd = list(args.command)
        if cmd and cmd[0] == "--":
            cmd = cmd[1:]
        if not cmd:
            parser.error("lkmp run requires a command after '--'")
        env_cfg = EnvelopeConfig(
            workload_id=args.workload_id,
            command=cmd,
            rootfs=args.rootfs,
            ip_address=args.ip_address,
            net_interface=args.iface,
            use_time_ns=not args.no_time_ns,
        )
        mgr = EnvelopeManager()
        if args.dry_run:
            print(" ".join(mgr.build_unshare_command(env_cfg)))
            return 0
        pid = mgr.launch(env_cfg)
        print(json.dumps({"workload_id": args.workload_id, "host_pid": pid}))
        return 0

    if args.subcommand == "agent":
        tls = TlsConfig(
            enabled=not args.no_tls,
            ca_cert=args.tls_ca,
            cert_file=args.tls_cert,
            key_file=args.tls_key,
        )
        service = AgentService(work_dir=args.work_dir)
        server = AgentServer(host=args.host, port=args.port, service=service, tls=tls)
        print(f"lkmp-agent listening on {args.host}:{args.port} (work_dir={args.work_dir})")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()
        return 0

    if args.subcommand == "preflight":
        cfg = _build_migration_config(args)
        src_client = AgentClient(cfg.source_addr, tls=cfg.tls)
        dst_client = AgentClient(cfg.dest_addr, tls=cfg.tls)
        orch = MigrationOrchestrator(cfg, src_client, dst_client)
        report = orch.run_preflight()
        if args.json:
            payload = {
                "compatible": report.compatible,
                "selected_strategy": orch.config.strategy.value,
                "estimated_cold_downtime_ms": report.estimated_cold_downtime_ms,
                "estimated_live_downtime_ms": report.estimated_live_downtime_ms,
                "required_criu_flags": report.required_criu_flags,
                "findings": [f.to_dict() for f in report.findings],
            }
            print(json.dumps(payload, indent=2))
        else:
            print(render_preflight_scorecard(report, orch.config.strategy.value))
        return 0 if report.compatible else 2

    if args.subcommand == "migrate":
        cfg = _build_migration_config(args)
        src_client = AgentClient(cfg.source_addr, tls=cfg.tls)
        dst_client = AgentClient(cfg.dest_addr, tls=cfg.tls)
        orch = MigrationOrchestrator(cfg, src_client, dst_client)
        result = orch.execute()
        if args.json:
            payload = asdict(result)
            payload["final_state"] = result.final_state.value
            payload["state_history"] = [s.value for s in result.state_history]
            print(json.dumps(payload, indent=2))
        else:
            print(render_migration_report(result, orch.config.strategy.value))
        return 0 if result.success else 1

    if args.subcommand == "demo":
        result, resolved_strategy, metrics = run_live_demo(
            strategy=MigrationStrategy(args.strategy),
            rss_mb=args.rss_mb,
            dirty_mbps=args.dirty_mbps,
            inject_fault=args.inject_fault,
        )
        if args.json:
            payload = asdict(result)
            payload["selected_strategy"] = resolved_strategy
            payload["final_state"] = result.final_state.value
            payload["state_history"] = [s.value for s in result.state_history]
            print(json.dumps(payload, indent=2))
        else:
            print(render_migration_report(result, resolved_strategy))
            if args.prometheus:
                print("\nPrometheus Metrics (/metrics):")
                print(metrics.export_prometheus_text().rstrip())
        return 0 if result.success or args.inject_fault != "none" else 1

    if args.subcommand == "benchmark":
        print(run_sota_benchmark_suite())
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
