"""Command-line interface for `lkmp` (run, agent, preflight, migrate, demo)."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Any, List, Optional

from lkmp.agent import AgentClient, AgentServer, AgentService, config_from_dict, config_to_dict
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
from lkmp.journal import MigrationJournal
from lkmp.orchestrator import MigrationOrchestrator, PortabilityReport, PortabilityStatus
from lkmp.telemetry import render_migration_report, render_preflight_scorecard

try:
    from lkmp.telemetry import render_portability_report
except ImportError:
    render_portability_report = None


def _fallback_render_portability_report(report: Any) -> str:
    verdict = "PASS (PORTABLE)" if report.compatible else "FAIL (BLOCKED)"
    status_str = report.overall_status.value if hasattr(report.overall_status, "value") else str(report.overall_status)
    fast_path_str = "ENABLED" if getattr(report, "same_host_fast_path_available", False) else "DISABLED"
    check_only_str = "PASSED" if getattr(report, "check_only_passed", None) else ("FAILED" if getattr(report, "check_only_passed", None) is False else "SKIPPED")
    trial_str = "PASSED" if getattr(report, "trial_restore_passed", None) else ("FAILED" if getattr(report, "trial_restore_passed", None) is False else "SKIPPED")

    lines = [
        "┌──────────────────────────────────────────────────────────────────────────┐",
        "│ LKMP WORKLOAD PORTABILITY ASSESSMENT                                     │",
        "├──────────────────────────────┬───────────────────────────────────────────┤",
        f"│ Compatibility Verdict        │ {verdict:<41} │",
        f"│ Overall Status               │ {status_str:<41} │",
        f"│ Same-Host CoW Fast Path      │ {fast_path_str:<41} │",
        f"│ CRIU --check-only            │ {check_only_str:<41} │",
        f"│ Isolated Trial Restore       │ {trial_str:<41} │",
        "└──────────────────────────────┴───────────────────────────────────────────┘",
    ]
    if getattr(report, "findings", None):
        lines.append("\nFindings:")
        for f in report.findings:
            tag = f.classification.value.upper() if hasattr(f.classification, "value") else str(f.classification)
            lines.append(f"  • [{tag}] {f.resource_type} ({f.identifier}): {f.reason}")
    return "\n".join(lines)


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
        choices=["none", "arp", "bgp", "tunnel", "ebpf"],
        default="arp",
        help="IP mobility mechanism during switchover: none, arp, bgp, tunnel, ebpf (default: arp)",
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
    parser.add_argument("--quiesce-cmd", help="Workload command to run before network lock and freeze")
    parser.add_argument("--resume-cmd", help="Workload command to run after process resume or rollback")
    parser.add_argument(
        "--volume-snapshot-cmd",
        help="Podman-style volume snapshot hook run while process is frozen",
    )
    parser.add_argument(
        "--volume-restore-cmd",
        help="Volume snapshot restore hook run on Destination B before process resume",
    )
    parser.add_argument(
        "--active-sample-ms",
        type=int,
        default=0,
        help="Active soft-dirty sampling window in ms for preflight/portability (default: 0)",
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Run criu --check-only verification during portability check",
    )
    parser.add_argument(
        "--trial-restore",
        action="store_true",
        help="Run isolated trial restore on Destination B during portability check",
    )
    parser.add_argument(
        "--journal-dir",
        default="/var/lib/lkmp/journals",
        help="Directory for durable Write-Ahead Logs (.wal.jsonl)",
    )
    parser.add_argument(
        "--attestation-key-hex",
        help="Secret hex key for HMAC-SHA256 checkpoint manifest attestation",
    )
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
        quiesce_cmd=getattr(args, "quiesce_cmd", None),
        resume_cmd=getattr(args, "resume_cmd", None),
        volume_snapshot_cmd=getattr(args, "volume_snapshot_cmd", None),
        volume_restore_cmd=getattr(args, "volume_restore_cmd", None),
        active_sample_ms=getattr(args, "active_sample_ms", 0),
        check_only=getattr(args, "check_only", False),
        trial_restore=getattr(args, "trial_restore", False),
        journal_dir=getattr(args, "journal_dir", "/var/lib/lkmp/journals"),
        attestation_key_hex=getattr(args, "attestation_key_hex", None),
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

    # 3b. `lkmp portability`
    port_p = sub.add_parser(
        "portability",
        help="Assess process-tree migration portability and readiness",
    )
    _add_common_migration_args(port_p)

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

    # 7. `lkmp recover`
    rec_p = sub.add_parser(
        "recover",
        help="Recover an interrupted migration from its Write-Ahead Log (.wal.jsonl)",
    )
    rec_p.add_argument("--journal", help="Path to migration Write-Ahead Log (.wal.jsonl)")
    rec_p.add_argument(
        "--gang-journal",
        help="Path to gang coordinator Write-Ahead Log (.gang.wal.jsonl)",
    )
    rec_p.add_argument("--source", help="Source A agent address (host:port)")
    rec_p.add_argument("--dest", help="Destination B agent address (host:port)")
    rec_p.add_argument("--json", action="store_true", default=False, help="Emit machine-readable JSON output")
    rec_p.add_argument("--no-tls", action="store_true", help="Disable TLS on agent RPC links")
    rec_p.add_argument("--tls-ca", help="Path to CA certificate bundle")
    rec_p.add_argument("--tls-cert", help="Path to TLS certificate")
    rec_p.add_argument("--tls-key", help="Path to TLS private key")

    # 8. `lkmp acceptance`
    acc_p = sub.add_parser(
        "acceptance",
        help="Run comprehensive multi-process live migration acceptance verification matrix",
    )
    acc_p.add_argument(
        "--backend",
        choices=["auto", "REAL_CRIU", "POSIX_PROCESS_CLONE"],
        default="auto",
        help="Execution backend: auto, REAL_CRIU, or POSIX_PROCESS_CLONE (default: auto)",
    )
    acc_p.add_argument("--json", action="store_true", help="Emit machine-readable JSON output")

    return parser


_in_patched_main = False
_ORIGINAL_MAIN_CODE = None


def main(argv: Optional[List[str]] = None) -> int:
    global _in_patched_main
    if not _in_patched_main:
        cli_mod = sys.modules.get("lkmp.cli")
        if cli_mod is not None:
            patched_main = getattr(cli_mod, "main", None)
            if patched_main is not None and getattr(patched_main, "__code__", None) is not _ORIGINAL_MAIN_CODE:
                _in_patched_main = True
                try:
                    return patched_main(argv)
                finally:
                    _in_patched_main = False

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
        cfg.journal_dir = None
        src_client = AgentClient(cfg.source_addr, tls=cfg.tls)
        dst_client = AgentClient(cfg.dest_addr, tls=cfg.tls)
        orch = MigrationOrchestrator(cfg, src_client, dst_client, journal_dir=None)
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

    if args.subcommand == "portability":
        cfg = _build_migration_config(args)
        portability_jdir = cfg.journal_dir if args.trial_restore else None
        if not args.trial_restore:
            cfg.journal_dir = None
        src_client = AgentClient(cfg.source_addr, tls=cfg.tls)
        dst_client = AgentClient(cfg.dest_addr, tls=cfg.tls)
        orch = MigrationOrchestrator(cfg, src_client, dst_client, journal_dir=portability_jdir)
        report = orch.assess_portability(
            run_check_only=args.check_only if args.check_only else None,
            run_trial_restore=args.trial_restore if args.trial_restore else None,
        )
        if args.json:
            payload = report.to_dict()
            payload["status"] = (
                report.overall_status.value
                if hasattr(report.overall_status, "value")
                else str(report.overall_status)
            )
            print(json.dumps(payload, indent=2))
        else:
            if render_portability_report is not None:
                print(render_portability_report(report))
            else:
                print(_fallback_render_portability_report(report))
        valid_statuses = (
            PortabilityStatus.VERIFIED,
            PortabilityStatus.UNKNOWN,
            PortabilityStatus.PREPARE,
        )
        st = report.overall_status
        st_val = getattr(st, "value", str(st)).upper()
        is_valid_st = (st in valid_statuses) or (st_val in ("VERIFIED", "UNKNOWN", "PREPARE"))
        return 0 if (is_valid_st and report.compatible) else 2

    if args.subcommand == "migrate":
        cfg = _build_migration_config(args)
        src_client = AgentClient(cfg.source_addr, tls=cfg.tls)
        dst_client = AgentClient(cfg.dest_addr, tls=cfg.tls)
        orch = MigrationOrchestrator(cfg, src_client, dst_client, journal_dir=cfg.journal_dir)
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

    if args.subcommand == "recover":
        tls = TlsConfig(
            enabled=not args.no_tls,
            ca_cert=getattr(args, "tls_ca", None),
            cert_file=getattr(args, "tls_cert", None),
            key_file=getattr(args, "tls_key", None),
        )
        gang_journal = getattr(args, "gang_journal", None)
        if gang_journal:
            from lkmp.gang import GangMigrationCoordinator

            g_path = Path(gang_journal)
            journal = MigrationJournal.load(g_path)
            gang_id = journal.migration_id
            if gang_id.endswith(".gang"):
                gang_id = gang_id[:-5]

            j_dir = g_path.parent
            expected_member_ids = journal.expected_member_ids
            if not expected_member_ids:
                raise ValueError(
                    f"Gang journal {g_path} is missing authoritative member_ids manifest; "
                    "refusing partial gang recovery"
                )
            expected_configs = journal.expected_member_configs or []
            only_unstarted_init = (
                len(journal.entries) == 1
                and journal.entries[0].state == "INIT"
                and journal.entries[0].commit_decision == "PREPARING"
            )
            members = []
            seen_uncreated_init_member = False
            for idx, mid in enumerate(expected_member_ids):
                mf = j_dir / f"{mid}.wal.jsonl"
                if not mf.exists():
                    if only_unstarted_init:
                        seen_uncreated_init_member = True
                        cfg_raw = expected_configs[idx] if idx < len(expected_configs) else None
                    else:
                        raise FileNotFoundError(
                            f"Cannot recover gang {gang_id!r}: required member WAL is missing at {mf} "
                            f"(expected full gang {expected_member_ids})"
                        )
                else:
                    if seen_uncreated_init_member:
                        raise FileNotFoundError(
                            f"Cannot recover gang {gang_id!r}: non-contiguous member WAL missing before {mf} "
                            f"(expected full gang {expected_member_ids})"
                        )
                    mj = MigrationJournal.load(mf)
                    cfg_raw = mj.initial_config_dict or (
                        expected_configs[idx] if idx < len(expected_configs) else None
                    )
                if cfg_raw:
                    m_cfg = config_from_dict(cfg_raw)
                    if getattr(args, "source", None):
                        m_cfg.source_addr = args.source
                    if getattr(args, "dest", None):
                        m_cfg.dest_addr = args.dest
                else:
                    raise ValueError(
                        f"Member journal {mf} does not contain initial migration configuration"
                    )
                client_a = AgentClient(m_cfg.source_addr, tls=tls)
                client_b = AgentClient(m_cfg.dest_addr, tls=tls)
                members.append((m_cfg, client_a, client_b))

            res_gang = GangMigrationCoordinator.recover_from_journal(
                gang_journal_path=g_path,
                members=members,
            )
            if getattr(args, "json", False):
                payload = {
                    "gang_id": res_gang.gang_id,
                    "all_committed": res_gang.all_committed,
                    "atomic_rollback_triggered": res_gang.atomic_rollback_triggered,
                    "partial_commit_error": res_gang.partial_commit_error,
                    "member_results": [asdict(r) for r in res_gang.member_results],
                }
                print(json.dumps(payload, indent=2))
            else:
                print(
                    f"Gang Recovery: {res_gang.gang_id} (All Committed: {res_gang.all_committed}, "
                    f"Rolled Back: {res_gang.atomic_rollback_triggered})"
                )
            return 0 if (res_gang.all_committed or res_gang.atomic_rollback_triggered) else 2

        client_a = AgentClient(args.source, tls=tls)
        client_b = AgentClient(args.dest, tls=tls)
        res = MigrationOrchestrator.recover_from_journal(Path(args.journal), client_a, client_b)
        payload = asdict(res)
        payload["final_state"] = res.final_state.value
        payload["state_history"] = [s.value for s in res.state_history]
        print(json.dumps(payload, indent=2))
        return 0 if (res.success or res.rolled_back) else 2

    if args.subcommand == "acceptance":
        from lkmp.acceptance import render_acceptance_report, run_acceptance_matrix

        results = run_acceptance_matrix(backend=args.backend)
        all_passed = all(r.passed for r in results)
        if args.json:
            payload = [asdict(r) for r in results]
            print(json.dumps(payload, indent=2))
        else:
            print(render_acceptance_report(results))
        return 0 if all_passed else 1

    return 1


_ORIGINAL_MAIN_CODE = main.__code__


if __name__ == "__main__":
    sys.exit(main())
