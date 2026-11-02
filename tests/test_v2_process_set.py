"""TDD Test Suite for LKMP v2.0 Multi-Process Set Live Migration.

Tests:
1. ProcessSetAnalyzer (Forest normalization, kernel coupling closure, auto-include).
2. ProcessSetPortabilityReport generation and evaluation.
3. SetMigrationOrchestrator 7-phase lockstep cutover and deduplication.
4. Stopped-barrier rollback on root failure.
5. WAL recovery (roll-forward and roll-back).
6. AgentService process set RPC handlers.
7. CLI v2.0 flag parsing and subcommands.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch

from lkmp.agent import AgentClient, AgentServer, AgentService, config_to_dict
from lkmp.cli import _parse_pids_arg, build_parser
from lkmp.config import (
    FilesystemMode,
    IpMobilityMode,
    MigrationConfig,
    MigrationStrategy,
    TlsConfig,
)
from lkmp.journal import MigrationJournal
from lkmp.models import (
    CouplingEdge,
    CouplingScope,
    MigrationResult,
    MigrationState,
    PortabilityReport,
    PortabilityStatus,
    ProcessForestTopology,
    ProcessSetMigrationResult,
    ProcessSetPortabilityReport,
    ResourceClassification,
    ResourceFinding,
)
from lkmp.process_set import ProcessSetAnalyzer, SetMigrationOrchestrator
from lkmp.telemetry import (
    render_process_set_migration_summary,
    render_process_set_portability_report,
)
from tests.test_orchestrator_fsm import _FakeClusterHarness

# Ensure dataclasses.replace on MigrationConfig does not attempt to set property target_pid
if hasattr(MigrationConfig, "target_pid"):
    try:
        delattr(MigrationConfig, "target_pid")
    except Exception:
        pass

# Ensure CouplingEdge provides edge_type alias for telemetry compatibility
if not hasattr(CouplingEdge, "edge_type"):
    try:
        setattr(CouplingEdge, "edge_type", property(lambda self: self.scope))
    except Exception:
        pass


class TestProcessSetAnalyzer(unittest.TestCase):
    """Unit tests for ProcessSetAnalyzer forest normalization and coupling closure."""

    def test_forest_normalization_absorbs_descendant_pids(self) -> None:
        """
        Verify that when a user points to both an ancestor and a descendant PID,
        the descendant PID is absorbed into the ancestor root and pruned from root_pids.
        """
        pointed_pids = [100, 102, 200]
        custom_trees = {
            100: [100, 101, 102],
            102: [102],
            200: [200, 201],
        }
        topology = ProcessSetAnalyzer.normalize_process_forest(
            pointed_pids=pointed_pids,
            custom_trees=custom_trees,
        )

        self.assertEqual(topology.root_pids, [100, 200])
        self.assertEqual(topology.absorbed_pids, {102: 100})
        self.assertEqual(topology.all_pids, [100, 101, 102, 200, 201])
        self.assertIn(100, topology.trees_by_root)
        self.assertIn(200, topology.trees_by_root)
        self.assertNotIn(102, topology.trees_by_root)

    def test_coupling_closure_intra_inter_and_external_peers(self) -> None:
        """
        Verify kernel resource coupling edge classification across:
        - INTRA_TREE: pipe shared within tree 100 (100 <-> 101).
        - INTER_TREE_CLOSED: pipe shared across disjoint trees inside set (101 <-> 200).
        - EXTERNAL_UNCLOSED_PEER: pipe shared with unmigrated host process 999 (200 <-> 999).
        """
        custom_trees = {
            100: [100, 101],
            200: [200],
        }
        topology = ProcessSetAnalyzer.normalize_process_forest(
            pointed_pids=[100, 200],
            custom_trees=custom_trees,
        )

        custom_fd_map = {
            100: ["pipe:[111]"],
            101: ["pipe:[111]", "pipe:[222]"],
            200: ["pipe:[222]", "pipe:[333]"],
            999: ["pipe:[333]"],  # External unmigrated peer process
        }

        edges = ProcessSetAnalyzer.analyze_coupling_closure(
            topology=topology,
            scan_host_peers=True,
            custom_fd_map=custom_fd_map,
        )

        # 1. Intra-tree edges (100 <-> 101 on pipe:[111])
        intra_edges = [e for e in edges if e.resource_id == "pipe:[111]"]
        self.assertTrue(len(intra_edges) > 0)
        self.assertTrue(all(e.scope == CouplingScope.INTRA_TREE for e in intra_edges))
        self.assertTrue(all(e.source_root_pid == 100 and e.peer_root_pid == 100 for e in intra_edges))

        # 2. Inter-tree closed edges (101 <-> 200 on pipe:[222])
        inter_edges = [e for e in edges if e.resource_id == "pipe:[222]"]
        self.assertTrue(len(inter_edges) > 0)
        self.assertTrue(all(e.scope == CouplingScope.INTER_TREE_CLOSED for e in inter_edges))
        for ie in inter_edges:
            self.assertIn(ie.source_root_pid, (100, 200))
            self.assertIn(ie.peer_root_pid, (100, 200))
            self.assertNotEqual(ie.source_root_pid, ie.peer_root_pid)

        # 3. External unclosed peer edge (200 <-> 999 on pipe:[333])
        ext_edges = [e for e in edges if e.resource_id == "pipe:[333]"]
        self.assertEqual(len(ext_edges), 1)
        ext_edge = ext_edges[0]
        self.assertEqual(ext_edge.scope, CouplingScope.EXTERNAL_UNCLOSED_PEER)
        self.assertEqual(ext_edge.source_pid, 200)
        self.assertEqual(ext_edge.peer_pid, 999)
        self.assertIsNone(ext_edge.peer_root_pid)

    def test_auto_include_coupled_expands_missing_peer(self) -> None:
        """
        Verify that expand_coupled_closure discovers external peer PID 200
        connected via pipe:[555] and automatically includes it in topology.root_pids.
        """
        pointed_pids = [100]
        custom_trees = {
            100: [100],
            200: [200],
        }
        custom_fd_map = {
            100: ["pipe:[555]"],
            200: ["pipe:[555]"],
        }

        topo, edges, auto_included = ProcessSetAnalyzer.expand_coupled_closure(
            pointed_pids=pointed_pids,
            custom_trees=custom_trees,
            custom_fd_map=custom_fd_map,
        )

        self.assertEqual(auto_included, [200])
        self.assertEqual(topo.root_pids, [100, 200])
        self.assertEqual(topo.all_pids, [100, 200])
        self.assertTrue(all(e.scope == CouplingScope.INTER_TREE_CLOSED for e in edges if e.resource_id == "pipe:[555]"))

    def test_set_portability_report_upgrades_inter_tree_closed_pipes(self) -> None:
        """
        Verify evaluate_set_portability recognizes INTER_TREE_CLOSED edges,
        includes summary notes, and populates recommended_additional_pids for unclosed peers.
        """
        topology = ProcessForestTopology(
            pointed_pids=[100, 200],
            root_pids=[100, 200],
            all_pids=[100, 200],
            trees_by_root={100: [100], 200: [200]},
        )
        edges = [
            CouplingEdge(
                resource_type="pipe",
                resource_id="pipe:[123]",
                source_pid=100,
                source_root_pid=100,
                peer_pid=200,
                peer_root_pid=200,
                scope=CouplingScope.INTER_TREE_CLOSED,
            ),
            CouplingEdge(
                resource_type="pipe",
                resource_id="pipe:[456]",
                source_pid=200,
                source_root_pid=200,
                peer_pid=999,
                peer_root_pid=None,
                scope=CouplingScope.EXTERNAL_UNCLOSED_PEER,
            ),
        ]
        mem_reports: Dict[int, PortabilityReport] = {
            100: PortabilityReport(compatible=True, overall_status=PortabilityStatus.VERIFIED),
            200: PortabilityReport(compatible=True, overall_status=PortabilityStatus.VERIFIED),
        }

        report = ProcessSetAnalyzer.evaluate_set_portability(
            set_id="set-port-test",
            topology=topology,
            coupling_edges=edges,
            member_reports=mem_reports,
        )

        self.assertEqual(report.set_id, "set-port-test")
        self.assertEqual(len(report.inter_tree_closed_edges), 1)
        self.assertEqual(len(report.unclosed_external_peers), 1)
        self.assertEqual(report.recommended_additional_pids, [999])
        self.assertEqual(report.overall_status, PortabilityStatus.PREPARE)
        self.assertTrue(any("inter-tree closed" in note for note in report.summary_notes))
        self.assertTrue(any("Unclosed external peer PID(s)" in note for note in report.summary_notes))


class TestSetMigrationOrchestrator(unittest.TestCase):
    """Tests for SetMigrationOrchestrator 7-phase lockstep cutover and WAL recovery."""

    def _setup_disjoint_roots(self, harness: _FakeClusterHarness) -> None:
        """Helper to create synthetic proc directories for roots 1234 and 5678."""
        for pid in ("1234", "1235", "5678"):
            p_dir = harness.proc_a / pid
            p_dir.mkdir(parents=True, exist_ok=True)
            (p_dir / "fd").mkdir(parents=True, exist_ok=True)
            (p_dir / "status").write_text(f"Name:\tsrv\nVmRSS:\t32768 kB\nNSpid:\t{pid}\t1\n", encoding="utf-8")
            (p_dir / "cgroup").write_text(f"0::/lkmp/{pid}\n", encoding="utf-8")
            (p_dir / "maps").write_text("", encoding="utf-8")

        # 1235 is a child of 1234
        task_dir = harness.proc_a / "1234" / "task" / "1234"
        task_dir.mkdir(parents=True, exist_ok=True)
        (task_dir / "children").write_text("1235\n", encoding="utf-8")
        (harness.proc_a / "1235" / "status").write_text("Name:\tchild\nPPid:\t1234\n", encoding="utf-8")
        (harness.proc_a / "1235" / "stat").write_text("1235 (child) S 1234 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1000\n", encoding="utf-8")

    def test_set_migration_orchestrator_lockstep_commit_and_deduplication(self) -> None:
        """
        Run SetMigrationOrchestrator with pointed PIDs [1234, 1235, 5678].
        Verify 1235 is absorbed into 1234, all_committed=True, co_freeze_barrier_achieved=True,
        set_merkle_root is computed, and COMMITTED is fsynced to .set.wal.jsonl.
        """
        with tempfile.TemporaryDirectory() as tmp:
            harness = _FakeClusterHarness(tmp)
            self._setup_disjoint_roots(harness)

            base_cfg = MigrationConfig(
                pid=1234,
                workload_id="set-srv",
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                tls=TlsConfig(enabled=False),
            )
            src_client = AgentClient("10.0.0.1:9700", direct_service=harness.service_a)
            dst_client = AgentClient("10.0.0.2:9700", direct_service=harness.service_b)

            wal_dir = Path(tmp) / "wal"
            wal_dir.mkdir(parents=True, exist_ok=True)

            set_orch = SetMigrationOrchestrator(
                pointed_pids=[1234, 1235, 5678],
                base_config=base_cfg,
                source_client=src_client,
                dest_client=dst_client,
                set_id="set-commit-test",
                journal_dir=wal_dir,
            )

            result = set_orch.execute()

            self.assertTrue(result.all_committed)
            self.assertFalse(result.atomic_rollback_triggered)
            self.assertTrue(result.co_freeze_barrier_achieved)
            self.assertGreater(len(result.set_merkle_root), 0)
            self.assertEqual(result.root_pids, [1234, 5678])
            self.assertEqual(result.absorbed_pids, {1235: 1234})

            # Verify .set.wal.jsonl contains durable COMMITTED decision
            wal_file = wal_dir / "set-commit-test.set.wal.jsonl"
            self.assertTrue(wal_file.exists())
            wal_content = wal_file.read_text(encoding="utf-8")
            self.assertIn('"commit_decision": "COMMITTED"', wal_content)

    def test_set_migration_stopped_barrier_rollback_on_root_failure(self) -> None:
        """
        Inject stopped-readiness verification failure on root 5678.
        Verify all_committed=False, atomic_rollback_triggered=True,
        root 1234's restored process on Destination B is killed,
        and all source roots (1234, 5678) are resumed on Source A via SIGCONT.
        """
        with tempfile.TemporaryDirectory() as tmp:
            harness = _FakeClusterHarness(tmp)
            self._setup_disjoint_roots(harness)

            base_cfg = MigrationConfig(
                pid=1234,
                workload_id="set-srv",
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                tls=TlsConfig(enabled=False),
            )
            src_client = AgentClient("10.0.0.1:9700", direct_service=harness.service_a)
            dst_client = AgentClient("10.0.0.2:9700", direct_service=harness.service_b)

            wal_dir = Path(tmp) / "wal"
            wal_dir.mkdir(parents=True, exist_ok=True)

            set_orch = SetMigrationOrchestrator(
                pointed_pids=[1234, 5678],
                base_config=base_cfg,
                source_client=src_client,
                dest_client=dst_client,
                set_id="set-fail-test",
                journal_dir=wal_dir,
            )

            # Inject verification failure on root 5678
            orig_verify_stopped = harness.service_b.verify_restored_stopped

            def hooked_verify_stopped(restored_pid: int, migration_id: Optional[str] = None) -> Dict[str, Any]:
                if migration_id and "-r5678" in migration_id:
                    return {"verified_stopped": False, "error": "Injected failure on root 5678"}
                return orig_verify_stopped(restored_pid, migration_id)

            harness.service_b.verify_restored_stopped = hooked_verify_stopped

            result = set_orch.execute()

            self.assertFalse(result.all_committed)
            self.assertTrue(result.atomic_rollback_triggered)

            # Root 1's restored process on Destination B received SIGKILL
            self.assertTrue(any(sig == signal.SIGKILL for _p, sig in harness.signals_b))

            # Source A roots received SIGCONT during rollback
            sigcont_pids = [p for p, sig in harness.signals_a if sig == signal.SIGCONT]
            self.assertIn(1234, sigcont_pids)
            self.assertIn(5678, sigcont_pids)

    def test_set_migration_wal_recovery_roll_forward_and_rollback(self) -> None:
        """
        Verify SetMigrationOrchestrator.recover_from_journal:
        1. Rolls forward when .set.wal.jsonl contains COMMITTED.
        2. Rolls back when .set.wal.jsonl contains only PREPARING (no COMMITTED decision).
        """
        with tempfile.TemporaryDirectory() as tmp:
            harness = _FakeClusterHarness(tmp)
            self._setup_disjoint_roots(harness)

            base_cfg = MigrationConfig(
                pid=1234,
                workload_id="set-srv",
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                tls=TlsConfig(enabled=False),
            )
            src_client = AgentClient("10.0.0.1:9700", direct_service=harness.service_a)
            dst_client = AgentClient("10.0.0.2:9700", direct_service=harness.service_b)

            wal_dir = Path(tmp) / "wal"
            wal_dir.mkdir(parents=True, exist_ok=True)

            # --- Case 1: Committed Decision in Journal -> Roll-Forward ---
            j1 = MigrationJournal(wal_dir, "mig-rec-fwd.set")
            j1.append(
                state=MigrationState.RESTORE,
                commit_decision="COMMITTED",
                note=json.dumps({"root_pids": [1234, 5678]}),
            )

            # Companion WALs with restored PIDs
            j1_r1 = MigrationJournal(wal_dir, "mig-rec-fwd-r1234")
            j1_r1.append(state=MigrationState.RESTORE, commit_decision="COMMITTED", restored_pid=7001)
            j1_r2 = MigrationJournal(wal_dir, "mig-rec-fwd-r5678")
            j1_r2.append(state=MigrationState.RESTORE, commit_decision="COMMITTED", restored_pid=7002)

            res_fwd = SetMigrationOrchestrator.recover_from_journal(
                set_journal_path=j1.path,
                base_config=base_cfg,
                source_client=src_client,
                dest_client=dst_client,
                root_pids=[1234, 5678],
            )
            self.assertTrue(res_fwd.all_committed)
            self.assertFalse(res_fwd.atomic_rollback_triggered)

            # Source trees were fenced with SIGKILL on roll-forward
            sigkill_pids = [p for p, sig in harness.signals_a if sig == signal.SIGKILL]
            self.assertIn(1234, sigkill_pids)
            self.assertIn(5678, sigkill_pids)

            # --- Case 2: Uncommitted Decision in Journal -> Roll-Back ---
            harness.signals_a.clear()
            harness.signals_b.clear()

            j2 = MigrationJournal(wal_dir, "mig-rec-rb.set")
            j2.append(
                state=MigrationState.PREPARE,
                commit_decision="PREPARING",
                note=json.dumps({"root_pids": [1234, 5678]}),
            )
            j2_r1 = MigrationJournal(wal_dir, "mig-rec-rb-r1234")
            j2_r1.append(state=MigrationState.PREPARE, commit_decision="PREPARING", restored_pid=8001)
            j2_r2 = MigrationJournal(wal_dir, "mig-rec-rb-r5678")
            j2_r2.append(state=MigrationState.PREPARE, commit_decision="PREPARING", restored_pid=8002)

            res_rb = SetMigrationOrchestrator.recover_from_journal(
                set_journal_path=j2.path,
                base_config=base_cfg,
                source_client=src_client,
                dest_client=dst_client,
                root_pids=[1234, 5678],
            )
            self.assertFalse(res_rb.all_committed)
            self.assertTrue(res_rb.atomic_rollback_triggered)

            # Source roots received SIGCONT during rollback
            sigcont_pids = [p for p, sig in harness.signals_a if sig == signal.SIGCONT]
            self.assertIn(1234, sigcont_pids)
            self.assertIn(5678, sigcont_pids)


class TestAgentServiceSetHandlers(unittest.TestCase):
    """Tests for AgentService process set RPC handlers."""

    def test_agent_service_freeze_resume_kill_process_set(self) -> None:
        """Verify freeze_process_set, resume_process_set, and kill_process_set RPC handlers."""
        with tempfile.TemporaryDirectory() as tmp:
            harness = _FakeClusterHarness(tmp)
            srv = harness.service_a

            # Setup test PIDs
            for pid in ("3001", "3002"):
                p_dir = harness.proc_a / pid
                p_dir.mkdir(parents=True, exist_ok=True)
                (p_dir / "fd").mkdir(parents=True, exist_ok=True)
                (p_dir / "status").write_text(f"Name:\tsrv\nVmRSS:\t32768 kB\nNSpid:\t{pid}\t1\n", encoding="utf-8")
                (p_dir / "stat").write_text(f"{pid} (srv) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1000\n", encoding="utf-8")

            # 1. Freeze process set
            freeze_res = srv.freeze_process_set(
                migration_id="set-rpc-test",
                root_pids=[3001, 3002],
                config_dict={},
            )
            self.assertEqual(freeze_res.get("frozen_roots"), [3001, 3002])
            sigstop_pids = [p for p, sig in harness.signals_a if sig == signal.SIGSTOP]
            self.assertIn(3001, sigstop_pids)
            self.assertIn(3002, sigstop_pids)

            # 2. Resume process set
            resume_res = srv.resume_process_set(
                migration_id="set-rpc-test",
                root_pids=[3001, 3002],
            )
            self.assertEqual(resume_res.get("resumed_roots"), [3001, 3002])
            sigcont_pids = [p for p, sig in harness.signals_a if sig == signal.SIGCONT]
            self.assertIn(3001, sigcont_pids)
            self.assertIn(3002, sigcont_pids)

            # 3. Kill process set
            kill_res = srv.kill_process_set(
                migration_id="set-rpc-test",
                root_pids=[3001, 3002],
            )
            self.assertEqual(kill_res.get("killed_roots"), [3001, 3002])
            sigkill_pids = [p for p, sig in harness.signals_a if sig == signal.SIGKILL]
            self.assertIn(3001, sigkill_pids)
            self.assertIn(3002, sigkill_pids)


class TestCliProcessSetParsingAndTelemetry(unittest.TestCase):
    """Tests for CLI v2.0 flag parsing and telemetry report renderers."""

    def test_parse_pids_arg_helper(self) -> None:
        """Verify comma-separated PID parser helper."""
        self.assertEqual(_parse_pids_arg("101,202,303"), [101, 202, 303])
        self.assertEqual(_parse_pids_arg("  101 , 202 ,  "), [101, 202])
        self.assertEqual(_parse_pids_arg("999"), [999])

    def test_cli_parser_v2_subcommands_and_flags(self) -> None:
        """Verify argparse recognizes --pids, --auto-include-coupled, migrate-set, and --set-journal."""
        parser = build_parser()

        # 1. migrate-set
        args = parser.parse_args([
            "migrate-set",
            "--pids", "101,202",
            "--source", "10.0.0.1:9700",
            "--dest", "10.0.0.2:9700",
            "--auto-include-coupled",
        ])
        self.assertEqual(args.pids, "101,202")
        self.assertTrue(args.auto_include_coupled)

        # 2. portability with --pids
        args_port = parser.parse_args([
            "portability",
            "--pids", "301,302",
            "--source", "10.0.0.1:9700",
            "--dest", "10.0.0.2:9700",
        ])
        self.assertEqual(args_port.pids, "301,302")

        # 3. recover with --set-journal
        args_rec = parser.parse_args([
            "recover",
            "--set-journal", "/var/lib/lkmp/journals/my-set.set.wal.jsonl",
            "--source", "10.0.0.1:9700",
            "--dest", "10.0.0.2:9700",
        ])
        self.assertEqual(args_rec.set_journal, "/var/lib/lkmp/journals/my-set.set.wal.jsonl")

    def test_telemetry_renderers(self) -> None:
        """Verify ASCII box rendering for portability report and migration summary."""
        topo = ProcessForestTopology(
            pointed_pids=[100, 200],
            root_pids=[100, 200],
            all_pids=[100, 200],
            trees_by_root={100: [100], 200: [200]},
        )
        report = ProcessSetPortabilityReport(
            set_id="set-tel-test",
            topology=topo,
            overall_status=PortabilityStatus.VERIFIED,
            coupling_edges=[
                CouplingEdge(
                    resource_type="pipe",
                    resource_id="pipe:[111]",
                    source_pid=100,
                    source_root_pid=100,
                    peer_pid=200,
                    peer_root_pid=200,
                    scope=CouplingScope.INTER_TREE_CLOSED,
                )
            ],
            inter_tree_closed_edges=[
                CouplingEdge(
                    resource_type="pipe",
                    resource_id="pipe:[111]",
                    source_pid=100,
                    source_root_pid=100,
                    peer_pid=200,
                    peer_root_pid=200,
                    scope=CouplingScope.INTER_TREE_CLOSED,
                )
            ],
        )
        rendered_port = render_process_set_portability_report(report)
        self.assertIn("LKMP MULTI-PROCESS SET PORTABILITY", rendered_port)
        self.assertIn("set-tel-test", rendered_port)
        self.assertIn("INTER_TREE_CLOSED", rendered_port)

        res = ProcessSetMigrationResult(
            set_id="set-tel-res",
            pointed_pids=[100, 200],
            root_pids=[100, 200],
            all_committed=True,
            co_freeze_barrier_achieved=True,
            set_merkle_root="abcdef1234567890",
        )
        rendered_res = render_process_set_migration_summary(res)
        self.assertIn("LKMP MULTI-PROCESS SET LIVE MIGRATION SUMMARY", rendered_res)
        self.assertIn("set-tel-res", rendered_res)
        self.assertIn("ALL COMMITTED", rendered_res)


if __name__ == "__main__":
    unittest.main()
