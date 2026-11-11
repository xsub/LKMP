"""Unit and Acceptance Verification Suite for Stateful Live Migration.

Asserts process-tree invariants across COLD, PRE_COPY, and LAZY strategies
as well as transactional 2PC fault injection boundaries.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lkmp.acceptance import (
    AcceptanceScenarioResult,
    DeterministicWorkloadService,
    WorkloadClient,
    render_acceptance_report,
    run_acceptance_matrix,
    run_acceptance_scenario,
)
from lkmp.config import MigrationStrategy
import socket


class TestLiveMigrationAcceptanceSuite(unittest.TestCase):
    """Rigorous acceptance test suite proving live migration process-tree invariants."""

    def _assert_scenario_invariants(self, res: AcceptanceScenarioResult) -> None:
        """Helper to assert all multi-process invariants for a scenario result."""
        self.assertTrue(
            res.passed,
            f"Scenario '{res.scenario_name}' failed to pass: {res.error_logs}",
        )
        self.assertTrue(
            res.same_tcp_connection_preserved,
            f"Persistent connection lost in '{res.scenario_name}'",
        )
        self.assertEqual(res.requests_before, 10)
        self.assertEqual(res.requests_during_and_after, 10)
        self.assertTrue(
            res.sequence_contiguous_no_loss_or_dup,
            f"Sequence lost or duplicated in '{res.scenario_name}'",
        )
        self.assertTrue(
            res.prng_trajectory_exact_match,
            f"PRNG trajectory deviation in '{res.scenario_name}'",
        )
        self.assertEqual(
            res.file_records_verified,
            20,
            f"Expected 20 fsynced state records, got {res.file_records_verified} in '{res.scenario_name}'",
        )
        self.assertTrue(
            res.all_children_resumed,
            f"Not all child workers resumed active in '{res.scenario_name}'",
        )
        self.assertTrue(
            res.no_dual_execution_observed,
            f"Dual execution observed in '{res.scenario_name}'",
        )
        self.assertGreaterEqual(
            res.client_observed_blackout_ms,
            0.0,
            f"Invalid blackout ms in '{res.scenario_name}'",
        )
        self.assertGreaterEqual(
            res.criu_restore_duration_ms,
            0.0,
            f"Invalid restore duration ms in '{res.scenario_name}'",
        )

    def test_01_cold_migration_commit(self) -> None:
        """1. COLD migration commit cutover with 100% TCP preservation and PRNG continuity."""
        res = run_acceptance_scenario(
            scenario_name="1. COLD Live Migration Commit Cutover",
            strategy=MigrationStrategy.COLD,
            injected_fault=None,
        )
        self._assert_scenario_invariants(res)
        self.assertTrue(res.source_tree_terminated_on_commit)
        self.assertFalse(res.source_tree_resumed_on_rollback)

    def test_02_pre_copy_migration_commit(self) -> None:
        """2. PRE_COPY iterative pre-dump live migration commit cutover."""
        res = run_acceptance_scenario(
            scenario_name="2. PRE_COPY Live Migration Commit Cutover",
            strategy=MigrationStrategy.PRE_COPY,
            injected_fault=None,
        )
        self._assert_scenario_invariants(res)
        self.assertTrue(res.source_tree_terminated_on_commit)
        self.assertFalse(res.source_tree_resumed_on_rollback)

    def test_03_lazy_migration_commit(self) -> None:
        """3. LAZY userfaultfd post-copy live migration commit cutover."""
        res = run_acceptance_scenario(
            scenario_name="3. LAZY Live Migration Commit Cutover",
            strategy=MigrationStrategy.LAZY,
            injected_fault=None,
        )
        self._assert_scenario_invariants(res)
        self.assertTrue(res.source_tree_terminated_on_commit)
        self.assertFalse(res.source_tree_resumed_on_rollback)

    def test_04_fault_final_dump_rollback(self) -> None:
        """4. Fault injection at FINAL_DUMP boundary -> transactional rollback to Source A."""
        res = run_acceptance_scenario(
            scenario_name="4. Fault at FINAL_DUMP Boundary (Rollback to Source A)",
            strategy=MigrationStrategy.COLD,
            injected_fault="FINAL_DUMP",
        )
        self._assert_scenario_invariants(res)
        self.assertFalse(res.source_tree_terminated_on_commit)
        self.assertTrue(res.source_tree_resumed_on_rollback)

    def test_05_fault_transfer_attestation_rollback(self) -> None:
        """5. Fault injection at TRANSFER (attestation bit-rot tamper detection -> rollback)."""
        res = run_acceptance_scenario(
            scenario_name="5. Fault at TRANSFER Boundary (Corrupted Image Rollback)",
            strategy=MigrationStrategy.COLD,
            injected_fault="TRANSFER",
        )
        self._assert_scenario_invariants(res)
        self.assertFalse(res.source_tree_terminated_on_commit)
        self.assertTrue(res.source_tree_resumed_on_rollback)

    def test_06_fault_restore_dest_rollback(self) -> None:
        """6. Fault injection at RESTORE on Destination B -> orphaned B cleanup & rollback to A."""
        res = run_acceptance_scenario(
            scenario_name="6. Fault at RESTORE Boundary on Destination B (Rollback)",
            strategy=MigrationStrategy.COLD,
            injected_fault="RESTORE",
        )
        self._assert_scenario_invariants(res)
        self.assertFalse(res.source_tree_terminated_on_commit)
        self.assertTrue(res.source_tree_resumed_on_rollback)

    def test_07_fault_verify_dest_rollback(self) -> None:
        """7. Fault injection at VERIFY on Destination B -> destination killed & rollback to A."""
        res = run_acceptance_scenario(
            scenario_name="7. Fault at VERIFY Boundary on Destination B (Rollback)",
            strategy=MigrationStrategy.COLD,
            injected_fault="VERIFY",
        )
        self._assert_scenario_invariants(res)
        self.assertFalse(res.source_tree_terminated_on_commit)
        self.assertTrue(res.source_tree_resumed_on_rollback)

    def test_08_crash_after_restore_wal_recovery(self) -> None:
        """8. Controller Crash after restore + WAL recovery -> discovers orphaned B PID & rolls back."""
        res = run_acceptance_scenario(
            scenario_name="8. Controller Crash After Restore + WAL Recovery",
            strategy=MigrationStrategy.COLD,
            injected_fault="CRASH_AFTER_RESTORE",
        )
        self._assert_scenario_invariants(res)
        self.assertFalse(res.source_tree_terminated_on_commit)
        self.assertTrue(res.source_tree_resumed_on_rollback)

    def test_09_coordinated_gang_migration_stopped_readiness_abort(self) -> None:
        """9. Coordinated Gang Migration: Member 2 fails verify_restored_stopped -> abort and rollback."""
        res = run_acceptance_scenario(
            scenario_name="9. Coordinated Gang Migration (Stopped-Readiness Abort)",
            strategy=MigrationStrategy.PRE_COPY,
            injected_fault="GANG_MEMBER_2_FAIL",
        )
        self._assert_scenario_invariants(res)
        self.assertFalse(res.source_tree_terminated_on_commit)
        self.assertTrue(res.source_tree_resumed_on_rollback)

    def test_10_coordinated_gang_migration_mid_commit_fault_roll_forward(self) -> None:
        """10. Coordinated Gang Migration Mid-Commit Fault: roll forward recovery to Destination B."""
        res = run_acceptance_scenario(
            scenario_name="10. Coordinated Gang Migration Mid-Commit Fault (Roll-Forward)",
            strategy=MigrationStrategy.PRE_COPY,
            injected_fault="GANG_MID_COMMIT_FAULT",
        )
        self._assert_scenario_invariants(res)
        self.assertTrue(res.source_tree_terminated_on_commit)
        self.assertFalse(res.source_tree_resumed_on_rollback)

    def test_11_active_tcp_and_file_write_surviving_forced_controller_restart(self) -> None:
        """11. Active TCP + File Write Surviving Forced Controller Restart."""
        res = run_acceptance_scenario(
            scenario_name="11. Active TCP + File Write Surviving Forced Controller Restart",
            strategy=MigrationStrategy.COLD,
            injected_fault="CONTROLLER_RESTART_MID_CUTOVER",
        )
        self._assert_scenario_invariants(res)
        self.assertTrue(res.source_tree_terminated_on_commit)
        self.assertFalse(res.source_tree_resumed_on_rollback)
        self.assertGreater(res.client_observed_blackout_ms, 0.0)

    def test_12_same_host_two_vm_cow_fast_path(self) -> None:
        """12. Same-Host Two-VM CoW Snapshot Fast Path."""
        res = run_acceptance_scenario(
            scenario_name="12. Same-Host Two-VM CoW Snapshot Fast Path",
            strategy=MigrationStrategy.COLD,
            injected_fault="SAME_HOST_COW",
        )
        self._assert_scenario_invariants(res)
        self.assertTrue(res.source_tree_terminated_on_commit)
        self.assertFalse(res.source_tree_resumed_on_rollback)
        self.assertGreater(res.client_observed_blackout_ms, 0.0)

    def test_13_full_acceptance_matrix_and_report_rendering(self) -> None:
        """Run full 12-scenario matrix and assert formatted report rendering."""
        results = run_acceptance_matrix(backend="auto")
        self.assertEqual(len(results), 12)
        report = render_acceptance_report(results)
        self.assertIn("LKMP STATEFUL MULTI-PROCESS LIVE MIGRATION ACCEPTANCE SUITE REPORT", report)
        self.assertIn("Total Scenarios: 12 | Passed: 12 | Failed: 0", report)
        self.assertIn("Blackout(ms)", report)
        for res in results:
            self._assert_scenario_invariants(res)

    def test_deterministic_workload_service_unit_lifecycle(self) -> None:
        """Unit test for DeterministicWorkloadService lifecycle, PRNG stepping, and quiesce/resume."""
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "unit_state.log"
            c_sock, s_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
            client = WorkloadClient(c_sock)

            srv = DeterministicWorkloadService(
                workload_id="unit-srv",
                state_log_path=log_path,
                stream_sock=s_sock,
                num_children=2,
            )
            root_pid = srv.start()
            self.assertIsNotNone(root_pid)
            self.assertTrue(srv.is_alive())
            self.assertEqual(len(srv.children_pids), 2)

            # Test 3 requests
            ack1 = client.send_request(1, "unit1")
            self.assertEqual(ack1.seq, 1)
            self.assertEqual(ack1.counter, 1)
            self.assertEqual(ack1.child_count, 2)

            ack2 = client.send_request(2, "unit2")
            self.assertEqual(ack2.seq, 2)
            self.assertEqual(ack2.counter, 2)

            # Test quiesce and checkpoint
            srv.quiesce()
            img_dir = Path(tmp) / "chk"
            cp_meta = srv.checkpoint(img_dir)
            self.assertEqual(cp_meta["counter"], 2)

            # Test resume
            srv.resume()
            ack3 = client.send_request(3, "unit3")
            self.assertEqual(ack3.seq, 3)
            self.assertEqual(ack3.counter, 3)

            client.close()
            srv.terminate()
            try:
                s_sock.close()
            except OSError:
                pass
            self.assertFalse(srv.is_alive())


if __name__ == "__main__":
    unittest.main()
