"""Regression tests directly reproducing every finding from the v0.3.0 external Principal/Staff audit."""

from __future__ import annotations

import errno
import json
import os
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple
from unittest.mock import patch

from lkmp.agent import AgentClient, config_to_dict
from lkmp.attestation import CheckpointAttestor, generate_ephemeral_key_hex
from lkmp.config import (
    FilesystemMode,
    IpMobilityMode,
    MigrationConfig,
    MigrationStrategy,
    TlsConfig,
)
from lkmp.drivers.base import WorkloadKind
from lkmp.drivers.microvm import MicroVmDriver
from lkmp.drivers.oci_runtime import OciContainerDriver
from lkmp.drivers.qemu_qmp import QemuQmpDriver
from lkmp.gang import GangMigrationCoordinator
from lkmp.journal import MigrationJournal
from lkmp.models import MigrationState
from lkmp.orchestrator import MigrationOrchestrator
from lkmp.pki import generate_mtls_pki
from tests.test_orchestrator_fsm import _FakeClusterHarness


class TestExternalAuditReproductions(unittest.TestCase):
    """Exact reproductions and safety assertions for all items in the external v0.3.0 technical audit."""

    def test_item_0_manifest_in_includes_scripts_and_tests_for_sdist(self) -> None:
        """Verify MANIFEST.in grafts scripts/ and tests/ so sdist tarballs run the full test suite."""
        repo_root = Path(__file__).resolve().parent.parent
        manifest_path = repo_root / "MANIFEST.in"
        self.assertTrue(manifest_path.exists(), "MANIFEST.in must exist at repository root")
        content = manifest_path.read_text(encoding="utf-8")
        self.assertIn("graft scripts", content)
        self.assertIn("graft tests", content)

    def test_finding_1_stopped_target_crash_recovery_wakes_destination_single_and_gang(self) -> None:
        """
        Finding 1: Crash right after recording SWITCHOVER (COMMIT_DECIDED) BEFORE `claim_ip_and_resume`
        reaches Destination B.
        - `verify_process` MUST report `healthy=False, still_stopped=True` while B is in `'T'`.
        - `recover_from_journal()` MUST wake B (`SIGCONT`), confirm B transitions to `'S'`, and reap Source A.
        """
        with tempfile.TemporaryDirectory() as tmp:
            harness = _FakeClusterHarness(tmp)
            stat_1234 = harness.proc_a / "1234" / "stat"
            stat_1234.write_text(
                "1234 (server) S 1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 11111 0\n",
                encoding="utf-8",
            )
            journal_dir = Path(tmp) / "journals"
            journal_dir.mkdir(parents=True, exist_ok=True)
            src_cli = AgentClient("10.0.0.1:9700", direct_service=harness.service_a)
            dst_cli = AgentClient("10.0.0.2:9700", direct_service=harness.service_b)

            cfg = MigrationConfig(
                pid=1234,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                fs_mode=FilesystemMode.SHARED,
                ip_mobility=IpMobilityMode.NONE,
                journal_dir=str(journal_dir),
            )
            orch = MigrationOrchestrator(
                cfg,
                src_cli,
                dst_cli,
                migration_id="audit-f1-single",
                require_persistent_journal=False,
            )
            prep = orch.execute_prepare_phase(defer_switchover_until_commit=True)
            self.assertTrue(prep.success)
            restored_pid = int(prep.restored_pid or 0)
            self.assertEqual(restored_pid, 5678)

            # Target B is currently stopped ('T')
            chk_stopped = harness.service_b.verify_process(
                restored_pid=restored_pid,
                health_check_cmd=None,
                migration_id="audit-f1-single",
            )
            self.assertFalse(chk_stopped["healthy"])
            self.assertTrue(chk_stopped.get("still_stopped"))

            # Simulate controller writing SWITCHOVER / COMMIT_DECIDED to WAL and crashing BEFORE claim_ip_and_resume RPC
            assert orch.journal is not None
            orch.journal.append(
                state=MigrationState.SWITCHOVER,
                commit_decision="COMMIT_DECIDED",
                restored_pid=restored_pid,
                note="Simulated crash right before claim_ip_and_resume",
            )
            self.assertEqual(harness.signals_b, [])

            # Recover from WAL: must detect still_stopped=True, call claim_ip_and_resume (SIGCONT), and verify running
            rec = MigrationOrchestrator.recover_from_journal(
                orch.journal.path,
                src_cli,
                dst_cli,
                require_persistent_journal=False,
            )
            self.assertTrue(rec.success, rec.error_message)
            self.assertIn((restored_pid, signal.SIGCONT), harness.signals_b)
            stat_b = (harness.proc_b / str(restored_pid) / "stat").read_text(encoding="utf-8")
            self.assertIn(") S ", stat_b)
            self.assertIn((1234, signal.SIGKILL), harness.signals_a)

        # Also verify GangMigrationCoordinator recovery under the exact same crash window
        with tempfile.TemporaryDirectory() as tmp_g:
            harness_g = _FakeClusterHarness(tmp_g)
            journal_dir_g = Path(tmp_g) / "gang_journals"
            journal_dir_g.mkdir(parents=True, exist_ok=True)
            src_g = AgentClient("10.0.0.1:9700", direct_service=harness_g.service_a)
            dst_g = AgentClient("10.0.0.2:9700", direct_service=harness_g.service_b)
            cfg_g = MigrationConfig(
                pid=1234,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                fs_mode=FilesystemMode.SHARED,
                ip_mobility=IpMobilityMode.NONE,
                tcp_established=False,
                journal_dir=str(journal_dir_g),
            )

            orig_claim = harness_g.service_b.claim_ip_and_resume

            def crash_before_claim(*args: Any, **kwargs: Any) -> Dict[str, Any]:
                raise ConnectionError("Controller crashed before claim_ip_and_resume reached Host B")

            harness_g.service_b.claim_ip_and_resume = crash_before_claim  # type: ignore[method-assign]
            coord = GangMigrationCoordinator(
                "audit-f1-gang",
                [(cfg_g, src_g, dst_g)],
                journal_dir=str(journal_dir_g),
                require_persistent_journal=False,
            )
            failed_gang = coord.execute()
            self.assertFalse(failed_gang.all_committed)
            self.assertFalse(failed_gang.atomic_rollback_triggered)
            self.assertEqual(harness_g.signals_b, [])

            # Restore RPC connectivity and recover from gang journal
            harness_g.service_b.claim_ip_and_resume = orig_claim  # type: ignore[method-assign]
            gang_wal = journal_dir_g / "audit-f1-gang.gang.wal.jsonl"
            rec_gang = GangMigrationCoordinator.recover_from_journal(
                gang_wal,
                [(cfg_g, src_g, dst_g)],
                require_persistent_journal=False,
            )
            self.assertTrue(rec_gang.all_committed)
            self.assertIn((5678, signal.SIGCONT), harness_g.signals_b)
            self.assertIn(") S ", (harness_g.proc_b / "5678" / "stat").read_text(encoding="utf-8"))

    def test_finding_2_commit_source_pid_reuse_after_wipe_images(self) -> None:
        """
        Finding 2: `wipe_images_on_commit=True` removes `mig_dir/source_state.json`.
        If PID 1234 is subsequently reused by an unrelated process (`starttime=99999`),
        repeated `commit_source()` or recovery MUST consult the durable `.tombstones/<id>.source.json`
        and send ZERO signals (`signals_after_pid_reuse == []`).
        Furthermore, if both `source_state.json` and the tombstone are missing while `/proc/1234/stat`
        exists, `commit_source()` MUST fail closed rather than blindly killing PID 1234.
        """
        with tempfile.TemporaryDirectory() as tmp:
            harness = _FakeClusterHarness(tmp)
            stat_1234 = harness.proc_a / "1234" / "stat"
            stat_1234.write_text(
                "1234 (server) S 1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 11111 0\n",
                encoding="utf-8",
            )
            journal_dir = Path(tmp) / "journals"
            journal_dir.mkdir(parents=True, exist_ok=True)
            src_cli = AgentClient("10.0.0.1:9700", direct_service=harness.service_a)
            dst_cli = AgentClient("10.0.0.2:9700", direct_service=harness.service_b)

            cfg = MigrationConfig(
                pid=1234,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                fs_mode=FilesystemMode.SHARED,
                ip_mobility=IpMobilityMode.NONE,
                wipe_images_on_commit=True,
                journal_dir=str(journal_dir),
            )
            orch = MigrationOrchestrator(
                cfg,
                src_cli,
                dst_cli,
                migration_id="audit-f2",
                require_persistent_journal=False,
            )
            res = orch.execute()
            self.assertTrue(res.success, res.error_message)

            # mig_dir was wiped, but durable tombstone outside mig_dir exists
            self.assertFalse((harness.work_a / "audit-f2" / "source_state.json").exists())
            tombstone = harness.work_a / ".tombstones" / "audit-f2.source.json"
            self.assertTrue(tombstone.exists())

            # Simulate PID 1234 reuse on Host A with a new starttime (99999 != original starttime)
            stat_1234 = harness.proc_a / "1234" / "stat"
            fields = stat_1234.read_text(encoding="utf-8").split()
            fields[21] = "99999"
            stat_1234.write_text(" ".join(fields) + "\n", encoding="utf-8")

            harness.signals_a.clear()
            repeat_res = harness.service_a.commit_source("audit-f2", config_to_dict(cfg))
            self.assertTrue(repeat_res["idempotent_noop"])
            self.assertEqual(harness.signals_a, [])

            # Even if tombstone marks committed=False (crash mid-commit after wipe), starttime mismatch blocks SIGKILL
            tomb_data = json.loads(tombstone.read_text(encoding="utf-8"))
            tomb_data["committed"] = False
            tombstone.write_text(json.dumps(tomb_data), encoding="utf-8")
            harness.signals_a.clear()
            harness.service_a.commit_source("audit-f2", config_to_dict(cfg))
            self.assertEqual(harness.signals_a, [])

            # If ALL state/tombstone files are deleted while PID 1234 is live, fail closed!
            tombstone.unlink()
            harness.signals_a.clear()
            with self.assertRaises(RuntimeError):
                harness.service_a.commit_source("audit-f2", config_to_dict(cfg))
            self.assertEqual(harness.signals_a, [])

    def test_finding_3_short_os_write_in_wal_loops_and_rolls_back_on_error(self) -> None:
        """
        Finding 3: `MigrationJournal.append()` MUST loop until all bytes + `\\n` are written and fsynced,
        and on zero-write or mid-write `OSError`, MUST `ftruncate` back to `start_offset` without
        advancing `_seq` or acknowledging `COMMITTED`.
        """
        with tempfile.TemporaryDirectory() as tmp:
            j_dir = Path(tmp) / "wal"
            journal = MigrationJournal(j_dir, "audit-f3", require_persistent=False)

            real_write = os.write

            def chunked_write(fd: int, data: bytes) -> int:
                return real_write(fd, data[:5])

            with patch("lkmp.journal.os.write", side_effect=chunked_write):
                entry = journal.append(state=MigrationState.INIT, commit_decision="PREPARING", note="chunked")
            self.assertEqual(entry.seq, 1)

            loaded = MigrationJournal.load(journal.path, require_persistent=False)
            self.assertEqual(len(loaded.entries), 1)
            self.assertEqual(loaded.entries[0].note, "chunked")

            size_before = journal.path.stat().st_size

            # Simulate short partial write followed by ENOSPC mid-record on COMMITTED
            calls = {"n": 0}

            def failing_partial_write(fd: int, data: bytes) -> int:
                calls["n"] += 1
                if calls["n"] == 1:
                    return real_write(fd, data[:17])
                raise OSError(errno.ENOSPC, "No space left on device")

            with patch("lkmp.journal.os.write", side_effect=failing_partial_write):
                with self.assertRaises(OSError):
                    journal.append(state=MigrationState.COMMIT, commit_decision="COMMITTED")

            # File MUST be truncated back to exact pre-append byte offset and COMMITTED never acknowledged
            self.assertEqual(journal.path.stat().st_size, size_before)
            self.assertEqual(len(journal.entries), 1)
            self.assertFalse(journal.has_committed_decision)
            reloaded = MigrationJournal.load(journal.path, require_persistent=False)
            self.assertEqual(len(reloaded.entries), 1)
            self.assertFalse(reloaded.has_committed_decision)

    def test_finding_4_single_execute_persists_commit_decided_before_target_resume(self) -> None:
        """
        Finding 4: In default single-workload `execute()` (no `--health-cmd`), `COMMIT_DECIDED` MUST be
        durable in `.wal.jsonl` BEFORE `claim_ip_and_resume` sends `SIGCONT` to Destination B, and
        post-decision errors MUST NOT trigger `rollback()`.
        When `--health-cmd` IS configured, `claim_ip_and_resume` runs in `fenced_canary=True` mode
        (`allow_loopback=True` in `nftables`) and unlocks external traffic only upon `commit()`.
        """
        with tempfile.TemporaryDirectory() as tmp:
            harness = _FakeClusterHarness(tmp)
            stat_1234 = harness.proc_a / "1234" / "stat"
            stat_1234.write_text(
                "1234 (server) S 1 1234 1234 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 11111 0\n",
                encoding="utf-8",
            )
            journal_dir = Path(tmp) / "journals"
            journal_dir.mkdir(parents=True, exist_ok=True)
            src_cli = AgentClient("10.0.0.1:9700", direct_service=harness.service_a)
            dst_cli = AgentClient("10.0.0.2:9700", direct_service=harness.service_b)

            cfg = MigrationConfig(
                pid=1234,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                fs_mode=FilesystemMode.SHARED,
                ip_mobility=IpMobilityMode.NONE,
                journal_dir=str(journal_dir),
            )
            orch = MigrationOrchestrator(
                cfg,
                src_cli,
                dst_cli,
                migration_id="audit-f4",
                require_persistent_journal=False,
            )

            committed_when_target_resumed: List[bool] = []
            orig_claim = harness.service_b.claim_ip_and_resume

            def spy_claim(*args: Any, **kwargs: Any) -> Dict[str, Any]:
                assert orch.journal is not None
                disk_wal = MigrationJournal.load(orch.journal.path, require_persistent=False)
                committed_when_target_resumed.append(disk_wal.has_committed_decision)
                return orig_claim(*args, **kwargs)

            harness.service_b.claim_ip_and_resume = spy_claim  # type: ignore[method-assign]
            res = orch.execute()
            self.assertTrue(res.success, res.error_message)
            self.assertEqual(committed_when_target_resumed, [True])

        # Also verify `--health-cmd` uses loopback-fenced canary (`iifname != "lo"`) before unlocking external network
        with tempfile.TemporaryDirectory() as tmp_c:
            harness_c = _FakeClusterHarness(tmp_c)
            journal_dir_c = Path(tmp_c) / "journals_c"
            journal_dir_c.mkdir(parents=True, exist_ok=True)
            src_c = AgentClient("10.0.0.1:9700", direct_service=harness_c.service_a)
            dst_c = AgentClient("10.0.0.2:9700", direct_service=harness_c.service_b)

            cfg_c = MigrationConfig(
                pid=1234,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.COLD,
                fs_mode=FilesystemMode.SHARED,
                ip_mobility=IpMobilityMode.GARP,
                workload_ip="10.0.0.50/24",
                health_check_cmd="true",
                journal_dir=str(journal_dir_c),
            )
            orch_c = MigrationOrchestrator(
                cfg_c,
                src_c,
                dst_c,
                migration_id="audit-f4-canary",
                require_persistent_journal=False,
            )
            res_c = orch_c.execute()
            self.assertTrue(res_c.success, res_c.error_message)
            nft_cmds_b = [" ".join(c) for c in harness_c.commands_b if c and c[0] == "nft"]
            self.assertTrue(any('iifname != "lo"' in cmd for cmd in nft_cmds_b))
            self.assertEqual(harness_c._nft_b, {})

    def test_finding_5_lazy_commit_source_preserves_lazy_dump_until_dest_confirms(self) -> None:
        """
        Finding 5: During `LAZY` / `HYBRID` migration, an unconfirmed `commit_source()` call MUST keep
        `lazy-dump` and stopped/fenced Source A alive (`lazy_transfer_pending=True`) until Destination B
        confirms `lazy-pages` completion (`lazy_transfer_confirmed_by_dest=True`).
        """
        with tempfile.TemporaryDirectory() as tmp:
            harness = _FakeClusterHarness(tmp)
            cfg = MigrationConfig(
                pid=1234,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.LAZY,
                fs_mode=FilesystemMode.SHARED,
                ip_mobility=IpMobilityMode.NONE,
                wipe_images_on_commit=True,
            )
            cfg_dict = config_to_dict(cfg)
            harness.service_a.prepare_migration("audit-f5", cfg_dict, is_dest=False)
            harness.service_a.freeze_and_final_dump("audit-f5", None, "10.0.0.2", cfg_dict)

            lazy_dump_pidfile = harness.work_a / "audit-f5" / "final" / "lazy-dump.pid"
            self.assertTrue(lazy_dump_pidfile.exists())

            # Simulate live lazy-dump daemon on Source A
            with patch.object(harness.service_a.criu, "is_daemon_running", return_value=True):
                pending = harness.service_a.commit_source(
                    "audit-f5",
                    cfg_dict,
                    lazy_transfer_confirmed_by_dest=False,
                )
            self.assertTrue(pending.get("lazy_transfer_pending"))
            self.assertFalse(pending.get("committed"))
            self.assertEqual(harness.signals_a, [])
            self.assertTrue(lazy_dump_pidfile.exists())

            # Once Destination B confirms lazy transfer finished, commit_source reaps Source A and wipes images
            confirmed = harness.service_a.commit_source(
                "audit-f5",
                cfg_dict,
                lazy_transfer_confirmed_by_dest=True,
            )
            self.assertTrue(confirmed.get("committed"))
            self.assertIn((1234, signal.SIGKILL), harness.signals_a)
            self.assertFalse((harness.work_a / "audit-f5").exists())
            self.assertTrue((harness.work_a / ".tombstones" / "audit-f5.source.json").exists())

    def test_finding_6_recovery_uses_effective_post_preflight_and_hybrid_config(self) -> None:
        """
        Finding 6: WAL recovery MUST restore the latest enriched `effective_config_dict` (including
        auto-detected `workload_kind="qemu"`, `runtime_metadata`, and `PRE_COPY -> HYBRID` upgrades)
        rather than Entry #1's pre-preflight `initial_config_dict`.
        """
        with tempfile.TemporaryDirectory() as tmp:
            j_dir = Path(tmp) / "journals"
            initial_cfg = MigrationConfig(
                pid=4242,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.PRE_COPY,
                workload_kind="auto",
                journal_dir=str(j_dir),
            )
            journal = MigrationJournal(
                j_dir,
                "audit-f6",
                require_persistent=False,
            )
            journal.append(
                state=MigrationState.INIT,
                commit_decision="PREPARING",
                config_dict=config_to_dict(initial_cfg),
            )

            # Simulate preflight QEMU auto-detection + non-converging PRE_COPY -> HYBRID upgrade
            enriched_cfg = MigrationConfig(
                pid=4242,
                source_addr="10.0.0.1:9700",
                dest_addr="10.0.0.2:9700",
                strategy=MigrationStrategy.HYBRID,
                workload_kind=WorkloadKind.QEMU_VM.value,
                runtime_metadata={
                    "qmp_socket": "/run/lkmp/vm-4242.qmp",
                    "qemu_cmdline": ["qemu-system-x86_64", "-S"],
                },
                journal_dir=str(j_dir),
            )
            journal.append(
                state=MigrationState.PRE_COPY,
                commit_decision="PREPARING",
                config_dict=config_to_dict(enriched_cfg),
                note="Enriched post-preflight + hybrid upgrade",
            )
            journal.append(
                state=MigrationState.FREEZE,
                commit_decision="PREPARING",
                note="Subsequent state without redundant config_dict",
            )

            loaded = MigrationJournal.load(journal.path, require_persistent=False)
            eff = loaded.effective_config_dict
            self.assertIsNotNone(eff)
            assert eff is not None
            self.assertEqual(eff["workload_kind"], "qemu")
            self.assertEqual(eff["strategy"], "hybrid")
            self.assertEqual(eff["runtime_metadata"]["qmp_socket"], "/run/lkmp/vm-4242.qmp")

    def test_finding_7_qemu_mtls_x509_and_oci_microvm_merkle_attestation(self) -> None:
        """
        Finding 7a: When `config.tls.enabled=True`, `QemuQmpDriver` MUST stage `0700`/`0600` X.509 PEMs
        and configure QMP `object-add` `tls-creds-x509` (`id="lkmp_tls0"`, `verify-peer=True`) +
        `migrate-set-parameters` `tls-creds="lkmp_tls0"`, failing closed if certs are missing or QMP rejects TLS.
        Finding 7b: `CheckpointAttestor` MUST bind and verify `.tar` (OCI) and `.snap`/`.mem` (MicroVM)
        artifacts, rejecting 1-byte tampering prior to `restore_process`.
        """
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            pki = generate_mtls_pki(tmp_path / "pki", hosts=("127.0.0.1", "localhost"))
            tls_on = TlsConfig(
                enabled=True,
                ca_cert=str(pki.ca_cert),
                cert_file=str(pki.node_cert),
                key_file=str(pki.node_key),
            )

            qmp_calls: List[Tuple[str, str, Dict[str, Any]]] = []
            mig_started = {"on": False}

            def fake_qmp(sock: str | Path, execute: str, arguments: Dict[str, Any] | None = None, **_: Any) -> Dict[str, Any]:
                args = dict(arguments or {})
                qmp_calls.append((str(sock), execute, args))
                if execute == "migrate":
                    mig_started["on"] = True
                if execute == "query-migrate":
                    return {"status": "pre-switchover"} if mig_started["on"] else {"status": ""}
                if execute == "query-status":
                    return {"status": "inmigrate", "running": False}
                return {}

            proc_root = tmp_path / "proc"
            (proc_root / "5000").mkdir(parents=True)
            (proc_root / "5000" / "stat").write_text("5000 (qemu) S 1 5000 5000 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 777 0\n")

            src_qmp = tmp_path / "src.qmp"
            src_qmp.write_text("", encoding="utf-8")

            def fake_spawner(cmd: List[str]) -> subprocess.CompletedProcess:
                for idx, tok in enumerate(cmd):
                    if tok == "-qmp" and idx + 1 < len(cmd):
                        spec = cmd[idx + 1]
                        if spec.startswith("unix:"):
                            sock_path = Path(spec[len("unix:") :].split(",")[0])
                            sock_path.parent.mkdir(parents=True, exist_ok=True)
                            sock_path.write_text("", encoding="utf-8")
                    elif tok == "-pidfile" and idx + 1 < len(cmd):
                        pf = Path(cmd[idx + 1])
                        pf.parent.mkdir(parents=True, exist_ok=True)
                        pf.write_text("6000\n", encoding="utf-8")
                return subprocess.CompletedProcess(cmd, 0, "", "")

            drv = QemuQmpDriver(
                proc_root=str(proc_root),
                qmp_caller=fake_qmp,
                spawner=fake_spawner,
            )
            q_cfg = MigrationConfig(
                pid=5000,
                source_addr="127.0.0.1:9700",
                dest_addr="127.0.0.1:9701",
                strategy=MigrationStrategy.PRE_COPY,
                workload_kind="qemu",
                runtime_metadata={
                    "qmp_socket": str(src_qmp),
                    "qemu_cmdline": ["qemu-system-x86_64", "-m", "128"],
                },
                tls=tls_on,
            )
            mig_dst = tmp_path / "mig_dst"
            mig_src = tmp_path / "mig_src"
            mig_dst.mkdir()
            mig_src.mkdir()
            (proc_root / "6000").mkdir(parents=True)
            (proc_root / "6000" / "stat").write_text("6000 (qemu) S 1 6000 6000 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 888 0\n")

            prep_dst = drv.prepare_dest("q-tls", mig_dst, q_cfg)
            dst_Res = drv.start_pre_copy_target("q-tls", mig_dst, "round_1", None, q_cfg)
            q_cfg.runtime_metadata["qemu_incoming_port"] = dst_Res.get("qemu_incoming_port", prep_dst.get("qemu_incoming_port", 49155))
            drv.run_pre_copy_source("q-tls", mig_src, "round_1", None, "127.0.0.1", q_cfg)
            Path("/tmp/lkmp-qmp-mig_dst.sock").unlink(missing_ok=True)

            obj_adds = [args for _, cmd, args in qmp_calls if cmd == "object-add"]
            self.assertEqual(len(obj_adds), 2)
            endpoints = {a["endpoint"] for a in obj_adds}
            self.assertEqual(endpoints, {"server", "client"})
            for a in obj_adds:
                self.assertEqual(a["qom-type"], "tls-creds-x509")
                self.assertEqual(a["id"], "lkmp_tls0")
                self.assertTrue(a["verify-peer"])

            param_sets = [args for _, cmd, args in qmp_calls if cmd == "migrate-set-parameters" and "tls-creds" in args]
            self.assertEqual(len(param_sets), 2)
            self.assertTrue(all(p["tls-creds"] == "lkmp_tls0" for p in param_sets))

            # Fail closed when TLS is enabled without certificate paths
            bad_tls_cfg = MigrationConfig(
                pid=5000,
                source_addr="127.0.0.1:9700",
                dest_addr="127.0.0.1:9701",
                workload_kind="qemu",
                runtime_metadata={"qmp_socket": str(src_qmp), "qemu_cmdline": ["qemu-system-x86_64"]},
                tls=TlsConfig(enabled=True, ca_cert=None, cert_file=None, key_file=None),
            )
            with self.assertRaises(RuntimeError):
                drv.prepare_dest("q-bad-tls", tmp_path / "mig_bad", bad_tls_cfg)

            # Finding 7b: Merkle + HMAC-SHA256 attestation over OCI (.tar) and MicroVM (.snap / .mem)
            attestor = CheckpointAttestor()
            key_hex = generate_ephemeral_key_hex()
            for suffix_set in (("container-ckpt.tar",), ("vm.snap", "guest.mem")):
                art_dir = tmp_path / f"attest_{suffix_set[0]}"
                art_dir.mkdir(parents=True, exist_ok=True)
                for fname in suffix_set:
                    (art_dir / fname).write_bytes(b"authentic-checkpoint-payload-" + fname.encode("utf-8"))
                manifest = attestor.generate_manifest(
                    images_dir=art_dir,
                    migration_id="mig-non-criu",
                    pid=777,
                    key_hex=key_hex,
                )
                manifest_filenames = {f.filename for f in manifest.files}
                for fname in suffix_set:
                    self.assertIn(fname, manifest_filenames)
                attestor.verify_directory(art_dir, expected_migration_id="mig-non-criu", key_hex=key_hex)

                # Flip 1 byte in the archive / memory snapshot -> must raise ValueError!
                victim = art_dir / suffix_set[-1]
                raw = bytearray(victim.read_bytes())
                raw[0] ^= 0xFF
                victim.write_bytes(bytes(raw))
                with self.assertRaises(ValueError):
                    attestor.verify_directory(art_dir, expected_migration_id="mig-non-criu", key_hex=key_hex)

            # Confirm OCI and MicroVM drivers expose verify_running_dest stopped checks
            oci_drv = OciContainerDriver(
                proc_root=str(proc_root),
                runner=lambda cmd: subprocess.CompletedProcess(
                    cmd, 0, json.dumps([{"State": {"Status": "paused", "Paused": True}}]), ""
                ),
            )
            oci_chk = oci_drv.verify_running_dest(
                "m1",
                tmp_path,
                5000,
                MigrationConfig(
                    pid=5000,
                    source_addr="a",
                    dest_addr="b",
                    runtime_metadata={"engine": "podman", "container_id": "c1"},
                ),
            )
            self.assertFalse(oci_chk["healthy"])
            self.assertTrue(oci_chk["still_stopped"])

            mvm_dir = tmp_path / "mvm_mig"
            (mvm_dir / "final").mkdir(parents=True)
            (mvm_dir / "final" / "restore_state.json").write_text(json.dumps({"resumed": False}), encoding="utf-8")
            mvm_drv = MicroVmDriver(proc_root=str(proc_root))
            mvm_chk = mvm_drv.verify_running_dest(
                "m2",
                mvm_dir,
                5000,
                MigrationConfig(pid=5000, source_addr="a", dest_addr="b"),
            )
            self.assertFalse(mvm_chk["healthy"])
            self.assertTrue(mvm_chk["still_stopped"])


if __name__ == "__main__":
    unittest.main()
