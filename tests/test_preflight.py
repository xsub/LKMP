"""Tests for Phase 1 preflight inspection, ELF build-id parser, and compatibility checks."""

from __future__ import annotations

import os
import struct
import tempfile
import unittest
from pathlib import Path

from lkmp.config import GpuPlugin, MigrationConfig, MigrationStrategy
from lkmp.models import (
    FileArtifact,
    HostCapabilities,
    ProcessSnapshotInfo,
    ResourceClassification,
)
from lkmp.preflight import (
    evaluate_compatibility,
    inspect_process_tree,
    parse_elf_build_id,
    parse_proc_cpuinfo,
)


def _create_synthetic_elf64_with_build_id(path: Path, build_id_bytes: bytes) -> None:
    """Construct a minimal valid 64-bit little-endian ELF binary with a PT_NOTE GNU build-id."""
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    e_phoff = 64
    e_phentsize = 56
    e_phnum = 1
    hdr = struct.pack(
        "<HHIQQQIHHHHHH",
        2,          # ET_EXEC
        62,         # EM_X86_64
        1,          # EV_CURRENT
        0x400000,   # e_entry
        e_phoff,
        0,          # e_shoff
        0,          # e_flags
        64,         # e_ehsize
        e_phentsize,
        e_phnum,
        0,
        0,
        0,
    )
    name = b"GNU\x00"
    note_hdr = struct.pack("<III", len(name), len(build_id_bytes), 3)  # NT_GNU_BUILD_ID = 3
    pad_len = ((len(build_id_bytes) + 3) & ~3) - len(build_id_bytes)
    note_payload = note_hdr + name + build_id_bytes + (b"\x00" * pad_len)

    note_offset = e_phoff + e_phentsize
    phdr = struct.pack(
        "<IIQQQQQQ",
        4,                  # PT_NOTE
        4,                  # PF_R
        note_offset,
        0,
        0,
        len(note_payload),
        len(note_payload),
        4,
    )
    path.write_bytes(e_ident + hdr + phdr + note_payload)


class TestPreflight(unittest.TestCase):
    def test_parse_elf_build_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            elf_path = Path(tmp) / "test_bin"
            expected = bytes.fromhex("deadbeefcafebabe0123456789abcdef01234567")
            _create_synthetic_elf64_with_build_id(elf_path, expected)
            actual = parse_elf_build_id(elf_path)
            self.assertEqual(actual, expected.hex())

    def test_parse_proc_cpuinfo(self) -> None:
        sample = """
processor   : 0
vendor_id   : GenuineIntel
flags       : fpu vme de pse tsc msr pae mce cx8 apic sep mtrr avx avx2 bmi1 bmi2 xsave
"""
        vendor, flags = parse_proc_cpuinfo(sample)
        self.assertEqual(vendor, "GenuineIntel")
        self.assertIn("avx2", flags)
        self.assertIn("xsave", flags)

    def test_inspect_process_tree_detects_io_uring_and_dbus_and_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp) / "proc"
            pid_dir = proc_root / "4242"
            (pid_dir / "fd").mkdir(parents=True)
            (pid_dir / "task" / "4242").mkdir(parents=True)

            (pid_dir / "status").write_text(
                "Name:\tworker\nVmRSS:\t102400 kB\nTracerPid:\t0\nNSpid:\t4242\t1\n",
                encoding="utf-8",
            )
            (pid_dir / "cgroup").write_text("0::/lkmp/job-1\n", encoding="utf-8")
            (pid_dir / "task" / "4242" / "children").write_text("4243 4244\n", encoding="utf-8")

            bin_path = Path(tmp) / "app.bin"
            _create_synthetic_elf64_with_build_id(bin_path, bytes.fromhex("1122334455667788"))
            (pid_dir / "maps").write_text(
                f"00400000-00401000 r-xp 00000000 08:01 123 {bin_path}\n",
                encoding="utf-8",
            )

            os.symlink("anon_inode:[io_uring]", pid_dir / "fd" / "3")
            os.symlink("/run/dbus/system_bus_socket", pid_dir / "fd" / "4")

            snap = inspect_process_tree(4242, proc_root=str(proc_root))
            self.assertTrue(snap.in_envelope)
            self.assertEqual(snap.rss_bytes, 102400 * 1024)
            self.assertEqual(snap.child_pids, [4243, 4244])
            self.assertEqual(len(snap.files), 1)
            self.assertEqual(snap.files[0].build_id, "1122334455667788")

            classifications = {f.identifier: f.classification for f in snap.findings}
            self.assertEqual(
                classifications["fd:3->anon_inode:[io_uring]"],
                ResourceClassification.BLOCKER,
            )
            self.assertEqual(
                classifications["fd:4->/run/dbus/system_bus_socket"],
                ResourceClassification.NEEDS_FLAG,
            )

    def test_cpu_superset_and_file_build_id_compatibility(self) -> None:
        cfg = MigrationConfig(
            pid=100,
            source_addr="10.0.0.1:9700",
            dest_addr="10.0.0.2:9700",
            strategy=MigrationStrategy.PRE_COPY,
        )
        src_caps = HostCapabilities(
            arch="x86_64",
            kernel_release="6.8.0",
            cpu_vendor="GenuineIntel",
            cpu_flags={"sse4_2", "avx", "avx2", "avx512f", "xsave"},
            criu_available=True,
            has_soft_dirty=True,
        )
        dst_caps_missing_avx512 = HostCapabilities(
            arch="x86_64",
            kernel_release="6.8.0",
            cpu_vendor="GenuineIntel",
            cpu_flags={"sse4_2", "avx", "avx2", "xsave"},
            criu_available=True,
            has_soft_dirty=True,
        )
        snap = ProcessSnapshotInfo(
            root_pid=100,
            rss_bytes=64 * 1024 * 1024,
            in_envelope=True,
            files=[
                FileArtifact(
                    path="/usr/bin/app",
                    size=4096,
                    build_id="aabbccdd",
                    is_mapped_executable=True,
                )
            ],
        )
        dst_files_ok = {
            "/usr/bin/app": FileArtifact(
                path="/usr/bin/app",
                size=4096,
                build_id="aabbccdd",
                is_mapped_executable=True,
            )
        }

        # 1. Fail when Destination B lacks avx512f
        report_bad_cpu = evaluate_compatibility(
            cfg, src_caps, dst_caps_missing_avx512, snap, dst_files_ok
        )
        self.assertFalse(report_bad_cpu.compatible)
        self.assertTrue(any(b.resource_type == "cpu" for b in report_bad_cpu.blockers))

        # 2. Succeed when Destination B is a superset of Source A
        dst_caps_superset = HostCapabilities(
            arch="x86_64",
            kernel_release="6.8.0",
            cpu_vendor="GenuineIntel",
            cpu_flags={"sse4_2", "avx", "avx2", "avx512f", "avx512bw", "xsave"},
            criu_available=True,
            has_soft_dirty=True,
        )
        report_ok = evaluate_compatibility(
            cfg, src_caps, dst_caps_superset, snap, dst_files_ok
        )
        self.assertTrue(report_ok.compatible)

        # 3. Fail when ELF build-id mismatches on Destination B
        dst_files_mismatch = {
            "/usr/bin/app": FileArtifact(
                path="/usr/bin/app",
                size=4096,
                build_id="deadbeef",
                is_mapped_executable=True,
            )
        }
        report_bad_elf = evaluate_compatibility(
            cfg, src_caps, dst_caps_superset, snap, dst_files_mismatch
        )
        self.assertFalse(report_bad_elf.compatible)
        self.assertTrue(any("build-id mismatch" in b.reason for b in report_bad_elf.blockers))

    def test_gpu_device_requires_matching_plugin(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            proc_root = Path(tmp) / "proc"
            pid_dir = proc_root / "500"
            (pid_dir / "fd").mkdir(parents=True)
            (pid_dir / "status").write_text("NSpid:\t500\t1\n", encoding="utf-8")
            os.symlink("/dev/nvidia0", pid_dir / "fd" / "5")

            snap = inspect_process_tree(500, proc_root=str(proc_root))
            caps = HostCapabilities(
                arch="x86_64",
                kernel_release="6.8.0",
                cpu_vendor="GenuineIntel",
                cpu_flags={"avx2"},
                has_soft_dirty=True,
            )

            cfg_no_gpu = MigrationConfig(
                pid=500,
                source_addr="a:9700",
                dest_addr="b:9700",
                gpu_plugin=GpuPlugin.NONE,
            )
            rep_blocked = evaluate_compatibility(cfg_no_gpu, caps, caps, snap, {})
            self.assertFalse(rep_blocked.compatible)

            cfg_cuda = MigrationConfig(
                pid=500,
                source_addr="a:9700",
                dest_addr="b:9700",
                gpu_plugin=GpuPlugin.CUDA,
            )
            rep_allowed = evaluate_compatibility(cfg_cuda, caps, caps, snap, {})
            self.assertTrue(rep_allowed.compatible)


if __name__ == "__main__":
    unittest.main()
