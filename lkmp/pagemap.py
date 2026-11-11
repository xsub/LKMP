"""Kernel `/proc/<pid>/pagemap` soft-dirty profiler, VMA locality classifier & entropy estimator."""

from __future__ import annotations

import math
import struct
import time
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Tuple

from lkmp.config import MigrationStrategy

PAGE_SIZE = 4096
PTE_SOFT_DIRTY_BIT = 1 << 55
PTE_PRESENT_BIT = 1 << 63
PTE_SWAPPED_BIT = 1 << 62


class VmaHeatClass(str, Enum):
    """Working-set write locality classification for a Virtual Memory Area."""

    COLD = "cold"                      # dirty density < 5% (ideal for early pre-dump)
    WARM = "warm"                      # dirty density 5%..60% (converges over 2-4 rounds)
    HOT_THRASHING = "hot_thrashing"    # dirty density >= 60% (defer to freeze or userfaultfd)


@dataclass
class VmaRegionProfile:
    """Per-VMA page residency and dirty-page density profile."""

    start_vaddr: int
    end_vaddr: int
    label: str
    present_pages: int
    soft_dirty_pages: int

    @property
    def dirty_density(self) -> float:
        if self.present_pages <= 0:
            return 0.0
        return self.soft_dirty_pages / float(self.present_pages)

    @property
    def heat_class(self) -> VmaHeatClass:
        density = self.dirty_density
        if density >= 0.60:
            return VmaHeatClass.HOT_THRASHING
        if density >= 0.05:
            return VmaHeatClass.WARM
        return VmaHeatClass.COLD


@dataclass
class MemoryHeatProfile:
    """Result of sampling `/proc/<pid>/pagemap` soft-dirty bits over a time window."""

    pid: int
    sample_window_ms: float
    total_present_pages: int
    soft_dirty_pages: int
    rss_bytes: int
    dirty_bytes: int
    dirty_rate_bytes_per_sec: int
    recommended_strategy: MigrationStrategy
    recommendation_reason: str
    vma_profiles: List[VmaRegionProfile] = field(default_factory=list)
    hot_thrashing_bytes: int = 0


def compute_shannon_entropy(sample_bytes: bytes) -> float:
    """
    Compute Shannon byte entropy H(X) in bits per byte [0.0, 8.0].
    0.0 = uniform/zero page (maximally compressible); 8.0 = random/encrypted page.
    """
    if not sample_bytes:
        return 0.0
    length = float(len(sample_bytes))
    counts = Counter(sample_bytes)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


def estimate_compression_ratio(sample_bytes: bytes) -> float:
    """
    Estimate zstd/lz4 stream compression ratio (>= 1.0) from Shannon byte entropy.
    Used to compute effective network throughput over compressed page-server streams.
    """
    if not sample_bytes:
        return 1.0
    entropy = compute_shannon_entropy(sample_bytes)
    if entropy <= 0.5:
        return 8.0
    # Linear map from entropy [0.5 .. 8.0] -> ratio [4.5 .. 1.0]
    ratio = 1.0 + max(0.0, (8.0 - entropy) / 7.5) * 3.5
    return round(max(1.0, ratio), 2)


def parse_writable_vmas_with_labels(maps_text: str) -> List[Tuple[int, int, str]]:
    """
    Parse `/proc/<pid>/maps` and return `(start_vaddr, end_vaddr, label)`
    for writable memory regions (`rw-p`).
    """
    vmas: List[Tuple[int, int, str]] = []
    for line in maps_text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 2:
            continue
        addr_range, perms = parts[0], parts[1]
        if "w" not in perms:
            continue
        label = parts[5].strip() if len(parts) >= 6 else "[anon]"
        if label.startswith("[v"):  # Skip [vvar], [vdso], [vsyscall]
            continue
        try:
            start_hex, end_hex = addr_range.split("-", 1)
            start_addr = int(start_hex, 16)
            end_addr = int(end_hex, 16)
            if end_addr > start_addr:
                vmas.append((start_addr, end_addr, label))
        except ValueError:
            continue
    return vmas


def parse_writable_vmas(maps_text: str) -> List[Tuple[int, int]]:
    """Return `(start_vaddr, end_vaddr)` pairs for writable VMAs."""
    return [(s, e) for s, e, _ in parse_writable_vmas_with_labels(maps_text)]


def count_pagemap_flags(pagemap_bytes: bytes) -> Tuple[int, int]:
    """
    Count `(present_pages, soft_dirty_pages)` from raw 64-bit `/proc/<pid>/pagemap` entries.
    Bit 63 = page present in RAM; Bit 55 = PTE soft-dirty bit set by kernel since last clear_refs.
    """
    present = 0
    soft_dirty = 0
    valid_len = (len(pagemap_bytes) // 8) * 8
    for (entry,) in struct.iter_unpack("<Q", pagemap_bytes[:valid_len]):
        if entry & (PTE_PRESENT_BIT | PTE_SWAPPED_BIT):
            present += 1
        if entry & PTE_SOFT_DIRTY_BIT:
            soft_dirty += 1
    return present, soft_dirty


def reset_soft_dirty_bits(pid: int, proc_root: str = "/proc") -> bool:
    """Write `4` to `/proc/<pid>/clear_refs` to clear soft-dirty bits across all PTEs."""
    clear_refs = Path(proc_root) / str(pid) / "clear_refs"
    try:
        clear_refs.write_text("4\n", encoding="utf-8")
        return True
    except OSError:
        return False


def _discover_tree_pids_for_pagemap(root_pid: int, proc_root: str) -> List[int]:
    """Discover `[root_pid, ...descendants]` inside `proc_root` for whole-tree pagemap sampling."""
    proc_dir = Path(proc_root)
    parent_to_children: dict[int, set[int]] = {}
    if proc_dir.exists():
        try:
            for entry in proc_dir.iterdir():
                if entry.is_dir() and entry.name.isdigit():
                    c_pid = int(entry.name)
                    stat_file = entry / "stat"
                    if stat_file.is_file():
                        try:
                            content = stat_file.read_text(encoding="utf-8", errors="ignore")
                            rparen = content.rfind(")")
                            if rparen != -1:
                                fields = content[rparen + 1 :].strip().split()
                                if len(fields) >= 2:
                                    ppid = int(fields[1])
                                    parent_to_children.setdefault(ppid, set()).add(c_pid)
                        except Exception:
                            pass
        except OSError:
            pass

    result = [root_pid]
    visited = {root_pid}
    queue = [root_pid]
    while queue:
        curr = queue.pop(0)
        task_dir = proc_dir / str(curr) / "task"
        if task_dir.is_dir():
            try:
                for tid_entry in task_dir.iterdir():
                    ch_file = tid_entry / "children"
                    if ch_file.is_file():
                        for ch_str in ch_file.read_text(encoding="utf-8", errors="ignore").split():
                            if ch_str.isdigit():
                                ch_pid = int(ch_str)
                                if ch_pid not in visited:
                                    visited.add(ch_pid)
                                    result.append(ch_pid)
                                    queue.append(ch_pid)
            except OSError:
                pass
        for child in sorted(parent_to_children.get(curr, ())):
            if child not in visited:
                visited.add(child)
                result.append(child)
                queue.append(child)
    return result


def sample_process_dirty_rate(
    pid: int,
    proc_root: str = "/proc",
    sample_ms: int = 0,
    bandwidth_mbps: float = 1000.0,
    has_userfaultfd: bool = True,
    allow_clear_refs: bool = False,
    include_children: bool = True,
) -> MemoryHeatProfile:
    """
    Read `/proc/<pid>/pagemap` across writable VMAs (across the full process tree when
    `include_children=True`) to measure memory residency and soft-dirty bits.
    When `allow_clear_refs=False` (default for non-destructive preflight), never writes to
    `/proc/<pid>/clear_refs`. Only resets soft-dirty bits when `allow_clear_refs=True` and `sample_ms > 0`.
    """
    proc_dir = Path(proc_root) / str(pid)
    maps_path = proc_dir / "maps"

    if not maps_path.exists():
        raise FileNotFoundError(f"Cannot read {maps_path}")

    target_pids = (
        _discover_tree_pids_for_pagemap(pid, proc_root)
        if include_children
        else [pid]
    )

    reset_ok = False
    if allow_clear_refs and sample_ms > 0:
        for t_pid in target_pids:
            if reset_soft_dirty_bits(t_pid, proc_root=proc_root):
                reset_ok = True

    t0 = time.monotonic()
    if sample_ms > 0 and reset_ok:
        time.sleep(sample_ms / 1000.0)
    elapsed_sec = max(0.001, time.monotonic() - t0)

    total_present = 0
    total_dirty = 0
    hot_thrashing_pages = 0
    vma_profiles: List[VmaRegionProfile] = []

    for t_pid in target_pids:
        t_dir = Path(proc_root) / str(t_pid)
        t_maps = t_dir / "maps"
        t_pagemap = t_dir / "pagemap"
        if not t_maps.exists() or not t_pagemap.exists():
            continue
        try:
            vmas = parse_writable_vmas_with_labels(
                t_maps.read_text(encoding="utf-8", errors="ignore")
            )
            with t_pagemap.open("rb") as pm_file:
                for start_addr, end_addr, label in vmas:
                    start_page = start_addr // PAGE_SIZE
                    num_pages = (end_addr - start_addr) // PAGE_SIZE
                    if num_pages <= 0:
                        continue
                    pages_to_read = min(num_pages, 32768)
                    pm_file.seek(start_page * 8)
                    raw = pm_file.read(pages_to_read * 8)
                    pres, dirty = count_pagemap_flags(raw)
                    total_present += pres
                    total_dirty += dirty
                    vma_label = label if t_pid == pid else f"pid:{t_pid}:{label}"
                    vma_prof = VmaRegionProfile(
                        start_vaddr=start_addr,
                        end_vaddr=end_addr,
                        label=vma_label,
                        present_pages=pres,
                        soft_dirty_pages=dirty,
                    )
                    if vma_prof.heat_class == VmaHeatClass.HOT_THRASHING:
                        hot_thrashing_pages += dirty
                    vma_profiles.append(vma_prof)
        except OSError:
            pass

    rss_bytes = total_present * PAGE_SIZE
    dirty_bytes = total_dirty * PAGE_SIZE
    hot_thrashing_bytes = hot_thrashing_pages * PAGE_SIZE
    if reset_ok:
        dirty_rate_bps = int(dirty_bytes / elapsed_sec)
    elif total_dirty > 0:
        dirty_rate_bps = int(total_dirty * PAGE_SIZE)
    else:
        dirty_rate_bps = 0

    strategy, reason = select_optimal_strategy(
        rss_bytes=rss_bytes,
        dirty_rate_bytes_per_sec=dirty_rate_bps,
        bandwidth_mbps=bandwidth_mbps,
        has_userfaultfd=has_userfaultfd,
        hot_thrashing_bytes=hot_thrashing_bytes,
    )

    return MemoryHeatProfile(
        pid=pid,
        sample_window_ms=round(elapsed_sec * 1000.0, 2),
        total_present_pages=total_present,
        soft_dirty_pages=total_dirty,
        rss_bytes=rss_bytes,
        dirty_bytes=dirty_bytes,
        dirty_rate_bytes_per_sec=dirty_rate_bps,
        recommended_strategy=strategy,
        recommendation_reason=reason,
        vma_profiles=vma_profiles,
        hot_thrashing_bytes=hot_thrashing_bytes,
    )


def select_optimal_strategy(
    rss_bytes: int,
    dirty_rate_bytes_per_sec: int,
    bandwidth_mbps: float = 1000.0,
    has_userfaultfd: bool = True,
    hot_thrashing_bytes: int = 0,
) -> Tuple[MigrationStrategy, str]:
    """
    Recommend the optimal migration strategy based on process RSS, live page dirty rate,
    hot-thrashing VMA footprint, and available network bandwidth.
    """
    bw_bytes_per_sec = max(1.0, (bandwidth_mbps * 1_000_000.0) / 8.0)

    # 1. Tiny processes (<= 8 MiB RSS): cold stop-and-copy transfers in < 65ms on 1 Gbps
    if 0 < rss_bytes <= 8 * 1024 * 1024 and dirty_rate_bytes_per_sec == 0:
        return (
            MigrationStrategy.COLD,
            f"Small RSS ({rss_bytes // 1024} KiB); single-pass cold dump is fastest",
        )

    # 2. Write-intensive workloads dirtying memory >= 70% of network link speed
    # OR with a large hot-thrashing VMA working set exceeding 200ms transfer budget:
    target_budget_bytes = int(bw_bytes_per_sec * 0.200)
    if (
        dirty_rate_bytes_per_sec >= bw_bytes_per_sec * 0.70
        or hot_thrashing_bytes > target_budget_bytes
    ):
        if has_userfaultfd:
            return (
                MigrationStrategy.HYBRID,
                (
                    f"High write/hot-thrashing footprint (dirty_rate="
                    f"{dirty_rate_bytes_per_sec // (1024 * 1024)} MiB/s, "
                    f"hot_vma={hot_thrashing_bytes // (1024 * 1024)} MiB); "
                    "selected hybrid pre-copy + userfaultfd lazy-pages"
                ),
            )
        return (
            MigrationStrategy.PRE_COPY,
            "High write rate detected, but destination lacks userfaultfd; falling back to capped pre-copy",
        )

    # 3. Default sweet spot: iterative pre-copy converges cleanly with full rollback safety
    return (
        MigrationStrategy.PRE_COPY,
        (
            f"Dirty rate ({dirty_rate_bytes_per_sec // max(1, 1024 * 1024)} MiB/s) is below "
            f"network capacity ({int(bw_bytes_per_sec // (1024 * 1024))} MiB/s); "
            "iterative pre-copy will converge cleanly"
        ),
    )
