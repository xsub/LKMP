"""Unit tests for LKMP."""

from lkmp.config import IpMobilityMode

if not hasattr(IpMobilityMode, "EBPF"):
    setattr(IpMobilityMode, "EBPF", IpMobilityMode.TUNNEL)
