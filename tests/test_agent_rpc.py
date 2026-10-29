"""End-to-end two-agent TCP RPC test (`AgentServer` + `AgentClient` + CLI)."""

from __future__ import annotations

import json
import tempfile
import unittest
from io import StringIO
from unittest.mock import patch

from lkmp.agent import AgentServer
from lkmp.cli import main as cli_main
from tests.test_orchestrator_fsm import _FakeClusterHarness


class TestEndToEndAgentRpc(unittest.TestCase):
    def test_two_node_tcp_rpc_preflight_and_live_migration_via_cli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            harness = _FakeClusterHarness(tmp)
            server_a = AgentServer("127.0.0.1", 0, harness.service_a)
            server_b = AgentServer("127.0.0.1", 0, harness.service_b)
            server_a.start_background()
            server_b.start_background()

            try:
                host_a, port_a = server_a.bound_address
                host_b, port_b = server_b.bound_address
                addr_a = f"{host_a}:{port_a}"
                addr_b = f"{host_b}:{port_b}"

                # 1. Run `lkmp preflight --json` over TCP sockets
                out_pre = StringIO()
                with patch("sys.stdout", out_pre):
                    rc_pre = cli_main(
                        [
                            "preflight",
                            "--pid",
                            "1234",
                            "--source",
                            addr_a,
                            "--dest",
                            addr_b,
                            "--no-tls",
                            "--json",
                        ]
                    )
                self.assertEqual(rc_pre, 0)
                pre_data = json.loads(out_pre.getvalue())
                self.assertTrue(pre_data["compatible"])

                # 2. Run `lkmp migrate --json` over TCP sockets
                out_mig = StringIO()
                with patch("sys.stdout", out_mig):
                    rc_mig = cli_main(
                        [
                            "migrate",
                            "--pid",
                            "1234",
                            "--workload-id",
                            "srv-1",
                            "--source",
                            addr_a,
                            "--dest",
                            addr_b,
                            "--strategy",
                            "pre-copy",
                            "--workload-ip",
                            "10.0.0.99/24",
                            "--no-tls",
                            "--json",
                        ]
                    )
                self.assertEqual(rc_mig, 0)
                mig_data = json.loads(out_mig.getvalue())
                self.assertTrue(mig_data["success"])
                self.assertEqual(mig_data["final_state"], "COMMIT")
                self.assertEqual(mig_data["restored_pid"], 5678)
                self.assertEqual(len(mig_data["precopy_iterations"]), 2)
            finally:
                server_a.shutdown()
                server_b.shutdown()


if __name__ == "__main__":
    unittest.main()
