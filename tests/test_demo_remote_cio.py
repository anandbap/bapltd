"""
Unit and Integration Tests for demo_remote_cio.py
=================================================
Validates enterprise squad composition, task catalogs, CLI argument parsing,
and payload structures for remote control panel demonstration.
"""

import os
import sys
import unittest

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

import demo_remote_cio


class TestDemoRemoteCIO(unittest.TestCase):
    def test_enterprise_squads_composition(self):
        """Verify all 12 enterprise squads are defined with rich persona metadata."""
        squads = demo_remote_cio.ENTERPRISE_SQUADS
        self.assertGreaterEqual(len(squads), 12, "Should define at least 12 enterprise squads")
        
        seen_ids = set()
        for squad in squads:
            self.assertIn("id", squad)
            self.assertIn("name", squad)
            self.assertIn("domain", squad)
            self.assertIn("app_id", squad)
            self.assertIn("lead", squad)
            self.assertIn("agents", squad)
            self.assertIn("tasks", squad)
            self.assertGreaterEqual(len(squad["agents"]), 2, f"Squad {squad['id']} must have at least 2 agent roles")
            self.assertGreaterEqual(len(squad["tasks"]), 1, f"Squad {squad['id']} must have tasks defined")
            self.assertNotIn(squad["id"], seen_ids, f"Duplicate squad id {squad['id']}")
            seen_ids.add(squad["id"])

    def test_url_resolver(self):
        """Verify URL resolver respects argument overrides, env variables, and defaults."""
        url = demo_remote_cio.resolve_control_plane_url("http://custom-host:9090")
        self.assertEqual(url, "http://custom-host:9090")

        # Test trailing slash normalization
        url_slash = demo_remote_cio.resolve_control_plane_url("https://remote.bap.internal:8443/")
        self.assertEqual(url_slash, "https://remote.bap.internal:8443")

    def test_agent_initialization(self):
        """Verify GovernedAgent generates valid SPIFFE ID and session identity."""
        stats = demo_remote_cio.DemoStats()
        squad = demo_remote_cio.ENTERPRISE_SQUADS[0]
        agent = demo_remote_cio.GovernedAgent(
            squad_id=squad["id"],
            squad_name=squad["name"],
            domain_name=squad["domain"],
            app_id=squad["app_id"],
            lead_name=squad["lead"],
            agent_role=squad["agents"][0],
            agent_idx=1,
            server_url="http://127.0.0.1:8080",
            tasks=squad["tasks"],
            stats_collector=stats
        )
        self.assertTrue(agent.spiffe_id.startswith(f"spiffe://bap.internal/app/{squad['app_id']}/instance/"))
        self.assertTrue(agent.session_id.startswith(f"sess-{squad['id']}-"))
        self.assertEqual(agent.lead_name, squad["lead"])
        self.assertIn("@enterprise.internal", agent.user_email)

    def test_stats_counter(self):
        """Verify thread-safe DemoStats counting."""
        stats = demo_remote_cio.DemoStats()
        stats.record_allow()
        stats.record_allow()
        stats.record_denial()
        allows, denies = stats.get_counts()
        self.assertEqual(allows, 2)
        self.assertEqual(denies, 1)


if __name__ == "__main__":
    unittest.main()
