"""
test_agent_watch_v2.py: Comprehensive validation of Agent Watch V2 (Mission Control, Trust Command, Capability Atlas)
and complete preservation of legacy V1 functionality.
Uses only Python standard library.
"""

import os
import re
import unittest


class TestAgentWatchV2(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        cls.v2_html_path = os.path.join(cls.base_dir, "bap-controlplane", "internal", "dashboardui", "web", "v2.html")
        cls.v1_html_path = os.path.join(cls.base_dir, "bap-controlplane", "internal", "dashboardui", "web", "index.html")
        cls.server_go_path = os.path.join(cls.base_dir, "bap-controlplane", "internal", "dashboardui", "server.go")
        cls.matrix_doc_path = os.path.join(
            r"C:\Users\User\.gemini\antigravity\brain\1f6ca452-b244-4d51-90cb-1d44b9f8a1cd",
            "agent_watch_v2_feature_matrix_and_ia.md"
        )

        with open(cls.v2_html_path, "r", encoding="utf-8") as f:
            cls.v2_content = f.read()

        with open(cls.v1_html_path, "r", encoding="utf-8") as f:
            cls.v1_content = f.read()

        with open(cls.server_go_path, "r", encoding="utf-8") as f:
            cls.server_go = f.read()

    def test_routing_and_legacy_preservation_in_server(self):
        """Verify server.go provides dual routing for V2 and legacy V1."""
        self.assertIn("/dashboard/v2", self.server_go)
        self.assertIn("/dashboard/legacy", self.server_go)
        self.assertIn("v2.html", self.server_go)
        self.assertIn("index.html", self.server_go)
        self.assertIn('?v=legacy', self.server_go)

    def test_legacy_v1_has_v2_switcher(self):
        """Verify legacy V1 includes a clean switcher to V2."""
        self.assertIn("/dashboard/v2/", self.v1_content)
        self.assertIn("Agent Watch V2", self.v1_content)

    def test_v2_has_v1_switcher(self):
        """Verify V2 provides a seamless return toggle to Classic V1."""
        self.assertIn("/dashboard/?v=legacy", self.v2_content)
        self.assertIn("Classic V1", self.v2_content)

    def test_three_purpose_built_workspaces_present(self):
        """Verify the three dedicated workspaces exist with appropriate navigation."""
        button_ids = re.findall(r'data-ws=[\'"]([^\'"]+)[\'"]', self.v2_content)
        self.assertIn("mission-control", button_ids)
        self.assertIn("trust-command", button_ids)
        self.assertIn("capability-atlas", button_ids)

        self.assertIn('id="pane-mission-control"', self.v2_content)
        self.assertIn('id="pane-trust-command"', self.v2_content)
        self.assertIn('id="pane-capability-atlas"', self.v2_content)

    def test_mission_control_executive_summary_and_workstreams(self):
        """Verify Mission Control 10-second summary bar, honest metrics, and 6 canonical workstreams."""
        # 10-second summary bar elements
        self.assertIn('id="mcActiveAgents"', self.v2_content)
        self.assertIn('id="mcAssistedHours"', self.v2_content)
        self.assertIn('id="mcFTEEquiv"', self.v2_content)
        self.assertIn('id="mcPrevented"', self.v2_content)
        self.assertIn('id="mcDriftCount"', self.v2_content)

        # Check for Honest telemetry tags
        est_tags = re.findall(r'class=[\'"][^\'"]*tag-est[^\'"]*[\'"]', self.v2_content)
        self.assertGreaterEqual(len(est_tags), 2, "Assisted hours and FTE equivalent must be honestly tagged as ESTIMATED")

        # 6 Canonical Workstreams in script
        for ws in ['build', 'operate', 'analyze', 'document', 'support', 'unknown']:
            self.assertIn(f"id: '{ws}'", self.v2_content, f"Workstream {ws} must be defined")

    def test_activity_topology_map_and_text_alternative(self):
        """Verify the enterprise topology map has visual SVG and an accessible text alternative."""
        self.assertIn('id="topoSvg"', self.v2_content)
        self.assertIn('id="topologyTextAlt"', self.v2_content)
        self.assertIn('id="btnToggleTopoAlt"', self.v2_content)

        # Verify environments represented
        self.assertIn("Laptop Workstation", self.v2_content)
        self.assertIn("Linux Fleet Worker", self.v2_content)
        self.assertIn("Cloud & Vendor MCP", self.v2_content)
        self.assertIn("HookWatch Active", self.v2_content)

    def test_trust_command_subtabs_and_controls(self):
        """Verify Trust Command covers all operational controls: fleet, decisions, grants, policies, audit, step-up, recon, helpdesk."""
        expected_tabs = ['fleet', 'decisions', 'grants', 'policies', 'audit', 'approvals', 'recon', 'helpdesk']
        tc_buttons = re.findall(r'data-tctab=[\'"]([^\'"]+)[\'"]', self.v2_content)
        for tab in expected_tabs:
            self.assertIn(tab, tc_buttons, f"Trust Command tab {tab} must be present")

        # Emergency controls
        self.assertIn('id="killModal"', self.v2_content)
        self.assertIn('id="modalConfirmInput"', self.v2_content)
        self.assertIn("executeScopedEmergencyAction", self.v2_content)

    def test_capability_atlas_12_domains_and_vendors(self):
        """Verify Capability Atlas has all 12 domains, 4 seeded vendors, and evidence inspection."""
        expected_domains = [
            'identity', 'interception', 'containment', 'policy', 'honeytokens',
            'jit', 'delegation', 'antibypass', 'prompt', 'fim', 'hitl', 'audit'
        ]
        for d in expected_domains:
            self.assertIn(f"id: '{d}'", self.v2_content, f"Domain {d} must be defined in ATLAS_DOMAINS")

        # Vendors
        for vendor in ['bap', 'keycard', 'runlayer', 'air']:
            self.assertIn(f"{vendor}:", self.v2_content, f"Vendor {vendor} must be seeded in ATLAS_DOMAINS")

        # BAP lifecycle stages
        for stage in ['designed', 'implemented', 'integration-tested', 'deployed']:
            self.assertIn(f"'{stage}'", self.v2_content)

        # Drawer inspection
        self.assertIn('id="drawerOverlay"', self.v2_content)
        self.assertIn("openAtlasEvidence", self.v2_content)

    def test_feature_preservation_matrix_exists(self):
        """Verify the comprehensive preservation matrix artifact document exists and covers key criteria."""
        self.assertTrue(os.path.exists(self.matrix_doc_path), "Feature Preservation Matrix artifact must exist")
        with open(self.matrix_doc_path, "r", encoding="utf-8") as f:
            matrix_text = f.read()

        self.assertIn("Mission Control", matrix_text)
        self.assertIn("Trust Command", matrix_text)
        self.assertIn("Capability Atlas", matrix_text)
        self.assertIn("Preserved & Enhanced", matrix_text)


if __name__ == "__main__":
    unittest.main()
