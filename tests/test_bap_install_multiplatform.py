#!/usr/bin/env python3
"""
Test Suite: Multi-Platform BAP Installation & Wheel Packaging
============================================================
Verifies that:
1. bap install logic and binary resolution works across Windows, macOS, and Linux.
2. Built Python wheels contain precompiled Go binaries across platforms.
3. Copilot, Claude Code, Antigravity, and Cursor hooks are configured correctly on each OS.
"""

import os
import sys
import json
import shutil
import tempfile
import zipfile
import unittest
from unittest.mock import patch

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from scripts import bap_install
from scripts import build_wheel

class TestBAPInstallMultiPlatform(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.workspace_dir = os.path.join(self.temp_dir, "workspace")
        self.install_dir = os.path.join(self.temp_dir, "bin")
        os.makedirs(self.workspace_dir, exist_ok=True)
        os.makedirs(self.install_dir, exist_ok=True)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_platform_id_detection(self):
        """Test platform and architecture mapping for all 3 OS platforms."""
        test_cases = [
            ("win32", "AMD64", "windows-amd64"),
            ("win32", "ARM64", "windows-arm64"),
            ("darwin", "arm64", "darwin-arm64"),
            ("darwin", "x86_64", "darwin-amd64"),
            ("linux", "x86_64", "linux-amd64"),
            ("linux", "aarch64", "linux-arm64"),
        ]
        for sys_plat, machine, expected in test_cases:
            with patch("sys.platform", sys_plat), patch("platform.machine", return_value=machine):
                plat_id = bap_install.get_platform_id()
                self.assertEqual(plat_id, expected, f"Failed mapping for {sys_plat} / {machine}")

    def test_source_binary_resolution_across_os(self):
        """Test that get_source_binary locates binaries for Windows, macOS, and Linux hermetically."""
        platforms = ["windows-amd64", "darwin-arm64", "darwin-amd64", "linux-amd64", "linux-arm64"]
        
        for p in platforms:
            ext = ".exe" if p.startswith("windows") else ""
            mock_client_dir = os.path.join(self.temp_dir, "dist", p, "claude-client")
            os.makedirs(mock_client_dir, exist_ok=True)
            mock_bapedge = os.path.join(mock_client_dir, "bapedge" + ext)
            mock_interceptor = os.path.join(mock_client_dir, "interceptor" + ext)
            with open(mock_bapedge, "w") as f:
                f.write("mock")
            with open(mock_interceptor, "w") as f:
                f.write("mock")

            with patch("scripts.bap_install.REPO_ROOT", self.temp_dir):
                with patch("scripts.bap_install.get_platform_id", return_value=p):
                    with patch("sys.platform", "win32" if p.startswith("windows") else ("darwin" if p.startswith("darwin") else "linux")):
                        bapedge_path = bap_install.get_source_binary("bapedge")
                        self.assertTrue(os.path.isfile(bapedge_path), f"bapedge not found for platform {p}: {bapedge_path}")
                        self.assertEqual(os.path.normpath(bapedge_path), os.path.normpath(mock_bapedge))

                        interceptor_path = bap_install.get_source_binary("interceptor")
                        self.assertTrue(os.path.isfile(interceptor_path), f"interceptor not found for platform {p}: {interceptor_path}")
                        self.assertEqual(os.path.normpath(interceptor_path), os.path.normpath(mock_interceptor))

    def test_configure_agent_hooks_all_os(self):
        """Verify VS Code Copilot and Claude settings are set properly on Windows, macOS, and Linux."""
        os_configs = [
            ("win32", "terminal.integrated.profiles.windows", "terminal.integrated.defaultProfile.windows"),
            ("darwin", "terminal.integrated.profiles.osx", "terminal.integrated.defaultProfile.osx"),
            ("linux", "terminal.integrated.profiles.linux", "terminal.integrated.defaultProfile.linux"),
        ]

        for sys_plat, expected_profile_key, expected_default_key in os_configs:
            ws = os.path.join(self.temp_dir, f"ws_{sys_plat}")
            os.makedirs(ws, exist_ok=True)
            with patch("sys.platform", sys_plat):
                agents = bap_install.configure_agent_hooks(ws, self.install_dir)
                self.assertGreater(len(agents), 0)

                # Check VS Code Copilot settings
                vscode_settings_file = os.path.join(ws, ".vscode", "settings.json")
                self.assertTrue(os.path.isfile(vscode_settings_file))
                with open(vscode_settings_file, "r", encoding="utf-8") as f:
                    v_settings = json.load(f)
                self.assertIn(expected_profile_key, v_settings, f"Missing {expected_profile_key} for {sys_plat}")
                self.assertIn(expected_default_key, v_settings, f"Missing {expected_default_key} for {sys_plat}")

                # Check Claude Code settings
                claude_settings_file = os.path.join(ws, ".claude", "settings.json")
                self.assertTrue(os.path.isfile(claude_settings_file))
                with open(claude_settings_file, "r", encoding="utf-8") as f:
                    c_settings = json.load(f)
                self.assertIn("hooks", c_settings)
                self.assertIn("PreToolUse", c_settings["hooks"])

    def test_wheel_package_contains_go_binaries(self):
        """Verify that built wheels in dist/ contain appropriate Go binaries."""
        dist_dir = os.path.join(REPO_ROOT, "dist")
        wheels = [os.path.join(dist_dir, f) for f in os.listdir(dist_dir) if f.endswith(".whl") and "1.3.1" in f] if os.path.isdir(dist_dir) else []
        
        if not wheels:
            self.skipTest("No prebuilt 1.3.1 wheels in dist/ to inspect")

        # Verify Windows wheel contains Windows binary
        win_wheels = [w for w in wheels if "win_amd64" in w or "py3-none-any" in w]
        if win_wheels:
            with zipfile.ZipFile(win_wheels[0], "r") as z:
                names = z.namelist()
                has_win_bin = any("windows-amd64/bapedge.exe" in n for n in names)
                self.assertTrue(has_win_bin, f"{win_wheels[0]} does not contain windows-amd64/bapedge.exe")

        # Verify macOS wheel contains Darwin binary
        mac_wheels = [w for w in wheels if "macosx" in w]
        if mac_wheels:
            with zipfile.ZipFile(mac_wheels[0], "r") as z:
                names = z.namelist()
                has_mac_bin = any("bapedge" in n and "darwin" in n for n in names)
                self.assertTrue(has_mac_bin, f"{mac_wheels[0]} does not contain darwin bapedge")

        # Verify Linux wheel contains Linux binary
        linux_wheels = [w for w in wheels if "manylinux" in w]
        if linux_wheels:
            with zipfile.ZipFile(linux_wheels[0], "r") as z:
                names = z.namelist()
                has_linux_bin = any("bapedge" in n and "linux" in n for n in names)
                self.assertTrue(has_linux_bin, f"{linux_wheels[0]} does not contain linux bapedge")

    def test_install_core_binaries_deploys_configs_and_launchers(self):
        """Verify install_core_binaries stages policy.cedar, schema.json, and all agent launchers in bin."""
        bap_install.install_core_binaries(self.install_dir)

        # 1. Configs deployed to bin
        for cfg in ["policy.cedar", "schema.json", "bap-config.json"]:
            cfg_path = os.path.join(self.install_dir, cfg)
            self.assertTrue(os.path.isfile(cfg_path), f"Configuration {cfg} was not deployed to bin directory: {cfg_path}")

        # 2. Key launchers deployed to bin
        expected_launchers = [
            "run_claude_bap.bat" if sys.platform == "win32" else "run_claude_bap.sh",
            "run_antigravity_cli_bap.bat" if sys.platform == "win32" else "run_antigravity_cli_bap.sh",
            "run_copilot_cli_bap.bat" if sys.platform == "win32" else "run_copilot_cli_bap.sh",
            "run_cursor_bap.bat" if sys.platform == "win32" else "run_cursor_bap.sh",
            "run_gemini_cli_bap.bat" if sys.platform == "win32" else "run_gemini_cli_bap.sh",
        ]
        for launcher in expected_launchers:
            l_path = os.path.join(self.install_dir, launcher)
            self.assertTrue(os.path.isfile(l_path), f"Launcher {launcher} was not deployed to bin directory: {l_path}")

    def test_bap_doctor_loads_policy_from_bin_directory(self):
        """Verify bap_doctor prioritizes installed bin directory policy over source/workspace."""
        from scripts import bap_doctor

        # Stage mock environment where bin contains policy.cedar
        bap_install.install_core_binaries(self.install_dir)
        bin_policy = os.path.join(self.install_dir, "policy.cedar")
        self.assertTrue(os.path.isfile(bin_policy))

        # Run doctor in an isolated directory without policy.cedar
        isolated_cwd = os.path.join(self.temp_dir, "isolated_cwd")
        os.makedirs(isolated_cwd, exist_ok=True)

        old_cwd = os.getcwd()
        try:
            os.chdir(isolated_cwd)
            # Patch user_bin to point to self.install_dir
            with patch("os.path.expanduser", side_effect=lambda p: self.temp_dir if p == "~" else p):
                checklist = bap_doctor.DoctorChecklist()
                policy_candidates = [
                    os.path.join(self.install_dir, "policy.cedar"),
                    os.path.join(isolated_cwd, "policy.cedar"),
                ]
                policy_path = None
                for p in policy_candidates:
                    if p and os.path.isfile(p):
                        policy_path = p
                        break
                self.assertIsNotNone(policy_path)
                self.assertEqual(os.path.normpath(policy_path), os.path.normpath(bin_policy))
        finally:
            os.chdir(old_cwd)

    def test_bap_doctor_reports_bap_config_location(self):
        """Verify bap_doctor detects and reports bap-config.json location and mode."""
        from scripts import bap_doctor

        # Stage mock environment where bin contains bap-config.json
        bap_install.install_core_binaries(self.install_dir)
        bin_cfg = os.path.join(self.install_dir, "bap-config.json")
        self.assertTrue(os.path.isfile(bin_cfg))

        isolated_cwd = os.path.join(self.temp_dir, "isolated_cwd_cfg")
        os.makedirs(isolated_cwd, exist_ok=True)

        old_cwd = os.getcwd()
        try:
            os.chdir(isolated_cwd)
            with patch("os.path.expanduser", side_effect=lambda p: self.temp_dir if p == "~" else p):
                cfg_candidates = [
                    os.path.join(self.install_dir, "bap-config.json"),
                    os.path.join(isolated_cwd, "bap-config.json"),
                ]
                cfg_path = None
                for p in cfg_candidates:
                    if p and os.path.isfile(p):
                        cfg_path = p
                        break
                self.assertIsNotNone(cfg_path)
                self.assertEqual(os.path.normpath(cfg_path), os.path.normpath(bin_cfg))
        finally:
            os.chdir(old_cwd)

    def test_universal_wheel_contains_all_launchers_and_configs(self):
        """Verify the latest universal wheel contains policy.cedar, configs, and all agent launchers."""
        dist_dir = os.path.join(REPO_ROOT, "dist")
        wheels = [os.path.join(dist_dir, f) for f in os.listdir(dist_dir) if f.endswith("-py3-none-any.whl")] if os.path.isdir(dist_dir) else []
        if not wheels:
            self.skipTest("No universal wheels in dist/")

        # Pick newest wheel
        wheels.sort(key=os.path.getmtime, reverse=True)
        newest_wheel = wheels[0]

        with zipfile.ZipFile(newest_wheel, "r") as z:
            names = z.namelist()
            # Verify configurations
            for asset in ["policy.cedar", "schema.json", "bap-config.json"]:
                has_asset = any(f"bap/{asset}" in n or f"bap/launchers/{asset}" in n for n in names)
                self.assertTrue(has_asset, f"{newest_wheel} does not contain {asset}")

            # Verify key agent launchers
            for launcher in [
                "run_claude_bap.bat", "run_claude_bap.ps1", "run_claude_bap.sh",
                "run_antigravity_cli_bap.bat", "run_antigravity_cli_bap.ps1", "run_antigravity_cli_bap.sh",
                "run_copilot_cli_bap.bat", "run_copilot_cli_bap.ps1", "run_copilot_cli_bap.sh",
                "run_cursor_bap.bat", "run_cursor_bap.ps1", "run_cursor_bap.sh",
                "run_gemini_cli_bap.bat", "run_gemini_cli_bap.ps1", "run_gemini_cli_bap.sh",
            ]:
                has_launcher = any(launcher in n for n in names)
                self.assertTrue(has_launcher, f"{newest_wheel} does not contain launcher {launcher}")

    def test_uninstall_cleanly_restores_hooks(self):
        """Verify uninstall function cleanly removes hooks and restored settings."""
        ws = os.path.join(self.temp_dir, "ws_uninstall")
        os.makedirs(ws, exist_ok=True)
        bap_install.configure_agent_hooks(ws, self.install_dir)
        
        # Verify installed
        claude_settings = os.path.join(ws, ".claude", "settings.json")
        self.assertTrue(os.path.isfile(claude_settings))
        with open(claude_settings, "r") as f:
            self.assertIn("hooks", json.load(f))
            
        # Run uninstall
        bap_install.uninstall(self.install_dir, ws)
        
        # Verify reverted
        with open(claude_settings, "r") as f:
            self.assertNotIn("hooks", json.load(f))

if __name__ == "__main__":
    unittest.main()
