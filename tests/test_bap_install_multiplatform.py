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
        """Test that get_source_binary locates binaries for Windows, macOS, and Linux."""
        platforms = ["windows-amd64", "darwin-arm64", "darwin-amd64", "linux-amd64", "linux-arm64"]
        
        for p in platforms:
            with patch("scripts.bap_install.get_platform_id", return_value=p):
                ext = ".exe" if p.startswith("windows") else ""
                with patch("sys.platform", "win32" if p.startswith("windows") else ("darwin" if p.startswith("darwin") else "linux")):
                    bapedge_path = bap_install.get_source_binary("bapedge")
                    self.assertTrue(os.path.isfile(bapedge_path), f"bapedge not found for platform {p}: {bapedge_path}")
                    self.assertTrue(bapedge_path.endswith("bapedge" + ext), f"Incorrect binary name {bapedge_path}")

                    interceptor_path = bap_install.get_source_binary("interceptor")
                    self.assertTrue(os.path.isfile(interceptor_path), f"interceptor not found for platform {p}: {interceptor_path}")

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
        wheels = [os.path.join(dist_dir, f) for f in os.listdir(dist_dir) if f.endswith(".whl") and "1.3.1" in f]
        self.assertTrue(len(wheels) > 0, "No version 1.3.1 wheel found in dist/")
        
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
