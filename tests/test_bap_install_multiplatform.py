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
                agents = bap_install.configure_agent_hooks(ws, self.install_dir, portable=True)
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
        wheels = [os.path.join(dist_dir, f) for f in os.listdir(dist_dir) if f.startswith("bap_ltd-") and f.endswith(".whl")] if os.path.isdir(dist_dir) else []
        
        if not wheels:
            if os.environ.get("BAP_REQUIRE_WHEEL_TESTS") == "1":
                self.fail("Release gate requires a built BAP wheel in dist/")
            self.skipTest("No built BAP wheels in dist/ to inspect")

        wheels.sort(key=os.path.getmtime, reverse=True)
        universal = [w for w in wheels if w.endswith("-py3-none-any.whl")]
        if universal:
            with zipfile.ZipFile(universal[0], "r") as archive:
                for target in ("windows-amd64", "linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64"):
                    extension = ".exe" if target.startswith("windows") else ""
                    for binary in ("bapedge", "interceptor"):
                        name = f"bap/bin/{target}/{binary}{extension}"
                        self.assertIn(name, archive.namelist())
                        with archive.open(name) as stream:
                            magic = stream.read(4)
                        if target.startswith("windows"):
                            self.assertTrue(magic.startswith(b"MZ"), name)
                        elif target.startswith("linux"):
                            self.assertEqual(magic, b"\x7fELF", name)
                        else:
                            self.assertIn(magic, (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf"), name)

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
            if os.environ.get("BAP_REQUIRE_WHEEL_TESTS") == "1":
                self.fail("Release gate requires a universal BAP wheel in dist/")
            self.skipTest("No universal wheels in dist/")

        # Pick newest wheel
        wheels.sort(key=os.path.getmtime, reverse=True)
        newest_wheel = wheels[0]

        with zipfile.ZipFile(newest_wheel, "r") as z:
            names = z.namelist()
            for helper in ("review_session.ps1", "review_session_impl.ps1", "session_calls.ps1"):
                self.assertIn(f"bap/{helper}", names, f"Missing packaged review helper {helper}")
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
        mock_home = os.path.join(self.temp_dir, "uninstall_home")
        os.makedirs(mock_home, exist_ok=True)

        with patch("os.path.expanduser", side_effect=lambda p: mock_home + p[1:] if p.startswith("~") else p):
            bap_install.configure_agent_hooks(ws, self.install_dir)

            # Verify installed
            claude_settings = os.path.join(ws, ".claude", "settings.json")
            self.assertTrue(os.path.isfile(claude_settings))
            with open(claude_settings, "r") as f:
                self.assertIn("hooks", json.load(f))

            # Run uninstall
            with patch.object(bap_install, "stop_running_bap_processes"), \
                 patch("scripts.bap_startup.configure_startup"):
                bap_install.uninstall(self.install_dir, ws)
        
        # Verify reverted
        with open(claude_settings, "r") as f:
            self.assertNotIn("hooks", json.load(f))

    def test_safe_copy_and_safe_remove_file(self):
        """Verify safe_copy_binary and safe_remove_file correctly handle files."""
        src_file = os.path.join(self.temp_dir, "test_bin.exe")
        with open(src_file, "w") as f:
            f.write("binary content v2")

        dst_file = os.path.join(self.install_dir, "test_bin.exe")
        with open(dst_file, "w") as f:
            f.write("binary content v1")

        # Test safe copy
        bap_install.safe_copy_binary(src_file, dst_file)
        with open(dst_file, "r") as f:
            self.assertEqual(f.read(), "binary content v2")

        # Test safe remove
        bap_install.safe_remove_file(dst_file)
        self.assertFalse(os.path.isfile(dst_file))

    def test_clean_stale_secondary_installations_preserves_pip_scripts(self):
        """Verify clean_stale_secondary_installations preserves pip-installed Python entry points (bap, bapedge)."""
        secondary_dir = os.path.join(self.temp_dir, ".local", "bin")
        os.makedirs(secondary_dir, exist_ok=True)
        
        # Simulate pip-installed console scripts in ~/.local/bin
        pip_bap = os.path.join(secondary_dir, "bap")
        with open(pip_bap, "w", encoding="utf-8") as f:
            f.write("#!/usr/bin/env python3\nfrom bap.cli import main\nmain()\n")

        pip_bapedge = os.path.join(secondary_dir, "bapedge")
        with open(pip_bapedge, "w", encoding="utf-8") as f:
            f.write("#!/usr/bin/env python3\nfrom bap.cli import bapedge_proxy\nbapedge_proxy()\n")

        # Also create a stale compiled binary that SHOULD be removed
        stale_interceptor = os.path.join(secondary_dir, "interceptor")
        with open(stale_interceptor, "wb") as f:
            f.write(b"\x7fELFfakebinarydata")

        # Temporarily mock get_all_bap_candidate_dirs to include secondary_dir
        with patch("scripts.bap_install.get_all_bap_candidate_dirs", return_value=[self.install_dir, secondary_dir]):
            with patch.dict(os.environ, {"BAP_ALLOW_TEST_PURGE": "1"}):
                bap_install.clean_stale_secondary_installations(self.install_dir)

        # bap and bapedge python scripts MUST be preserved
        self.assertTrue(os.path.isfile(pip_bap), "clean_stale_secondary_installations wiped pip entrypoint 'bap'!")
        self.assertTrue(os.path.isfile(pip_bapedge), "clean_stale_secondary_installations wiped pip entrypoint 'bapedge'!")
        # Stale compiled binary MUST be cleaned
        self.assertFalse(os.path.isfile(stale_interceptor), "Stale binary was not cleaned!")

    def test_install_core_binaries_deploys_bap_wrapper(self):
        """Verify install_core_binaries deploys bap wrapper across Unix and Windows platforms."""
        for sys_plat in ["darwin", "linux", "win32"]:
            test_bin = os.path.join(self.temp_dir, f"bin_{sys_plat}")
            os.makedirs(test_bin, exist_ok=True)
            with patch("sys.platform", sys_plat):
                bap_install.install_core_binaries(test_bin)
                bap_wrapper = os.path.join(test_bin, "bap")
                self.assertTrue(os.path.isfile(bap_wrapper), f"bap wrapper missing in {test_bin} on {sys_plat}")
                if sys_plat == "win32":
                    self.assertTrue(os.path.isfile(os.path.join(test_bin, "bap.cmd")))

    def test_find_bapedge_skips_python_shims(self):
        """Verify find_bapedge in bap.cli distinguishes compiled native binaries from Python script shims."""
        from bap import cli as bap_cli
        shim_dir = os.path.join(self.temp_dir, "shim_bin")
        real_dir = os.path.join(self.temp_dir, "real_bin")
        os.makedirs(shim_dir, exist_ok=True)
        os.makedirs(real_dir, exist_ok=True)

        shim_edge = os.path.join(shim_dir, "bapedge")
        with open(shim_edge, "w", encoding="utf-8") as f:
            f.write("#!/usr/bin/env python3\nfrom bap.cli import bapedge_proxy\n")

        real_edge = os.path.join(real_dir, "bapedge")
        with open(real_edge, "wb") as f:
            # macOS 64-bit Mach-O magic
            f.write(b"\xcf\xfa\xed\xfe\x00\x00\x00\x00" + b"\x00" * 100)

        self.assertFalse(bap_cli.is_real_binary(shim_edge))
        with patch("sys.platform", "darwin"):
            self.assertTrue(bap_cli.is_real_binary(real_edge))

    def test_debug_flag_controls_diagnostic_scripts_deployment(self):
        """Verify that debugging scripts (bap review, watch_session, verify_sts, check_stale_copies)
        are only deployed when --debug is active, and omitted in default minimal installs."""
        test_bin_default = os.path.join(self.temp_dir, "bin_default")
        test_bin_debug = os.path.join(self.temp_dir, "bin_debug")
        os.makedirs(test_bin_default, exist_ok=True)
        os.makedirs(test_bin_debug, exist_ok=True)

        # 1. Default install (without debug scripts)
        bap_install.install_core_binaries(test_bin_default)
        self.assertFalse(os.path.isfile(os.path.join(test_bin_default, "review_session.ps1")))
        self.assertFalse(os.path.isfile(os.path.join(test_bin_default, "watch_session.ps1")))
        self.assertFalse(os.path.isfile(os.path.join(test_bin_default, "check_stale_copies.ps1")))
        self.assertFalse(os.path.isfile(os.path.join(test_bin_default, "verify_sts_obo_exchange.py")))

        # 2. Debug install (--debug active)
        deployed_count = bap_install.install_debug_scripts(test_bin_debug)
        self.assertGreater(deployed_count, 0)
        self.assertTrue(os.path.isfile(os.path.join(test_bin_debug, "review_session.ps1")))
        self.assertTrue(os.path.isfile(os.path.join(test_bin_debug, "review_session_impl.ps1")))
        self.assertTrue(os.path.isfile(os.path.join(test_bin_debug, "session_calls.ps1")))
        self.assertTrue(os.path.isfile(os.path.join(test_bin_debug, "watch_session.ps1")))
        self.assertTrue(os.path.isfile(os.path.join(test_bin_debug, "check_stale_copies.ps1")))
        self.assertTrue(os.path.isfile(os.path.join(test_bin_debug, "check_stale_copies.bat")))
        self.assertTrue(os.path.isfile(os.path.join(test_bin_debug, "verify_sts_obo_exchange.py")))

    def test_install_native_agent_plugins_refreshes_stale_hook_adapter_exe(self):
        """Verify upgrading overwrites stale bap-hook-adapter.exe across workspace, global, and Claude plugin cache dirs."""
        mock_home = os.path.join(self.temp_dir, "home")
        os.makedirs(mock_home, exist_ok=True)
        new_edge = os.path.join(self.install_dir, "bapedge.exe")
        new_bytes = b"MZ" + b"NEW_BAPEDGE_1_12_26" + b"\x00" * 64
        with open(new_edge, "wb") as f:
            f.write(new_bytes)

        stale_bytes = b"MZ" + b"OLD_STALE_ADAPTER" + b"\x00" * 64
        stale_paths = [
            os.path.join(self.workspace_dir, "plugins", "claude", "scripts", "bap-hook-adapter.exe"),
            os.path.join(mock_home, ".claude", "plugins", "claude", "scripts", "bap-hook-adapter.exe"),
            os.path.join(mock_home, ".claude", "plugins", "cache", "bap", "scripts", "bap-hook-adapter.exe"),
        ]
        for sp in stale_paths:
            os.makedirs(os.path.dirname(sp), exist_ok=True)
            with open(sp, "wb") as f:
                f.write(stale_bytes)

        with patch("sys.platform", "win32"), \
             patch("os.path.expanduser", side_effect=lambda p: mock_home + p[1:] if p.startswith("~") else p):
            bap_install.install_native_agent_plugins(self.workspace_dir, self.install_dir)

        for sp in stale_paths:
            with open(sp, "rb") as f:
                self.assertEqual(f.read(), new_bytes, f"Stale bap-hook-adapter.exe was not refreshed at {sp}")

    def test_get_source_binary_prefers_newest_mtime(self):
        """Verify get_source_binary picks the newest binary by mtime instead of returning stale staged copy."""
        plat = bap_install.get_platform_id()
        ext = ".exe" if sys.platform == "win32" else ""
        staged = os.path.join(self.temp_dir, "bap", "bin", plat, f"bapedge{ext}")
        fresh = os.path.join(self.temp_dir, "bap-edge", f"bapedge{ext}")
        os.makedirs(os.path.dirname(staged), exist_ok=True)
        os.makedirs(os.path.dirname(fresh), exist_ok=True)
        with open(staged, "wb") as f:
            f.write(b"MZ" + b"OLD_STAGED" + b"\x00" * 32)
        with open(fresh, "wb") as f:
            f.write(b"MZ" + b"NEW_BUILD" + b"\x00" * 32)
        now = time.time() if "time" in globals() else __import__("time").time()
        os.utime(staged, (now - 3600, now - 3600))
        os.utime(fresh, (now, now))

        with patch.object(bap_install, "REPO_ROOT", self.temp_dir):
            chosen = bap_install.get_source_binary("bapedge")
        self.assertEqual(os.path.normpath(chosen), os.path.normpath(fresh))

    def test_clean_workspace_mode_avoids_workspace_clutter_and_uses_bin_bapstate(self):
        """Verify global default mode uses ~/bin/.bapstate and leaves clean project workspaces untouched."""
        mock_home = os.path.join(self.temp_dir, "clean_home")
        clean_ws = os.path.join(self.temp_dir, "clean_project")
        clean_bin = os.path.join(mock_home, "bin")
        os.makedirs(clean_ws, exist_ok=True)
        os.makedirs(clean_bin, exist_ok=True)

        with patch("os.path.expanduser", side_effect=lambda p: mock_home + p[1:] if p.startswith("~") else p), \
             patch.dict(os.environ, {"BAP_STATE_DIR": ""}, clear=False):
            os.environ.pop("BAP_STATE_DIR", None)
            self.assertEqual(
                os.path.normpath(bap_install.get_bapstate_dir()),
                os.path.normpath(os.path.join(mock_home, "bin", ".bapstate")),
            )
            bap_install.configure_bap_config(clean_bin, clean_ws, "http://localhost:8080", is_offline=True, write_workspace=False)
            bap_install.configure_agent_hooks(clean_ws, clean_bin, workspace_hooks=False)

        for clutter in (".bap", ".bapstate", ".claude", ".codex", ".cursor", ".cursorrules", ".vscode", ".antigravity", "GEMINI.md", "bap-config.json", "plugins"):
            self.assertFalse(os.path.exists(os.path.join(clean_ws, clutter)), f"Unexpected workspace clutter created: {clutter}")

        self.assertTrue(os.path.isfile(os.path.join(mock_home, "bin", ".bapstate", "config.json")))
        self.assertTrue(os.path.isfile(os.path.join(mock_home, ".claude", "settings.json")))
        self.assertTrue(os.path.isfile(os.path.join(mock_home, ".codex", "hooks.json")))
        self.assertTrue(os.path.isdir(os.path.join(clean_bin, "plugins", "claude")))

    def test_clean_workspace_clutter_removes_bap_files_and_preserves_env(self):
        """Verify clean_workspace_clutter removes legacy BAP clutter without touching .env or user code."""
        ws = os.path.join(self.temp_dir, "dirty_ws")
        os.makedirs(os.path.join(ws, ".bap"), exist_ok=True)
        os.makedirs(os.path.join(ws, ".bapstate"), exist_ok=True)
        os.makedirs(os.path.join(ws, "plugins", "claude"), exist_ok=True)
        with open(os.path.join(ws, "bap-gateway.pid"), "w") as f:
            f.write("12345")
        with open(os.path.join(ws, "bap-config.json"), "w") as f:
            f.write('{"controlplane_url": "http://localhost:8080"}')
        with open(os.path.join(ws, ".env"), "w") as f:
            f.write("USER_SECRET=keep\n")

        bap_install.clean_workspace_clutter(ws)

        self.assertFalse(os.path.exists(os.path.join(ws, ".bap")))
        self.assertFalse(os.path.exists(os.path.join(ws, ".bapstate")))
        self.assertFalse(os.path.exists(os.path.join(ws, "plugins")))
        self.assertFalse(os.path.exists(os.path.join(ws, "bap-gateway.pid")))
        self.assertFalse(os.path.exists(os.path.join(ws, "bap-config.json")))
        self.assertTrue(os.path.isfile(os.path.join(ws, ".env")))

    def test_portable_requires_dir(self):
        """Verify --portable/--isolated refuses to run without an explicit --dir target."""
        with patch("sys.argv", ["bap_install", "--portable", "--offline", "--non-interactive"]):
            with self.assertRaises(SystemExit) as ctx:
                bap_install.main()
            self.assertEqual(ctx.exception.code, 1)

    def test_portable_mode_is_self_contained_and_skips_home_and_path(self):
        """Verify --portable --dir <path> stores state in <dir>/.bapstate and leaves ~ and workspace clean."""
        mock_home = os.path.join(self.temp_dir, "portable_home")
        real_user_bin = os.path.join(mock_home, "bin")
        real_user_bap = os.path.join(mock_home, ".bap")
        real_user_bapstate = os.path.join(real_user_bin, ".bapstate")
        os.makedirs(real_user_bapstate, exist_ok=True)
        os.makedirs(real_user_bap, exist_ok=True)
        sentinel_bin = os.path.join(real_user_bin, "bap-config.json")
        sentinel_home = os.path.join(real_user_bap, "bap-config.json")
        with open(sentinel_bin, "w", encoding="utf-8") as f:
            f.write("KEEP_HOST_BIN")
        with open(sentinel_home, "w", encoding="utf-8") as f:
            f.write("KEEP_HOST_BAP")

        portable_dir = os.path.join(self.temp_dir, "portable_bundle")
        clean_ws = os.path.join(self.temp_dir, "portable_ws")
        os.makedirs(clean_ws, exist_ok=True)

        argv = [
            "bap_install",
            "--portable",
            "--dir", portable_dir,
            "--workspace", clean_ws,
            "--offline",
            "--non-interactive",
            "--no-rebuild",
        ]
        env_patch = {
            "HOME": mock_home,
            "USERPROFILE": mock_home,
            "BAP_STATE_DIR": "",
            "BAP_ZSP_DIR": "",
        }
        with patch("sys.argv", argv), \
             patch.dict(os.environ, env_patch, clear=False), \
             patch("os.path.expanduser", side_effect=lambda p: mock_home + p[1:] if p.startswith("~") else p), \
             patch.object(bap_install, "inspect_release_sources", return_value=(None, {"status": "test_unmanifested", "source_qualified": False})), \
             patch.object(bap_install, "update_user_path") as mock_path, \
             patch.object(bap_install, "deploy_powershell_profile") as mock_ps, \
             patch.object(bap_install, "clean_stale_secondary_installations") as mock_clean_stale:
            os.environ.pop("BAP_STATE_DIR", None)
            os.environ.pop("BAP_ZSP_DIR", None)
            bap_install.main()

        mock_path.assert_not_called()
        mock_ps.assert_not_called()
        # Note: install_core_binaries calls clean_stale_secondary_installations(..., portable=True)
        mock_clean_stale.assert_called_once_with(os.path.abspath(portable_dir), portable=True)

        # Self-contained state & artifacts exist inside portable_dir
        self.assertTrue(os.path.isfile(os.path.join(portable_dir, "bap-config.json")))
        self.assertTrue(os.path.isfile(os.path.join(portable_dir, ".bapstate", "config.json")))
        self.assertTrue(os.path.isfile(os.path.join(portable_dir, ".bapstate", "release-provenance.json")))
        self.assertTrue(os.path.isdir(os.path.join(portable_dir, "plugins", "claude")))

        # Host home dirs & clean workspace untouched
        self.assertFalse(os.path.exists(os.path.join(mock_home, ".claude")))
        self.assertFalse(os.path.exists(os.path.join(mock_home, ".codex")))
        for clutter in (".bap", ".bapstate", ".claude", ".codex", ".cursor", ".vscode", "GEMINI.md", "bap-config.json", "plugins"):
            self.assertFalse(os.path.exists(os.path.join(clean_ws, clutter)), f"Unexpected workspace clutter in portable mode: {clutter}")
        with open(sentinel_bin, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), "KEEP_HOST_BIN")
        with open(sentinel_home, "r", encoding="utf-8") as f:
            self.assertEqual(f.read(), "KEEP_HOST_BAP")

    def test_portable_uninstall_is_strictly_scoped_to_dir(self):
        """Verify --uninstall --portable --dir <path> removes <dir> cleanly without touching ~ or CWD."""
        mock_home = os.path.join(self.temp_dir, "pu_home")
        user_bin_sentinel = os.path.join(mock_home, "bin", "bap-config.json")
        dot_bap_sentinel = os.path.join(mock_home, ".bap", "bap-config.json")
        os.makedirs(os.path.dirname(user_bin_sentinel), exist_ok=True)
        os.makedirs(os.path.dirname(dot_bap_sentinel), exist_ok=True)
        with open(user_bin_sentinel, "w", encoding="utf-8") as f:
            f.write("KEEP")
        with open(dot_bap_sentinel, "w", encoding="utf-8") as f:
            f.write("KEEP")

        portable_dir = os.path.join(self.temp_dir, "pu_bundle")
        os.makedirs(os.path.join(portable_dir, ".bapstate"), exist_ok=True)
        os.makedirs(os.path.join(portable_dir, "plugins", "claude"), exist_ok=True)
        with open(os.path.join(portable_dir, "bap-config.json"), "w", encoding="utf-8") as f:
            f.write("{}")
        with open(os.path.join(portable_dir, ".bapstate", "config.json"), "w", encoding="utf-8") as f:
            f.write("{}")

        # Uninstalling from CWD containing workspace clutter must not delete unrelated workspace files when --workspace is omitted.
        unrelated_cwd = os.path.join(self.temp_dir, "unrelated_cwd")
        os.makedirs(os.path.join(unrelated_cwd, ".bap"), exist_ok=True)
        cwd_marker = os.path.join(unrelated_cwd, ".bap", "keep.txt")
        with open(cwd_marker, "w", encoding="utf-8") as f:
            f.write("KEEP")

        old_cwd = os.getcwd()
        try:
            os.chdir(unrelated_cwd)
            with patch("sys.argv", ["bap_install", "--uninstall", "--portable", "--dir", portable_dir]), \
                 patch("os.path.expanduser", side_effect=lambda p: mock_home + p[1:] if p.startswith("~") else p):
                with self.assertRaises(SystemExit) as ctx:
                    bap_install.main()
                self.assertEqual(ctx.exception.code, 0)
        finally:
            os.chdir(old_cwd)

        self.assertFalse(os.path.exists(portable_dir))
        self.assertTrue(os.path.isfile(user_bin_sentinel))
        self.assertTrue(os.path.isfile(dot_bap_sentinel))
        self.assertTrue(os.path.isfile(cwd_marker))

if __name__ == "__main__":
    unittest.main()
