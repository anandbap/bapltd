#!/usr/bin/env python3
"""
BAP Universal User-Mode Installer
==================================
Zero-privilege, single-click installer and onboarding engine for the
Bounded Authority Plane (BAP) Zero-Trust ecosystem.

Supported Platforms:
  - Windows (x64 / ARM64)
  - macOS (Apple Silicon / Intel)
  - Linux (x86_64 / aarch64)

Supported Developer Agents:
  - Claude Code (Anthropic CLI)
  - Google Antigravity (Gemini Pair Programmer)
  - GitHub Copilot (VS Code & CLI)
  - Cursor IDE (.cursorrules & broker routing)
  - Python Autonomous Agents (LangChain, AutoGen, CrewAI, custom SDK)

Security Guarantee:
  - By default, runs completely in USER MODE.
  - Zero administrator, UAC, or root privileges required.
  - Installs to user directory (%USERPROFILE%\\bin, %APPDATA%\\BAP\\bin, or ~/bin).
  - Only requests administrative elevation if the user explicitly passes --system.

Zero external dependencies (pure Python standard library).
"""

import os
import sys
import json
import shutil
import subprocess
import argparse
import time
import urllib.request
import urllib.error
import ssl
import platform

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

if sys.platform == "win32":
    import winreg
    import ctypes

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_REMOTE_SERVER = "https://bap-controlplane.onrender.com"

# Colored terminal output helper
class TermColor:
    CYAN = "\033[96m" if sys.platform != "win32" or "WT_SESSION" in os.environ or "ANSICON" in os.environ else ""
    GREEN = "\033[92m" if sys.platform != "win32" or "WT_SESSION" in os.environ or "ANSICON" in os.environ else ""
    YELLOW = "\033[93m" if sys.platform != "win32" or "WT_SESSION" in os.environ or "ANSICON" in os.environ else ""
    RED = "\033[91m" if sys.platform != "win32" or "WT_SESSION" in os.environ or "ANSICON" in os.environ else ""
    BOLD = "\033[1m" if sys.platform != "win32" or "WT_SESSION" in os.environ or "ANSICON" in os.environ else ""
    RESET = "\033[0m" if sys.platform != "win32" or "WT_SESSION" in os.environ or "ANSICON" in os.environ else ""


def get_platform_id() -> str:
    """Detects OS platform and architecture to select matching precompiled dist assets."""
    machine = platform.machine().lower()
    is_arm = machine in ("arm64", "aarch64", "armv8b", "armv8l")
    if sys.platform == "win32":
        return "windows-arm64" if is_arm else "windows-amd64"
    elif sys.platform == "darwin":
        return "darwin-arm64" if is_arm else "darwin-amd64"
    else:
        return "linux-arm64" if is_arm else "linux-amd64"


def is_admin() -> bool:
    """Check if the current process has administrative/root privileges."""
    if sys.platform == "win32":
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def resolve_default_install_dir(roaming: bool = False) -> str:
    """Resolves standard user-mode installation directory.
    Priority:
      Windows:
        - Roaming: %APPDATA%\\BAP\\bin (if roaming=True)
        - User bin: %USERPROFILE%\\bin (C:\\Users\\<Username>\\bin) (Default)
      macOS / Linux:
        - ~/bin (or ~/.local/bin)
    """
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        if roaming:
            app_data = os.environ.get("APPDATA", home)
            return os.path.join(app_data, "BAP", "bin")
        return os.path.join(home, "bin")
    else:
        return os.path.join(home, "bin")


def get_all_bap_candidate_dirs(target_dir: str = None) -> list:
    """
    Returns a deduplicated list of all potential directories where BAP binaries,
    shims, or components could be installed across Windows, macOS, and Linux.
    """
    home = os.path.expanduser("~")
    dirs = []
    if target_dir:
        dirs.append(target_dir)

    default_dir = resolve_default_install_dir()
    dirs.append(default_dir)

    if sys.platform == "win32":
        if os.environ.get("LOCALAPPDATA"):
            dirs.append(os.path.join(os.environ["LOCALAPPDATA"], "BAP", "bin"))
        if os.environ.get("APPDATA"):
            dirs.append(os.path.join(os.environ["APPDATA"], "BAP", "bin"))
        dirs.append(os.path.join(home, "bin"))
        dirs.append(os.path.join(home, ".bap", "bin"))
        dirs.append(os.path.join(home, ".bap"))
        if os.environ.get("ProgramData"):
            dirs.append(os.path.join(os.environ["ProgramData"], "BAP", "bin"))
    else:
        dirs.append(os.path.join(home, "bin"))
        dirs.append(os.path.expanduser("~/.local/bin"))
        dirs.append(os.path.expanduser("~/.bap/bin"))
        dirs.append(os.path.expanduser("~/.bap"))
        dirs.append("/usr/local/bin")

    # Discover any directory currently on PATH containing BAP binaries
    ext = ".exe" if sys.platform == "win32" else ""
    path_entries = os.environ.get("PATH", "").split(os.pathsep)
    for p in path_entries:
        p_clean = p.strip('"').strip()
        if not p_clean or not os.path.isdir(p_clean):
            continue
        p_lower = p_clean.lower()
        if "python" in p_lower or "site-packages" in p_lower or "system32" in p_lower or "windows" in p_lower:
            continue
        test_edge = os.path.join(p_clean, f"bapedge{ext}")
        test_cp = os.path.join(p_clean, f"bapcontrolplane{ext}")
        if os.path.isfile(test_edge) or os.path.isfile(test_cp):
            dirs.append(p_clean)

    # Deduplicate while preserving order
    seen = set()
    result = []
    for d in dirs:
        norm = os.path.normpath(d)
        if norm.lower() not in seen:
            seen.add(norm.lower())
            result.append(norm)
    return result


def is_real_binary(path: str) -> bool:
    """Returns True if path is an actual compiled native executable, not a Python script shim."""
    if not path or not os.path.isfile(path):
        return False
    try:
        with open(path, "rb") as f:
            header = f.read(512)
        if not header:
            return False
        # If it has a python shebang or mentions python/bap shims, it is not a native binary
        if header.startswith(b"#!") and (b"python" in header or b"bap" in header):
            return False
        if b"bapedge_proxy" in header or b"bap.cli" in header:
            return False
        # Mach-O headers for macOS
        if sys.platform == "darwin":
            if len(header) >= 4:
                magic = header[:4]
                if magic in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
                    return True
        elif sys.platform.startswith("linux"):
            if header.startswith(b"\x7fELF"):
                return True
        elif sys.platform == "win32":
            if header.startswith(b"MZ"):
                return True
        return not header.startswith(b"#!")
    except Exception:
        return False


def clean_stale_secondary_installations(target_dir: str):
    """
    Ensures single-source-of-truth: cleans stale BAP binaries from other candidate
    paths so no conflicting older versions of bapedge or BAP components exist on PATH.
    Preserves Python entry point console scripts (e.g. bap and bapedge installed by pip).
    """
    # If running inside unit tests, avoid purging host directories unless explicitly allowed in mock test
    if ("unittest" in sys.modules and os.environ.get("BAP_ALLOW_TEST_PURGE") != "1") or os.environ.get("BAP_TEST_ENV") == "1":
        return

    all_dirs = get_all_bap_candidate_dirs(target_dir)
    target_norm = os.path.normpath(target_dir).lower()
    
    bap_bins = [
        "bapedge.exe", "bapedge",
        "bapcontrolplane.exe", "bapcontrolplane",
        "bapdashboard.exe", "bapdashboard",
        "bapgateway.exe", "bapgateway",
        "bapmcp.exe", "bapmcp",
        "interceptor.exe", "interceptor",
        "cchook-interceptor.exe", "cchook-interceptor",
        "copilot-interceptor.exe", "copilot-interceptor",
        "policy.cedar", "schema.json", "bap-config.json"
    ]
    
    cleaned_count = 0
    for d in all_dirs:
        if not os.path.isdir(d):
            continue
        if os.path.normpath(d).lower() == target_norm:
            continue
        d_lower = os.path.normpath(d).lower()
        if "site-packages" in d_lower or "dist-packages" in d_lower:
            continue
        # This is a secondary candidate directory; clean any stale BAP files
        for f in bap_bins:
            fp = os.path.join(d, f)
            if os.path.isfile(fp):
                # Never delete Python console scripts (like pip's ~/.local/bin/bapedge shim)
                if ("bapedge" in f or "interceptor" in f) and not is_real_binary(fp):
                    continue
                try:
                    safe_remove_file(fp)
                    cleaned_count += 1
                except Exception:
                    pass
    if cleaned_count > 0:
        print(f"  {TermColor.GREEN}[+] Purged {cleaned_count} stale BAP component(s) from secondary paths to prevent version conflicts{TermColor.RESET}")


def stop_running_bap_processes(target_dir: str = None):
    """
    Terminates any running BAP daemon or agent processes (bapedge, bapcontrolplane, etc.)
    that would prevent binary replacement or uninstallation on Windows and Unix systems.
    """
    # If running inside unit tests, avoid terminating host system processes
    if "unittest" in sys.modules or os.environ.get("BAP_TEST_ENV") == "1":
        return

    # 1. Gracefully stop the background daemon if bapedge is available
    bapedge_names = ["bapedge.exe", "bapedge"]
    bapedge_bin = None
    if target_dir:
        for name in bapedge_names:
            candidate = os.path.join(target_dir, name)
            if os.path.isfile(candidate):
                bapedge_bin = candidate
                break
    if not bapedge_bin:
        bapedge_bin = shutil.which("bapedge")

    if bapedge_bin:
        try:
            subprocess.run([bapedge_bin, "daemon", "stop"], capture_output=True, timeout=3)
        except Exception:
            pass

    # 2. Check and terminate PID recorded in daemon PID file
    state_dir = os.path.expanduser("~/.bapstate")
    pid_file = os.path.join(state_dir, "bap-daemon.pid")
    if os.path.isfile(pid_file):
        try:
            with open(pid_file, "r") as f:
                daemon_pid = int(f.read().strip())
            if sys.platform == "win32":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(daemon_pid)], capture_output=True, timeout=3)
            else:
                subprocess.run(["kill", "-9", str(daemon_pid)], capture_output=True, timeout=3)
        except Exception:
            pass

    # 3. Forcefully kill lingering BAP processes to release file locks
    proc_names = [
        "bapedge", "bapcontrolplane", "bapdashboard", "bapgateway",
        "interceptor", "cchook-interceptor", "copilot-interceptor", "bapmcp"
    ]
    if sys.platform == "win32":
        for p in proc_names:
            try:
                subprocess.run(
                    ["taskkill", "/F", "/T", "/IM", f"{p}.exe"],
                    capture_output=True,
                    timeout=5
                )
            except Exception:
                pass
    else:
        for p in proc_names:
            try:
                subprocess.run(["pkill", "-9", "-f", p], capture_output=True, timeout=5)
            except Exception:
                pass
    time.sleep(0.5)


def safe_copy_binary(src: str, dst: str):
    """Copies src to dst, handling file locks on Windows via process termination and rename-and-replace."""
    try:
        shutil.copy2(src, dst)
        if sys.platform != "win32":
            os.chmod(dst, 0o755)
        return True
    except Exception:
        # File may be locked; attempt to release locks and retry
        target_dir = os.path.dirname(dst)
        stop_running_bap_processes(target_dir)
        try:
            shutil.copy2(src, dst)
            if sys.platform != "win32":
                os.chmod(dst, 0o755)
            return True
        except Exception:
            # If still locked on Windows, attempt rename-and-replace
            if sys.platform == "win32":
                old_file = f"{dst}.old"
                try:
                    if os.path.isfile(old_file):
                        try:
                            os.remove(old_file)
                        except Exception:
                            pass
                    os.rename(dst, old_file)
                    shutil.copy2(src, dst)
                    return True
                except Exception as final_err:
                    raise final_err
            raise


def safe_remove_file(fp: str):
    """Deletes fp, handling running process locks on Windows."""
    try:
        os.remove(fp)
        return True
    except Exception:
        stop_running_bap_processes(os.path.dirname(fp))
        try:
            os.remove(fp)
            return True
        except Exception:
            if sys.platform == "win32":
                old_file = f"{fp}.old"
                try:
                    if os.path.isfile(old_file):
                        try:
                            os.remove(old_file)
                        except Exception:
                            pass
                    os.rename(fp, old_file)
                    try:
                        os.remove(old_file)
                    except Exception:
                        pass
                    return True
                except Exception as final_err:
                    raise final_err
            raise


def get_source_binary(name: str) -> str:
    """Finds built binaries in the package bin directory, repository dist, or build directories."""
    plat_id = get_platform_id()
    ext = ".exe" if sys.platform == "win32" else ""
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    
    aliases = [name]
    if name == "interceptor":
        aliases.append("cchook-interceptor")
    elif name == "cchook-interceptor":
        aliases.append("interceptor")

    for alias in aliases:
        binary_name = alias + ext if not alias.endswith(ext) else alias
        candidates = [
            # Priority 1: Package bundled binaries (when installed via pip / wheel)
            os.path.join(pkg_dir, "bin", plat_id, binary_name),
            os.path.join(pkg_dir, "bin", plat_id.replace("arm64", "amd64"), binary_name),
            os.path.join(REPO_ROOT, "bap", "bin", plat_id, binary_name),
            # Priority 2: Specific architecture dist packages (repo mode)
            os.path.join(REPO_ROOT, "dist", plat_id, "claude-client", binary_name),
            os.path.join(REPO_ROOT, "dist", plat_id, binary_name),
            os.path.join(REPO_ROOT, "dist", plat_id, "controlplane", binary_name),
            # Priority 3: Fallback to general architecture if arm64/amd64 alias
            os.path.join(REPO_ROOT, "dist", plat_id.replace("arm64", "amd64"), binary_name),
            # Priority 4: Root and subproject folders
            os.path.join(REPO_ROOT, binary_name),
            os.path.join(REPO_ROOT, "bap-edge", binary_name),
            os.path.join(REPO_ROOT, "bap-controlplane", binary_name),
            os.path.join(REPO_ROOT, "cchook", binary_name),
            os.path.join(REPO_ROOT, "copilot", binary_name),
        ]
        for c in candidates:
            if c and os.path.isfile(c):
                return c

    # Fallback to system PATH
    for alias in aliases:
        binary_name = alias + ext if not alias.endswith(ext) else alias
        which_found = shutil.which(binary_name)
        if which_found:
            return which_found

    primary = name + ext if not name.endswith(ext) else name
    return os.path.join(pkg_dir, "bin", plat_id, primary)


def update_user_path(target_dir: str):
    """Adds the target directory to User Environment PATH persistently without admin rights."""
    clean_target = os.path.normpath(target_dir)
    print(f"[*] Updating User environment PATH to include: {clean_target}")

    if sys.platform == "win32":
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE)
            try:
                current_path, _ = winreg.QueryValueEx(key, "Path")
            except FileNotFoundError:
                current_path = ""

            original_entries = [p.strip() for p in current_path.split(";") if p.strip()]
            # Clean secondary stale BAP directories from PATH so target_dir is the sole active BAP path
            other_bap_paths = [d.lower() for d in get_all_bap_candidate_dirs(clean_target) if os.path.normpath(d).lower() != clean_target.lower()]
            clean_entries = [p for p in original_entries if os.path.normpath(p).lower() not in other_bap_paths]

            added = False
            if clean_target.lower() not in [p.lower() for p in clean_entries]:
                clean_entries.append(clean_target)
                added = True

            if added or clean_entries != original_entries:
                new_path = ";".join(clean_entries)
                winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
                if added:
                    print(f"  {TermColor.GREEN}[+] Added to Windows User PATH (HKCU\\Environment\\Path){TermColor.RESET}")
                    print(f"  {TermColor.CYAN}[i] Tip: Open a new terminal window to load the updated PATH in your shell.{TermColor.RESET}")
                else:
                    print(f"  {TermColor.GREEN}[+] Cleaned secondary stale BAP paths from Windows User PATH{TermColor.RESET}")
                
                # Broadcast WM_SETTINGCHANGE so existing explorer and new shells pick it up
                try:
                    HWND_BROADCAST = 0xFFFF
                    WM_SETTINGCHANGE = 0x001A
                    SMTO_ABORTIFHUNG = 0x0002
                    result = ctypes.c_long()
                    ctypes.windll.user32.SendMessageTimeoutW(
                        HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment",
                        SMTO_ABORTIFHUNG, 1000, ctypes.byref(result)
                    )
                except Exception:
                    pass
            else:
                print(f"  {TermColor.GREEN}[OK] User PATH already contains installation directory.{TermColor.RESET}")
            winreg.CloseKey(key)
        except Exception as e:
            print(f"  {TermColor.YELLOW}[!] Notice: Could not update registry PATH automatically: {e}{TermColor.RESET}")
    else:
        # macOS / Linux: Append to shell profile
        home = os.path.expanduser("~")
        shell = os.environ.get("SHELL", "")
        if "zsh" in shell or sys.platform == "darwin":
            preferred_profiles = [
                os.path.join(home, ".zshrc"),
                os.path.join(home, ".zprofile"),
                os.path.join(home, ".bashrc"),
                os.path.join(home, ".profile"),
            ]
        else:
            preferred_profiles = [
                os.path.join(home, ".bashrc"),
                os.path.join(home, ".profile"),
                os.path.join(home, ".zshrc"),
            ]
        
        export_line = f'export PATH="{clean_target}:$PATH"\n'
        updated_any = False
        for profile in preferred_profiles:
            if os.path.exists(profile):
                try:
                    with open(profile, "r", encoding="utf-8") as f:
                        content = f.read()
                    if clean_target not in content:
                        with open(profile, "a", encoding="utf-8") as f:
                            f.write(f"\n# BAP Zero-Trust Path\n{export_line}")
                        print(f"  {TermColor.GREEN}[+] Appended PATH export to {profile}{TermColor.RESET}")
                    else:
                        print(f"  {TermColor.GREEN}[OK] {profile} already includes {clean_target}{TermColor.RESET}")
                    updated_any = True
                    break
                except Exception as e:
                    print(f"  {TermColor.YELLOW}[!] Could not update {profile}: {e}{TermColor.RESET}")
        if not updated_any:
            fallback_profile = os.path.join(home, ".zshrc" if sys.platform == "darwin" else ".bashrc")
            try:
                with open(fallback_profile, "w", encoding="utf-8") as f:
                    f.write(f"# BAP Zero-Trust Path\n{export_line}")
                print(f"  {TermColor.GREEN}[+] Created {fallback_profile} with PATH export{TermColor.RESET}")
            except Exception as e:
                print(f"  {TermColor.YELLOW}[!] Could not create {fallback_profile}: {e}{TermColor.RESET}")

    # Also update current runtime process PATH
    if clean_target.lower() not in [p.lower() for p in os.environ.get("PATH", "").split(os.pathsep)]:
        os.environ["PATH"] = clean_target + os.pathsep + os.environ.get("PATH", "")


def install_core_binaries(target_dir: str):
    """Copies BAP executables and configuration assets into the user-mode directory."""
    os.makedirs(target_dir, exist_ok=True)
    stop_running_bap_processes(target_dir)
    clean_stale_secondary_installations(target_dir)
    plat_id = get_platform_id()
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"\n[*] Deploying BAP Binaries to {target_dir} (Platform: {plat_id})...")

    binaries = [
        ("bapedge", "Edge Daemon & Execution Broker"),
        ("interceptor", "Claude Code Lifecycle Hook"),
        ("cchook-interceptor", "Claude Code Alternate Hook"),
        ("copilot-interceptor", "Copilot Hook Interceptor"),
        ("bapmcp", "Zero-Trust MCP Security Server"),
        ("bapcontrolplane", "Local Control Plane Server"),
    ]

    deployed = 0
    ext = ".exe" if sys.platform == "win32" else ""
    for bin_name, desc in binaries:
        src = get_source_binary(bin_name)
        dst = os.path.join(target_dir, bin_name + ext)
        if os.path.isfile(src):
            try:
                if os.path.abspath(src).lower() == os.path.abspath(dst).lower():
                    size_kb = os.path.getsize(dst) / 1024
                    print(f"  {TermColor.GREEN}[OK] {bin_name:<20}{TermColor.RESET} ({desc}) [{size_kb:.0f} KB]")
                    deployed += 1
                    continue
                safe_copy_binary(src, dst)
                size_kb = os.path.getsize(dst) / 1024
                print(f"  {TermColor.GREEN}[+] {bin_name:<20}{TermColor.RESET} ({desc}) [{size_kb:.0f} KB]")
                deployed += 1
            except Exception as e:
                if os.path.isfile(dst):
                    size_kb = os.path.getsize(dst) / 1024
                    print(f"  {TermColor.YELLOW}[!] Warning: could not update {bin_name} (locked by active process: {e}){TermColor.RESET}")
                    deployed += 1
                else:
                    print(f"  {TermColor.RED}[!] Failed copying {bin_name}: {e}{TermColor.RESET}")
        else:
            if bin_name in ("bapedge", "interceptor"):
                print(f"  {TermColor.YELLOW}[-] Essential binary not found: {bin_name} (Searched: {src}){TermColor.RESET}")

    # Deploy default Cedar baseline policy & schema
    for asset in ["policy.cedar", "schema.json", "bap-config.json"]:
        candidates = [
            os.path.join(pkg_dir, "bin", plat_id, asset),
            os.path.join(pkg_dir, asset),
            os.path.join(REPO_ROOT, asset),
            os.path.join(REPO_ROOT, "dist", plat_id, asset),
        ]
        src = None
        for c in candidates:
            if os.path.isfile(c):
                src = c
                break
        if src:
            dst = os.path.join(target_dir, asset)
            shutil.copy2(src, dst)
            print(f"  {TermColor.GREEN}[+] Configuration: {asset:<16}{TermColor.RESET}")

    # Deploy convenience wrapper scripts and transactional agent launchers
    launcher_bases = [
        "run_antigravity_cli_bap",
        "run_antigravity_ide_bap",
        "run_copilot_cli_bap",
        "run_copilot_ide_bap",
        "run_claude_cli_bap",
        "run_claude_ide_bap",
        "run_claude_bap",
        "run_cursor_bap",
        "run_gemini_cli_bap",
        "run_codex_cli_bap",
    ]

    wrappers = []
    if sys.platform == "win32":
        # Deploy bap_launcher_engine.ps1 first
        engine_src = os.path.join(REPO_ROOT, "scripts", "bap_launcher_engine.ps1")
        if not os.path.isfile(engine_src):
            engine_src = os.path.join(pkg_dir, "bap_launcher_engine.ps1")
        wrappers.append(("bap_launcher_engine.ps1", engine_src))

        # Copilot wrap
        wrappers.extend([
            ("copilot-wrap.bat", os.path.join(REPO_ROOT, "copilot", "copilot-wrap.bat")),
            ("copilot-wrap.ps1", os.path.join(REPO_ROOT, "copilot", "copilot-wrap.ps1")),
            ("copilot-wrap.sh", os.path.join(REPO_ROOT, "copilot", "copilot-wrap.sh")),
        ])

        for base in launcher_bases:
            # .bat
            bat_src = os.path.join(REPO_ROOT, f"{base}.bat")
            if not os.path.isfile(bat_src):
                bat_src = os.path.join(REPO_ROOT, "dist", plat_id, "claude-client", f"{base}.bat")
            wrappers.append((f"{base}.bat", bat_src))

            # .ps1
            ps1_src = os.path.join(REPO_ROOT, f"{base}.ps1")
            if not os.path.isfile(ps1_src):
                ps1_src = os.path.join(REPO_ROOT, "dist", plat_id, "claude-client", f"{base}.ps1")
            wrappers.append((f"{base}.ps1", ps1_src))

            # .sh
            sh_src = os.path.join(REPO_ROOT, f"{base}.sh")
            if not os.path.isfile(sh_src):
                sh_src = os.path.join(REPO_ROOT, "dist", "linux-amd64", "claude-client", f"{base}.sh")
            wrappers.append((f"{base}.sh", sh_src))
    else:
        wrappers.append(("copilot-wrap.sh", os.path.join(REPO_ROOT, "copilot", "copilot-wrap.sh")))
        for base in launcher_bases:
            sh_src = os.path.join(REPO_ROOT, f"{base}.sh")
            if not os.path.isfile(sh_src):
                sh_src = os.path.join(REPO_ROOT, "dist", plat_id, "claude-client", f"{base}.sh")
            wrappers.append((f"{base}.sh", sh_src))

    for name, initial_src in wrappers:
        dst = os.path.join(target_dir, name)
        src_candidates = [
            initial_src,
            os.path.join(pkg_dir, "launchers", name),
            os.path.join(pkg_dir, name),
            os.path.join(REPO_ROOT, name),
            os.path.join(REPO_ROOT, "dist", plat_id, "claude-client", name),
            os.path.join(REPO_ROOT, "dist", "linux-amd64", "claude-client", name),
            os.path.join(REPO_ROOT, "copilot", name),
            os.path.join(REPO_ROOT, "scripts", name),
        ]
        resolved_src = None
        for cand in src_candidates:
            if cand and os.path.isfile(cand):
                resolved_src = cand
                break

        if resolved_src and os.path.isfile(resolved_src):
            shutil.copy2(resolved_src, dst)
            if sys.platform != "win32":
                os.chmod(dst, 0o755)
            print(f"  {TermColor.GREEN}[+] Agent Launcher: {name:<26}{TermColor.RESET}")
        else:
            try:
                base_no_ext = os.path.splitext(name)[0]
                target_cmd = "claude"
                if "antigravity_cli" in name:
                    target_cmd = "agy"
                elif "antigravity_ide" in name:
                    target_cmd = "Antigravity"
                elif "copilot_cli" in name:
                    target_cmd = "copilot"
                elif "copilot_ide" in name or "claude_ide" in name:
                    target_cmd = "code"
                elif "cursor" in name:
                    target_cmd = "cursor"
                elif "gemini" in name:
                    target_cmd = "gemini"

                if name.endswith(".bat"):
                    with open(dst, "w", encoding="utf-8") as f:
                        f.write(f"@echo off\r\nsetlocal EnableExtensions\r\nif exist \"%~dp0{base_no_ext}.ps1\" (\r\n  powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%~dp0{base_no_ext}.ps1\" %*\r\n  exit /b %ERRORLEVEL%\r\n)\r\n{target_cmd} %*\r\n")
                elif name.endswith(".ps1"):
                    with open(dst, "w", encoding="utf-8") as f:
                        f.write(f"& {target_cmd} $args\r\n")
                elif name.endswith(".sh"):
                    with open(dst, "w", encoding="utf-8") as f:
                        f.write(f"#!/bin/sh\nexec {target_cmd} \"$@\"\n")
                    os.chmod(dst, 0o755)
                print(f"  {TermColor.GREEN}[+] Agent Launcher: {name:<26}{TermColor.RESET}")
            except Exception:
                pass

    # Deploy unified 'bap' CLI wrapper so the 'bap' command is immediately available in target_dir
    bap_wrapper = os.path.join(target_dir, "bap")
    try:
        py_exe = sys.executable or "python3"
        with open(bap_wrapper, "w", encoding="utf-8", newline="\n") as f:
            f.write(f'#!/bin/sh\nexec "{py_exe}" -m bap.cli "$@"\n')
        if sys.platform != "win32":
            os.chmod(bap_wrapper, 0o755)
        print(f"  {TermColor.GREEN}[+] bap                  (Unified Governance CLI Wrapper){TermColor.RESET}")
    except Exception as e:
        print(f"  {TermColor.YELLOW}[!] Notice: Could not create bap wrapper: {e}{TermColor.RESET}")

    if sys.platform == "win32":
        bap_cmd = os.path.join(target_dir, "bap.cmd")
        bap_ps1 = os.path.join(target_dir, "bap.ps1")
        try:
            py_exe = sys.executable or "python"
            with open(bap_cmd, "w", encoding="utf-8") as f:
                f.write(f'@echo off\r\n"{py_exe}" -m bap.cli %*\r\n')
            with open(bap_ps1, "w", encoding="utf-8") as f:
                f.write(f'& "{py_exe}" -m bap.cli $args\r\n')
        except Exception:
            pass

    # For Windows, also deploy extensionless POSIX shims so Git Bash and WSL can run bare commands (bap, bapedge, interceptor)
    if sys.platform == "win32":
        shims = [
            ("bap", "#!/bin/sh\nSCRIPT_DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"\nif [ -f \"$SCRIPT_DIR/bapedge.exe\" ]; then\n    case \"$1\" in\n        version|--version|-v|doctor|launch|install)\n            exec bap.exe \"$@\" 2>/dev/null || python -m bap.cli \"$@\"\n            ;;\n        *)\n            exec \"$SCRIPT_DIR/bapedge.exe\" \"$@\"\n            ;;\n    esac\nelse\n    exec bap.exe \"$@\"\nfi\n"),
            ("bapedge", "#!/bin/sh\nexec \"$(dirname \"$0\")/bapedge.exe\" \"$@\"\n"),
            ("interceptor", "#!/bin/sh\nexec \"$(dirname \"$0\")/interceptor.exe\" \"$@\"\n"),
            ("cchook-interceptor", "#!/bin/sh\nexec \"$(dirname \"$0\")/cchook-interceptor.exe\" \"$@\"\n"),
            ("copilot-interceptor", "#!/bin/sh\nexec \"$(dirname \"$0\")/copilot-interceptor.exe\" \"$@\"\n"),
            ("bapmcp", "#!/bin/sh\nexec \"$(dirname \"$0\")/bapmcp.exe\" \"$@\"\n"),
        ]
        for sname, scontent in shims:
            sp = os.path.join(target_dir, sname)
            try:
                with open(sp, "w", encoding="utf-8", newline="\n") as f:
                    f.write(scontent)
            except Exception:
                pass

    return deployed


def configure_claude_code(claude_dir: str, cchook_bin: str, mcp_bin: str, bapedge_bin: str, is_global: bool = False):
    """Configures Claude Code settings.json, mcp.json, and hooks for a given directory (global or workspace)."""
    claude_hooks_dir = os.path.join(claude_dir, "hooks")
    os.makedirs(claude_hooks_dir, exist_ok=True)
    
    hook_dest = os.path.join(claude_hooks_dir, "interceptor.exe" if sys.platform == "win32" else "interceptor")
    if os.path.isfile(cchook_bin):
        try:
            shutil.copy2(cchook_bin, hook_dest)
            if sys.platform != "win32":
                os.chmod(hook_dest, 0o755)
        except Exception:
            pass

    active_hook = cchook_bin if os.path.isfile(cchook_bin) else hook_dest

    claude_settings_path = os.path.join(claude_dir, "settings.json")
    claude_settings = {}
    if os.path.isfile(claude_settings_path):
        try:
            with open(claude_settings_path, "r", encoding="utf-8") as f:
                claude_settings = json.load(f)
        except Exception:
            claude_settings = {}

    if "hooks" not in claude_settings or not isinstance(claude_settings["hooks"], dict):
        claude_settings["hooks"] = {}

    hook_cmd = "interceptor.exe" if sys.platform == "win32" else "interceptor"
    interceptor_hook = {
        "type": "command",
        "command": hook_cmd
    }

    claude_settings["hooks"]["SessionStart"] = [
        {"hooks": [interceptor_hook]}
    ]
    claude_settings["hooks"]["UserPromptSubmit"] = [
        {"hooks": [interceptor_hook]}
    ]
    claude_settings["hooks"]["PreToolUse"] = [
        {"matcher": "*", "hooks": [interceptor_hook]}
    ]
    claude_settings["hooks"]["Stop"] = [
        {"hooks": [interceptor_hook]}
    ]
    # Clean up legacy/duplicate SessionEnd hook so Claude Code does not abort with 'Hook cancelled' on exit
    claude_settings["hooks"].pop("SessionEnd", None)

    with open(claude_settings_path, "w", encoding="utf-8") as f:
        json.dump(claude_settings, f, indent=2)

    # Claude MCP
    claude_mcp_path = os.path.join(claude_dir, "mcp.json")
    claude_mcp = {}
    if os.path.isfile(claude_mcp_path):
        try:
            with open(claude_mcp_path, "r", encoding="utf-8") as f:
                claude_mcp = json.load(f)
        except Exception:
            claude_mcp = {}

    if "mcpServers" not in claude_mcp or not isinstance(claude_mcp["mcpServers"], dict):
        claude_mcp["mcpServers"] = {}

    claude_mcp["mcpServers"]["bap-zero-trust"] = {
        "command": mcp_bin if mcp_bin != bapedge_bin else bapedge_bin,
        "args": ["mcp"] if mcp_bin == bapedge_bin else [],
        "env": {"LTD_SOURCE": "claude-code", "BAP_SESSION_ID": "sess-claude-governed"}
    }
    with open(claude_mcp_path, "w", encoding="utf-8") as f:
        json.dump(claude_mcp, f, indent=2)

    scope = "Global User (~/.claude)" if is_global else f"Workspace ({claude_dir})"
    print(f"  {TermColor.GREEN}[+] Claude Code ({scope}):{TermColor.RESET} Configured hooks in {claude_settings_path}")


def configure_codex_hooks(codex_dir: str, cchook_bin: str, is_global: bool = False):
    """Install native Codex lifecycle hooks while preserving unrelated hooks."""
    os.makedirs(codex_dir, exist_ok=True)
    hooks_path = os.path.join(codex_dir, "hooks.json")
    hooks_doc = {}
    if os.path.isfile(hooks_path):
        try:
            with open(hooks_path, "r", encoding="utf-8") as f:
                hooks_doc = json.load(f)
        except Exception:
            hooks_doc = {}

    hooks = hooks_doc.setdefault("hooks", {})
    hooks_doc.setdefault("description", "Codex lifecycle hooks, including BAP zero-trust governance.")
    hook_command = os.path.abspath(cchook_bin)

    def bap_handler(timeout: int):
        handler = {
            "type": "command",
            "command": hook_command,
            "timeout": timeout,
        }
        if sys.platform == "win32":
            handler["commandWindows"] = hook_command
        return handler

    def without_old_bap(groups):
        clean = []
        for group in groups if isinstance(groups, list) else []:
            handlers = group.get("hooks", []) if isinstance(group, dict) else []
            if any(
                "interceptor" in str(h.get("command", "")).lower()
                or "interceptor" in str(h.get("commandWindows", "")).lower()
                for h in handlers if isinstance(h, dict)
            ):
                continue
            clean.append(group)
        return clean

    event_groups = {
        "SessionStart": {"hooks": [bap_handler(10)]},
        "UserPromptSubmit": {"hooks": [bap_handler(10)]},
        "PreToolUse": {"matcher": ".*", "hooks": [bap_handler(30)]},
        "Stop": {"hooks": [bap_handler(10)]},
        "SessionEnd": {"hooks": [bap_handler(3)]},
    }
    for event, group in event_groups.items():
        hooks[event] = without_old_bap(hooks.get(event, [])) + [group]

    with open(hooks_path, "w", encoding="utf-8") as f:
        json.dump(hooks_doc, f, indent=2)

    scope = "Global User (~/.codex)" if is_global else f"Workspace ({codex_dir})"
    print(f"  {TermColor.GREEN}[+] Codex ({scope}):{TermColor.RESET} Configured native hooks in {hooks_path}")


def configure_agent_hooks(workspace_root: str, target_dir: str):
    """Autodetects installed agents and configures hooks, MCP configs, and rules."""
    print(f"\n[*] Autodetecting and Configuring Developer Agent Hooks in: {workspace_root}...")
    
    bapedge_bin = os.path.join(target_dir, "bapedge.exe" if sys.platform == "win32" else "bapedge")
    cchook_bin = os.path.join(target_dir, "interceptor.exe" if sys.platform == "win32" else "interceptor")
    mcp_bin = os.path.join(target_dir, "bapmcp.exe" if sys.platform == "win32" else "bapmcp")
    if not os.path.isfile(mcp_bin):
        mcp_bin = bapedge_bin

    detected_agents = []

    # 1. Claude Code - Workspace configuration
    ws_claude_dir = os.path.join(workspace_root, ".claude")
    configure_claude_code(ws_claude_dir, cchook_bin, mcp_bin, bapedge_bin, is_global=False)
    detected_agents.append("Claude Code (Hooks + MCP Installed)")

    # Also configure Global User (~/.claude) if installing to the default user bin or from user home
    home = os.path.expanduser("~")
    norm_workspace = os.path.normpath(workspace_root).lower()
    norm_home = os.path.normpath(home).lower()
    norm_target = os.path.normpath(target_dir).lower()
    default_dir = os.path.normpath(resolve_default_install_dir()).lower()
    roaming_dir = os.path.normpath(resolve_default_install_dir(roaming=True)).lower()

    if norm_workspace == norm_home or norm_target in (default_dir, roaming_dir):
        global_claude_dir = os.path.join(home, ".claude")
        if os.path.normpath(global_claude_dir).lower() != os.path.normpath(ws_claude_dir).lower():
            configure_claude_code(global_claude_dir, cchook_bin, mcp_bin, bapedge_bin, is_global=True)
            detected_agents.append("Claude Code (Global Hooks + MCP Installed)")

    # 2. OpenAI Codex - native lifecycle hooks work with the launcher, normal
    # `codex` invocations, the IDE integration, and local Codex desktop threads.
    ws_codex_dir = os.path.join(workspace_root, ".codex")
    configure_codex_hooks(ws_codex_dir, cchook_bin, is_global=False)
    detected_agents.append("OpenAI Codex (Native Hooks Installed)")
    if norm_workspace == norm_home or norm_target in (default_dir, roaming_dir):
        global_codex_dir = os.path.join(home, ".codex")
        if os.path.normpath(global_codex_dir).lower() != os.path.normpath(ws_codex_dir).lower():
            configure_codex_hooks(global_codex_dir, cchook_bin, is_global=True)
            detected_agents.append("OpenAI Codex (Global Native Hooks Installed)")

    # 3. Google Antigravity
    antigravity_dir = os.path.join(workspace_root, ".antigravity")
    os.makedirs(antigravity_dir, exist_ok=True)
    gemini_md_path = os.path.join(workspace_root, "GEMINI.md")
    if not os.path.isfile(gemini_md_path):
        gemini_rule_content = f"""# BAP Zero-Trust Policy & Shell Governance for Antigravity (Governed Session)

This workspace is actively governed by the BAP Zero-Trust Local Trusted Daemon ({os.path.basename(bapedge_bin)}).

## Mandatory Execution Rules
1. **Always Use BAP Edge Execution Broker**:
   - All shell executions MUST run through bapedge exec:
      {bapedge_bin} exec "<command>"
   - Never run raw, ungoverned shell commands on the host machine.
2. **Zero-Trust Policy Enforcement**:
   - Commands are evaluated against Cedar invariants before execution.
   - If a command is denied, inspect the suggestion in the structured response.
3. **Identity & Audit Logging**:
   - LTD_SOURCE=antigravity
"""
        with open(gemini_md_path, "w", encoding="utf-8") as f:
            f.write(gemini_rule_content)
        detected_agents.append("Google Antigravity (GEMINI.md Rule + MCP Installed)")
        print(f"  {TermColor.GREEN}[+] Google Antigravity:{TermColor.RESET} Created zero-trust rule at {gemini_md_path}")
    else:
        detected_agents.append("Google Antigravity (Existing GEMINI.md Preserved + MCP Installed)")
        print(f"  {TermColor.GREEN}[+] Google Antigravity:{TermColor.RESET} Verified active zero-trust rule at {gemini_md_path}")

    # 4. Cursor IDE (.cursorrules + .cursor/mcp.json)
    cursor_dir = os.path.join(workspace_root, ".cursor")
    os.makedirs(cursor_dir, exist_ok=True)
    cursorrules_path = os.path.join(workspace_root, ".cursorrules")
    if not os.path.isfile(cursorrules_path):
        with open(cursorrules_path, "w", encoding="utf-8") as f:
            f.write(f"""# BAP Zero-Trust Policy for Cursor Assistant
All terminal and tool commands must be routed through the BAP broker:
{bapedge_bin} exec "<command>"
""")
    cursor_mcp_path = os.path.join(cursor_dir, "mcp.json")
    claude_mcp_sample = {
        "mcpServers": {
            "bap-zero-trust": {
                "command": mcp_bin if mcp_bin != bapedge_bin else bapedge_bin,
                "args": ["mcp"] if mcp_bin == bapedge_bin else [],
                "env": {"LTD_SOURCE": "cursor-code", "BAP_SESSION_ID": "sess-cursor-governed"}
            }
        }
    }
    with open(cursor_mcp_path, "w", encoding="utf-8") as f:
        json.dump(claude_mcp_sample, f, indent=2)
    detected_agents.append("Cursor IDE (.cursorrules + MCP Installed)")
    print(f"  {TermColor.GREEN}[+] Cursor IDE:{TermColor.RESET} Configured broker routing in {cursorrules_path}")

    # 5. GitHub Copilot (.vscode/settings.json + .vscode/mcp.json)
    vscode_dir = os.path.join(workspace_root, ".vscode")
    os.makedirs(vscode_dir, exist_ok=True)
    vscode_settings_path = os.path.join(vscode_dir, "settings.json")
    vscode_settings = {}
    if os.path.isfile(vscode_settings_path):
        try:
            with open(vscode_settings_path, "r", encoding="utf-8") as f:
                vscode_settings = json.load(f)
        except Exception:
            pass

    if sys.platform == "win32":
        wrap_bat = os.path.join(target_dir, "copilot-wrap.bat")
        wrap_ps1 = os.path.join(target_dir, "copilot-wrap.ps1")
        wrap_sh = os.path.join(target_dir, "copilot-wrap.sh")
        vscode_settings["terminal.integrated.profiles.windows"] = {
            "CopilotSandbox": {"path": wrap_bat, "overrideName": True},
            "CopilotSandbox (PowerShell)": {
                "path": "powershell.exe",
                "args": ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", wrap_ps1],
                "overrideName": True
            },
            "CopilotSandbox (Git Bash)": {
                "path": "bash.exe",
                "args": [wrap_sh],
                "overrideName": True
            }
        }
        vscode_settings["terminal.integrated.defaultProfile.windows"] = "CopilotSandbox"
    elif sys.platform == "darwin":
        wrap_sh = os.path.join(target_dir, "copilot-wrap.sh")
        vscode_settings["terminal.integrated.profiles.osx"] = {
            "CopilotSandbox": {"path": wrap_sh, "overrideName": True}
        }
        vscode_settings["terminal.integrated.defaultProfile.osx"] = "CopilotSandbox"
    else:
        wrap_sh = os.path.join(target_dir, "copilot-wrap.sh")
        vscode_settings["terminal.integrated.profiles.linux"] = {
            "CopilotSandbox": {"path": wrap_sh, "overrideName": True}
        }
        vscode_settings["terminal.integrated.defaultProfile.linux"] = "CopilotSandbox"

    with open(vscode_settings_path, "w", encoding="utf-8") as f:
        json.dump(vscode_settings, f, indent=2)

    vscode_mcp_path = os.path.join(vscode_dir, "mcp.json")
    vscode_mcp = {
        "servers": {
            "bap-zero-trust": {
                "command": mcp_bin if mcp_bin != bapedge_bin else bapedge_bin,
                "args": ["mcp"] if mcp_bin == bapedge_bin else [],
                "env": {"LTD_SOURCE": "copilot-mcp", "BAP_SESSION_ID": "sess-copilot-mcp"}
            }
        }
    }
    with open(vscode_mcp_path, "w", encoding="utf-8") as f:
        json.dump(vscode_mcp, f, indent=2)
    detected_agents.append("GitHub Copilot (VS Code Profile + MCP Installed)")
    print(f"  {TermColor.GREEN}[+] GitHub Copilot:{TermColor.RESET} Configured VS Code sandbox in {vscode_settings_path}")

    # 6. Python Agent SDK
    py_agent_dir = os.path.join(REPO_ROOT, "python-agent")
    if os.path.isdir(py_agent_dir):
        print(f"  {TermColor.GREEN}[+] Python SDK:{TermColor.RESET} Local SDK available at {py_agent_dir}")
        detected_agents.append("Python Agent SDK (Available)")

    # 7. PowerShell Profile Auto-Binding (Codex, Claude Code, Antigravity, Copilot)
    if sys.platform == "win32":
        deploy_powershell_profile(target_dir)
        detected_agents.append("PowerShell Auto-Binding Profile (~/.bap/bap-profile.ps1)")

    return detected_agents


def deploy_powershell_profile(target_dir: str):
    """Deploys ~/.bap/bap-profile.ps1 and injects auto-binding into user PowerShell profiles."""
    home = os.path.expanduser("~")
    bap_dir = os.path.join(home, ".bap")
    os.makedirs(bap_dir, exist_ok=True)
    dst_profile = os.path.join(bap_dir, "bap-profile.ps1")
    src_profile = os.path.join(REPO_ROOT, "bap", "bap-profile.ps1")
    if not os.path.isfile(src_profile):
        src_profile = os.path.join(os.path.dirname(os.path.abspath(__file__)), "bap-profile.ps1")
    if os.path.isfile(src_profile):
        shutil.copy2(src_profile, dst_profile)
        print(f"  {TermColor.GREEN}[+] PowerShell Auto-Binding:{TermColor.RESET} Deployed {dst_profile}")

    source_line = '\n# BAP Zero-Trust Agent Auto-Binding\nif (Test-Path "$env:USERPROFILE\\.bap\\bap-profile.ps1") { . "$env:USERPROFILE\\.bap\\bap-profile.ps1" }\n'

    docs = os.path.join(home, "Documents")
    onedrive_docs = os.path.join(home, "OneDrive", "Documents")
    profile_candidates = [
        os.path.join(docs, "PowerShell", "Microsoft.PowerShell_profile.ps1"),
        os.path.join(docs, "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
        os.path.join(onedrive_docs, "PowerShell", "Microsoft.PowerShell_profile.ps1"),
        os.path.join(onedrive_docs, "WindowsPowerShell", "Microsoft.PowerShell_profile.ps1"),
    ]
    for p in profile_candidates:
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            existing = ""
            if os.path.isfile(p):
                with open(p, "r", encoding="utf-8") as f:
                    existing = f.read()
            if "bap-profile.ps1" not in existing:
                with open(p, "a", encoding="utf-8") as f:
                    f.write(source_line)
                print(f"  {TermColor.GREEN}[+] Configured Auto-Binding in:{TermColor.RESET} {p}")
        except Exception:
            pass

    # Also deploy CMD and POSIX shims to ~/.bap/bin for cmd.exe, Win+R Run dialog, and Git Bash
    bin_dir = os.path.join(bap_dir, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    shim_targets = [
        ("codex", "codex", [
            os.path.join(home, r"AppData\Local\Programs\OpenAI\Codex\bin\codex.exe"),
            os.path.join(home, r"AppData\Local\Programs\codex\codex.exe"),
        ]),
        ("claude-code", "claude", [
            os.path.join(home, r".local\bin\claude.exe"),
            os.path.join(home, r"AppData\Roaming\npm\claude.cmd"),
        ]),
        ("antigravity", "agy", [
            os.path.join(home, r"AppData\Local\agy\bin\agy.exe"),
            os.path.join(home, r"AppData\Roaming\Antigravity\bin\agy-node.cmd"),
        ]),
        ("copilot", "copilot", [
            os.path.join(home, r"AppData\Local\Microsoft\WinGet\Packages\GitHub.Copilot_Microsoft.Winget.Source_8wekyb3d8bbwe\copilot.exe"),
            os.path.join(home, r"AppData\Local\Programs\copilot\copilot.exe"),
        ]),
    ]
    for agent_id, cmd_name, candidates in shim_targets:
        real_bin = None
        for cand in candidates:
            if os.path.isfile(cand):
                real_bin = cand
                break
        if not real_bin:
            resolved = shutil.which(f"{cmd_name}.exe") or shutil.which(cmd_name)
            if resolved and "bap" not in resolved.lower():
                real_bin = resolved
        if real_bin:
            cmd_shim = os.path.join(bin_dir, f"{cmd_name}.cmd")
            cmd_content = f"""@echo off\r\nsetlocal EnableExtensions\r\nif "%BAP_SHIM_ACTIVE%"=="1" goto RUN_RAW\r\nset "BAP_SHIM_ACTIVE=1"\r\nset "LTD_SOURCE={agent_id}"\r\nif "%BAP_SESSION_ID%"=="" set "BAP_SESSION_ID=sess-{agent_id}-cmd-%RANDOM%"\r\nif exist "%~dp0bapedge.exe" (\r\n  "%~dp0bapedge.exe" session-start --app-id {agent_id} --session-id %BAP_SESSION_ID% >nul 2>&1\r\n)\r\n:RUN_RAW\r\n"{real_bin}" %*\r\nset "EXIT_CODE=%ERRORLEVEL%"\r\nif "%BAP_SHIM_ACTIVE%"=="1" (\r\n  if exist "%~dp0bapedge.exe" (\r\n    "%~dp0bapedge.exe" session-end --session-id %BAP_SESSION_ID% >nul 2>&1\r\n  )\r\n)\r\nexit /b %EXIT_CODE%\r\n"""
            try:
                with open(cmd_shim, "w", encoding="utf-8") as f:
                    f.write(cmd_content)
                print(f"  {TermColor.GREEN}[+] Command Prompt / Win+R Shim:{TermColor.RESET} {cmd_shim}")
            except Exception:
                pass


def verify_controlplane_handshake(server_url: str) -> bool:
    """Probes remote or local control plane for health and returns status."""
    print(f"\n[*] Probing BAP Control Plane connection ({server_url})...")
    ctx = ssl.create_default_context()
    try:
        req = urllib.request.Request(f"{server_url}/health", headers={"User-Agent": "BAP-UniversalInstaller/1.0"})
        with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
            if resp.status == 200:
                print(f"  {TermColor.GREEN}[+] Control Plane Reachable (HTTP 200 OK){TermColor.RESET}")
                return True
    except Exception as e:
        print(f"  {TermColor.YELLOW}[!] Control Plane offline or unreachable: {e}{TermColor.RESET}")
        print("      (bapedge will operate in secure offline cached policy mode)")
    return False


def run_pin_scan(target_dir: str, workspace_root: str):
    """Executes initial AIR content pinning to baseline all prompts and policies."""
    bapedge_bin = os.path.join(target_dir, "bapedge.exe" if sys.platform == "win32" else "bapedge")
    if os.path.isfile(bapedge_bin):
        print("\n[*] Initializing Cryptographic Content Pinning (AIR Model)...")
        try:
            res = subprocess.run([bapedge_bin, "pin", "scan", "--dir", workspace_root], capture_output=True, text=True, timeout=10)
            if res.returncode == 0:
                print(f"  {TermColor.GREEN}[+] Workspace skills, prompts, and manifests successfully pinned!{TermColor.RESET}")
            else:
                print(f"  {TermColor.YELLOW}[!] Pin scan notice: {res.stderr.strip()}{TermColor.RESET}")
        except Exception as e:
            print(f"  {TermColor.YELLOW}[!] Could not execute pin scan: {e}{TermColor.RESET}")


def revert_claude_code(claude_dir: str):
    """Cleanly reverts BAP hooks and MCP configuration from a .claude directory."""
    claude_settings = os.path.join(claude_dir, "settings.json")
    if os.path.isfile(claude_settings):
        try:
            with open(claude_settings, "r", encoding="utf-8") as f:
                data = json.load(f)
            if "hooks" in data and isinstance(data["hooks"], dict):
                for event in list(data["hooks"].keys()):
                    matchers = data["hooks"][event]
                    if isinstance(matchers, list):
                        cleaned = []
                        for m in matchers:
                            m_hooks = m.get("hooks", []) if isinstance(m, dict) else []
                            is_bap = False
                            for h in m_hooks:
                                cmd = str(h.get("command", "")).lower()
                                if "interceptor" in cmd or "bap" in cmd:
                                    is_bap = True
                                    break
                            if isinstance(m, dict) and ("interceptor" in str(m.get("command", "")).lower() or "bap" in str(m.get("command", "")).lower()):
                                is_bap = True
                            if not is_bap:
                                cleaned.append(m)
                        if cleaned:
                            data["hooks"][event] = cleaned
                        else:
                            del data["hooks"][event]
                if not data["hooks"]:
                    del data["hooks"]
            with open(claude_settings, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(f"  {TermColor.GREEN}[+] Reverted Claude Code hooks in {claude_settings}{TermColor.RESET}")
        except Exception as e:
            print(f"  {TermColor.YELLOW}[!] Could not revert Claude settings in {claude_settings}: {e}{TermColor.RESET}")

    # Revert Claude MCP
    claude_mcp = os.path.join(claude_dir, "mcp.json")
    if os.path.isfile(claude_mcp):
        try:
            with open(claude_mcp, "r", encoding="utf-8") as f:
                data = json.load(f)
            if "mcpServers" in data and "bap-zero-trust" in data["mcpServers"]:
                del data["mcpServers"]["bap-zero-trust"]
                if not data["mcpServers"]:
                    del data["mcpServers"]
            with open(claude_mcp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(f"  {TermColor.GREEN}[+] Removed bap-zero-trust from {claude_mcp}{TermColor.RESET}")
        except Exception:
            pass

    # Remove local hook copy
    for hook_file in ["interceptor.exe", "interceptor", "cchook-interceptor.exe", "cchook-interceptor"]:
        hp = os.path.join(claude_dir, "hooks", hook_file)
        if os.path.isfile(hp):
            try:
                os.remove(hp)
            except Exception:
                pass
    hooks_dir = os.path.join(claude_dir, "hooks")
    if os.path.isdir(hooks_dir) and not os.listdir(hooks_dir):
        try:
            os.rmdir(hooks_dir)
        except Exception:
            pass


def uninstall(target_dir: str, workspace_root: str):
    """Cleanly uninstalls BAP binaries, reverts PATH, and restores agent configurations across Windows, macOS, and Linux."""
    print("=" * 80)
    print(f"     {TermColor.YELLOW}{TermColor.BOLD}BAP ZERO-TRUST AGENT GOVERNANCE -- UNINSTALLATION{TermColor.RESET}")
    print("=" * 80)
    print(f"[*] Target Directory to Clean : {target_dir}")
    print(f"[*] Target Workspace to Clean : {workspace_root}")

    # Stop any running daemons or agents locking executable files
    stop_running_bap_processes(target_dir)

    home = os.path.expanduser("~")
    bap_files = [
        "bap", "bap.exe",
        "bapedge.exe", "bapedge",
        "interceptor.exe", "interceptor",
        "cchook-interceptor.exe", "cchook-interceptor",
        "copilot-interceptor.exe", "copilot-interceptor",
        "bapmcp.exe", "bapmcp",
        "bapcontrolplane.exe", "bapcontrolplane",
        "bap_launcher_engine.ps1",
        "policy.cedar", "schema.json", "bap-config.json",
        "policy-state.json", "ltd-audit.jsonl", ".bap-pin.json",
        "copilot-wrap.bat", "copilot-wrap.ps1", "copilot-wrap.sh",
        "codex.cmd", "claude.cmd", "agy.cmd", "copilot.cmd", "bap-profile.ps1"
    ]
    for _base in [
        "run_antigravity_cli_bap", "run_antigravity_ide_bap",
        "run_copilot_cli_bap", "run_copilot_ide_bap",
        "run_claude_cli_bap", "run_claude_ide_bap",
        "run_claude_bap", "run_cursor_bap", "run_gemini_cli_bap",
        "run_codex_cli_bap"
    ]:
        for _ext in [".bat", ".ps1", ".sh", ""]:
            bap_files.append(_base + _ext)

    unique_dirs = get_all_bap_candidate_dirs(target_dir)

    # 1. Clean BAP files from candidate directories without wiping entire user folders
    for d in unique_dirs:
        if not os.path.isdir(d):
            continue
        removed_count = 0
        for f in bap_files:
            fp = os.path.join(d, f)
            if os.path.isfile(fp):
                # Never remove pip's python console scripts in secondary or python directories
                if ("bap" in f or "bapedge" in f) and (os.path.normpath(d).lower() != os.path.normpath(target_dir).lower()):
                    if not is_real_binary(fp):
                        continue
                try:
                    safe_remove_file(fp)
                    removed_count += 1
                except Exception as e:
                    print(f"  {TermColor.YELLOW}[!] Could not remove {fp}: {e}{TermColor.RESET}")
        if removed_count > 0:
            print(f"  {TermColor.GREEN}[+] Removed {removed_count} BAP binaries/assets from {d}{TermColor.RESET}")
        
        # If directory is now empty, or if it is a dedicated BAP folder, remove it
        try:
            if not os.listdir(d):
                os.rmdir(d)
                print(f"  {TermColor.GREEN}[+] Removed empty directory: {d}{TermColor.RESET}")
                parent = os.path.dirname(d)
                if os.path.basename(parent).upper() == "BAP" and not os.listdir(parent):
                    os.rmdir(parent)
        except Exception:
            pass

    # 2. Revert User PATH
    if sys.platform == "win32":
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment", 0, winreg.KEY_READ | winreg.KEY_WRITE)
            try:
                current_path, _ = winreg.QueryValueEx(key, "Path")
            except FileNotFoundError:
                current_path = ""
            
            clean_targets = [d.lower() for d in unique_dirs]
            paths = [p.strip() for p in current_path.split(";") if p.strip()]
            new_paths = [p for p in paths if os.path.normpath(p).lower() not in clean_targets]
            
            if len(new_paths) != len(paths):
                new_path = ";".join(new_paths)
                winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
                print(f"  {TermColor.GREEN}[+] Cleaned BAP paths from Windows User PATH{TermColor.RESET}")
                try:
                    HWND_BROADCAST = 0xFFFF
                    WM_SETTINGCHANGE = 0x001A
                    SMTO_ABORTIFHUNG = 0x0002
                    result = ctypes.c_long()
                    ctypes.windll.user32.SendMessageTimeoutW(
                        HWND_BROADCAST, WM_SETTINGCHANGE, 0, "Environment",
                        SMTO_ABORTIFHUNG, 1000, ctypes.byref(result)
                    )
                except Exception:
                    pass
            winreg.CloseKey(key)
        except Exception as e:
            print(f"  {TermColor.YELLOW}[!] Notice: Registry PATH reversion: {e}{TermColor.RESET}")
    else:
        clean_targets = [d for d in unique_dirs]
        for p_name in [".bashrc", ".zshrc", ".profile", ".zprofile"]:
            prof = os.path.join(home, p_name)
            if os.path.isfile(prof):
                try:
                    with open(prof, "r", encoding="utf-8") as f:
                        lines = f.readlines()
                    filtered = [l for l in lines if not any(ct in l for ct in clean_targets) and "# BAP Zero-Trust Path" not in l]
                    if len(filtered) != len(lines):
                        with open(prof, "w", encoding="utf-8") as f:
                            f.writelines(filtered)
                        print(f"  {TermColor.GREEN}[+] Removed BAP PATH export from {prof}{TermColor.RESET}")
                except Exception:
                    pass

    # 3. Clean Claude Code Hooks (Workspace)
    ws_claude_dir = os.path.join(workspace_root, ".claude")
    if os.path.isdir(ws_claude_dir):
        revert_claude_code(ws_claude_dir)

    norm_workspace = os.path.normpath(workspace_root).lower()
    norm_home = os.path.normpath(home).lower()
    norm_target = os.path.normpath(target_dir).lower()
    default_dir = os.path.normpath(resolve_default_install_dir()).lower()
    roaming_dir = os.path.normpath(resolve_default_install_dir(roaming=True)).lower()

    # Clean Global Claude Code hooks if target_dir is default user bin or workspace is home
    if norm_workspace == norm_home or norm_target in (default_dir, roaming_dir):
        global_claude_dir = os.path.join(home, ".claude")
        if os.path.normpath(global_claude_dir).lower() != os.path.normpath(ws_claude_dir).lower() and os.path.isdir(global_claude_dir):
            revert_claude_code(global_claude_dir)

    # 4. Clean Antigravity (GEMINI.md)
    gemini_md = os.path.join(workspace_root, "GEMINI.md")
    if os.path.isfile(gemini_md):
        try:
            with open(gemini_md, "r", encoding="utf-8") as f:
                content = f.read()
            if "BAP Zero-Trust Policy" in content:
                backup_files = [os.path.join(workspace_root, f) for f in os.listdir(workspace_root) if f.startswith("GEMINI.md.bap-backup")]
                if backup_files:
                    backup_files.sort(key=os.path.getmtime, reverse=True)
                    shutil.copy2(backup_files[0], gemini_md)
                    print(f"  {TermColor.GREEN}[+] Restored GEMINI.md from backup {os.path.basename(backup_files[0])}{TermColor.RESET}")
                else:
                    os.remove(gemini_md)
                    print(f"  {TermColor.GREEN}[+] Removed BAP GEMINI.md from {gemini_md}{TermColor.RESET}")
        except Exception:
            pass

    # 5. Clean Cursor (.cursorrules + .cursor/mcp.json)
    cursorrules = os.path.join(workspace_root, ".cursorrules")
    if os.path.isfile(cursorrules):
        try:
            with open(cursorrules, "r", encoding="utf-8") as f:
                content = f.read()
            if "BAP Zero-Trust Policy" in content:
                os.remove(cursorrules)
                print(f"  {TermColor.GREEN}[+] Removed {cursorrules}{TermColor.RESET}")
        except Exception:
            pass
    cursor_mcp = os.path.join(workspace_root, ".cursor", "mcp.json")
    if os.path.isfile(cursor_mcp):
        try:
            os.remove(cursor_mcp)
            print(f"  {TermColor.GREEN}[+] Removed {cursor_mcp}{TermColor.RESET}")
        except Exception:
            pass

    # 6. Clean VS Code Copilot (.vscode/settings.json + .vscode/mcp.json)
    vscode_settings = os.path.join(workspace_root, ".vscode", "settings.json")
    if os.path.isfile(vscode_settings):
        try:
            with open(vscode_settings, "r", encoding="utf-8") as f:
                data = json.load(f)
            data.pop("terminal.integrated.profiles.windows", None)
            data.pop("terminal.integrated.defaultProfile.windows", None)
            data.pop("terminal.integrated.profiles.osx", None)
            data.pop("terminal.integrated.defaultProfile.osx", None)
            data.pop("terminal.integrated.profiles.linux", None)
            data.pop("terminal.integrated.defaultProfile.linux", None)
            if data:
                with open(vscode_settings, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2)
            else:
                os.remove(vscode_settings)
            print(f"  {TermColor.GREEN}[+] Reverted VS Code Copilot terminal profiles{TermColor.RESET}")
        except Exception:
            pass
    vscode_mcp = os.path.join(workspace_root, ".vscode", "mcp.json")
    if os.path.isfile(vscode_mcp):
        try:
            os.remove(vscode_mcp)
            print(f"  {TermColor.GREEN}[+] Removed {vscode_mcp}{TermColor.RESET}")
        except Exception:
            pass

    # 7. Clean Global User Configs & Stale Session Credentials
    for global_state in [
        os.path.join(os.path.expanduser("~"), "bap-config.json"),
        os.path.expanduser("~/.bap/config.json"),
        os.path.expanduser("~/.bap/bap-config.json"),
        os.path.expanduser("~/.bapstate/config.json"),
        os.path.expanduser("~/.bapstate/bap-config.json"),
        os.path.expanduser("~/.bapstate/credentials.json"),
        os.path.expanduser("~/.ltd/config.json"),
        os.path.expanduser("~/.ltd/credentials.json"),
    ]:
        if os.path.isfile(global_state):
            try:
                os.remove(global_state)
            except Exception:
                pass

    print("\n" + "=" * 80)
    print(f"  {TermColor.GREEN}[SUCCESS] BAP Uninstallation Complete.{TermColor.RESET}")
    print("=" * 80)



def configure_bap_config(target_dir: str, workspace_root: str, server_url: str, is_offline: bool = False):
    """Writes the active bap-config.json with the chosen server URL to installation target, workspace, and user state dirs."""
    effective_url = "http://localhost:8080" if is_offline else server_url.strip().rstrip("/")
    is_render = "onrender.com" in effective_url
    is_local = "localhost" in effective_url or "127.0.0.1" in effective_url

    cfg_data = {
        "controlplane_url": effective_url,
        "gateway_url": "http://localhost:9090",
        "envoy_url": "http://localhost:10000",
        "trust_domain": "bap.internal",
        "environment": "development" if (is_offline or is_local) else "production",
        "enforcement_mode": "enforce",
        "capture_user_prompt": True,
        "capture_agent_response": True,
        "developer_features": True,
        "oidc": {
            "enabled": not is_offline,
            "provider": "google" if is_render else ("entra" if not is_offline else "")
        }
    }
    
    cfg_json = json.dumps(cfg_data, indent=2) + "\n"

    destinations = [
        os.path.join(target_dir, "bap-config.json"),
        os.path.join(workspace_root, "bap-config.json"),
        os.path.join(workspace_root, ".bap", "bap-config.json"),
        os.path.join(os.path.expanduser("~"), "bap-config.json"),
        os.path.expanduser("~/.bapstate/config.json"),
        os.path.expanduser("~/.bapstate/bap-config.json"),
        os.path.expanduser("~/.bap/config.json"),
        os.path.expanduser("~/.bap/bap-config.json"),
    ]

    for dst in destinations:
        try:
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            with open(dst, "w", encoding="utf-8") as f:
                f.write(cfg_json)
        except Exception:
            pass

    # Synchronize via bapedge config set --global if bapedge binary is available
    bapedge_names = ["bapedge.exe", "bapedge"]
    bapedge_bin = None
    for name in bapedge_names:
        candidate = os.path.join(target_dir, name)
        if os.path.isfile(candidate):
            bapedge_bin = candidate
            break
    if not bapedge_bin:
        bapedge_bin = shutil.which("bapedge")

    if bapedge_bin:
        try:
            subprocess.run([bapedge_bin, "config", "set", "--server", effective_url, "--global"], capture_output=True, timeout=5)
        except Exception:
            pass

    # Purge stale credentials if they were bound to a different server URL (e.g. old localhost:8443)
    for cred_dir in [os.path.expanduser("~/.bapstate"), os.path.expanduser("~/.ltd")]:
        cred_file = os.path.join(cred_dir, "credentials.json")
        if os.path.isfile(cred_file):
            try:
                with open(cred_file, "r", encoding="utf-8") as f:
                    cdata = json.load(f)
                old_server = cdata.get("server_url", "").strip().rstrip("/")
                if old_server and old_server.lower() != effective_url.lower():
                    os.remove(cred_file)
            except Exception:
                pass

    print(f"  {TermColor.GREEN}[+] Control Plane Config : {effective_url} (written to bap-config.json){TermColor.RESET}")

def main():
    parser = argparse.ArgumentParser(
        description="BAP Universal User-Mode Installer — Single-click Zero-Trust onboarding for AI developer agents"
    )
    parser.add_argument("--dir", default=None, help="Target installation directory (default: ~/bin or %USERPROFILE%\\bin)")
    parser.add_argument("--roaming", action="store_true", help="Install to Windows Roaming AppData (%APPDATA%\\BAP\\bin) instead of user bin (%USERPROFILE%\\bin)")
    parser.add_argument("--workspace", default=os.getcwd(), help="Target workspace root to configure agent hooks")
    parser.add_argument("--server", default=DEFAULT_REMOTE_SERVER, help=f"Central BAP Control Plane URL (default: {DEFAULT_REMOTE_SERVER})")
    parser.add_argument("--system", action="store_true", help="Request administrative elevation for system-wide service installation")
    parser.add_argument("--offline", action="store_true", help="Install in purely offline local governance mode")
    parser.add_argument("--no-path", action="store_true", help="Skip updating User environment PATH")
    parser.add_argument("--non-interactive", action="store_true", help="Bypass interactive prompts and use defaults")
    parser.add_argument("--uninstall", action="store_true", help="Cleanly uninstall BAP binaries and restore original agent hooks")
    args = parser.parse_args()

    target_dir = args.dir if args.dir else resolve_default_install_dir(roaming=args.roaming)

    if args.uninstall:
        uninstall(target_dir, args.workspace)
        sys.exit(0)

    selected_server = args.server
    is_offline = args.offline
    
    # Interactive Server Selection (Default: Remote Server)
    explicit_server = any(arg.startswith("--server") for arg in sys.argv)
    if not explicit_server and not args.offline and not args.non_interactive and sys.stdin.isatty():
        print("\n" + "=" * 80)
        print("  SELECT CENTRAL BAP CONTROL PLANE FLEET:")
        print(f"  [1] Remote BAP Cloud Fleet ({DEFAULT_REMOTE_SERVER})  [Default]")
        print("  [2] Custom Enterprise Server URL (e.g. https://bap.corp.internal)")
        print("  [3] Offline / Local Resilience Mode (Standalone local governance without central fleet)")
        print("=" * 80)
        try:
            choice = input("  Enter selection [1/2/3] (Press Enter for default [1]): ").strip()
            if choice == "2":
                custom_url = input("  Enter BAP Control Plane URL: ").strip().rstrip("/")
                if custom_url:
                    selected_server = custom_url
            elif choice == "3":
                is_offline = True
            else:
                selected_server = DEFAULT_REMOTE_SERVER
        except (KeyboardInterrupt, EOFError):
            print("\n  Using default remote server.")
            selected_server = DEFAULT_REMOTE_SERVER

    plat_id = get_platform_id()
    print("=" * 80)
    print(f"     {TermColor.CYAN}{TermColor.BOLD}BAP ZERO-TRUST ENTERPRISE AGENT GOVERNANCE -- UNIVERSAL INSTALLER{TermColor.RESET}")
    print("=" * 80)
    print(f"[*] Detected Platform:    {plat_id} ({platform.system()} {platform.machine()})")
    print(f"[*] Target Install Mode:  {'SYSTEM SERVICE (Administrator)' if args.system else 'USER MODE (Zero Privilege / No Root)'}")
    print(f"[*] Target Directory:     {target_dir}")
    print(f"[*] Target Workspace:     {args.workspace}")
    print(f"[*] Control Plane URL:    {'OFFLINE (Local Store)' if is_offline else selected_server}")
    print("=" * 80)

    # 1. Admin escalation check (opt-in only)
    if args.system and not is_admin():
        print(f"\n{TermColor.YELLOW}[!] Administrator privileges requested for system-wide service.{TermColor.RESET}")
        if sys.platform == "win32":
            print("[*] Re-launching with UAC elevation...")
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit(0)
        else:
            print("[!] Please run with sudo: sudo python bap_install.py --system")
            sys.exit(1)

    # 2. Deploy core binaries
    deployed_count = install_core_binaries(target_dir)

    # 2.5 Configure Central Control Plane Endpoints & write bap-config.json
    configure_bap_config(target_dir, args.workspace, selected_server, is_offline)

    # 3. Update User PATH
    if not args.no_path:
        update_user_path(target_dir)

    # 4. Configure Agent Hooks
    agents = configure_agent_hooks(args.workspace, target_dir)

    # 5. Handshake with Control Plane
    if not is_offline:
        verify_controlplane_handshake(selected_server)

    # 6. Cryptographic Pinning Scan
    run_pin_scan(target_dir, args.workspace)

    # 6.5 Launch background supervisor daemon in user mode (zero admin rights required)
    bapedge_bin = os.path.join(target_dir, "bapedge.exe" if sys.platform == "win32" else "bapedge")
    if os.path.isfile(bapedge_bin):
        try:
            cflags = 0x08000000 | 0x00000200 if sys.platform == "win32" else 0
            subprocess.Popen(
                [bapedge_bin, "daemon", "start", "-server", selected_server],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                creationflags=cflags,
                start_new_session=True if sys.platform != "win32" else False
            )
            print(f"  {TermColor.GREEN}[+] BAP background supervisor daemon started in user space (zero admin rights required).{TermColor.RESET}")
        except Exception as e:
            pass

    # 7. Print Completion & Verification Banner
    print("\n" + "=" * 80)
    print(f"  {TermColor.GREEN}{TermColor.BOLD}[SUCCESS] BAP INSTALLATION COMPLETE! Your machine is ready to govern AI agents.{TermColor.RESET}")
    print("=" * 80)
    print(f"[+] Total Core Binaries Deployed : {deployed_count}")
    print(f"[+] Configured Agent Platforms   : {len(agents)}")
    for a in agents:
        print(f"    * {a}")
    print("-" * 80)
    print(f"{TermColor.BOLD}QUICKSTART -- RUN YOUR AGENTS WITH BAP ZERO-TRUST GOVERNANCE:{TermColor.RESET}")
    print(f"  1. Claude Code   : {TermColor.CYAN}claude{TermColor.RESET} (Hooks auto-intercept all actions)")
    print(f"  2. Antigravity   : Governed automatically via {TermColor.CYAN}GEMINI.md{TermColor.RESET} & BAP MCP")
    print(f"  3. VS Code Copilot: Opens with {TermColor.CYAN}CopilotSandbox{TermColor.RESET} governed profile")
    print(f"  4. Direct CLI    : {TermColor.CYAN}bapedge exec \"<command>\"{TermColor.RESET}")
    print(f"  5. Workstation Status: {TermColor.CYAN}bap status{TermColor.RESET} (Inspect 5-layer compliance & identity)")
    print(f"  6. Verification  : {TermColor.CYAN}bap doctor{TermColor.RESET} (Pre-flight diagnostic health check)")
    print(f"  7. Cockpit       : {TermColor.CYAN}bap launch{TermColor.RESET} (Open developer cockpit & monitor fleet)")
    print(f"  8. Uninstall     : {TermColor.CYAN}bap uninstall{TermColor.RESET} (Clean removal)")
    print("-" * 80)
    print(f"  {TermColor.YELLOW}Note: If 'bapedge' is not recognized in your current open terminal, simply open a{TermColor.RESET}")
    print(f"  {TermColor.YELLOW}new terminal window (or run 'refreshenv') so your shell reloads the updated PATH.{TermColor.RESET}")
    print("=" * 80)


if __name__ == "__main__":
    main()
