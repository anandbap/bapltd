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

            clean_entries = [p.strip() for p in current_path.split(";") if p.strip()]
            if clean_target.lower() not in [p.lower() for p in clean_entries]:
                clean_entries.append(clean_target)
                new_path = ";".join(clean_entries)
                winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
                print(f"  {TermColor.GREEN}[+] Added to Windows User PATH (HKCU\\Environment\\Path){TermColor.RESET}")
                
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
                shutil.copy2(src, dst)
                if sys.platform != "win32":
                    os.chmod(dst, 0o755)
                size_kb = os.path.getsize(dst) / 1024
                print(f"  {TermColor.GREEN}[+] {bin_name:<20}{TermColor.RESET} ({desc}) [{size_kb:.0f} KB]")
                deployed += 1
            except Exception as e:
                if os.path.isfile(dst):
                    size_kb = os.path.getsize(dst) / 1024
                    print(f"  {TermColor.GREEN}[OK] {bin_name:<20}{TermColor.RESET} ({desc}) [{size_kb:.0f} KB] (Active)")
                    deployed += 1
                else:
                    print(f"  {TermColor.YELLOW}[!] Failed copying {bin_name}: {e}{TermColor.RESET}")
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

    # 2. Google Antigravity
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

    # 3. Cursor IDE (.cursorrules + .cursor/mcp.json)
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

    # 4. GitHub Copilot (.vscode/settings.json + .vscode/mcp.json)
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

    # 5. Python Agent SDK
    py_agent_dir = os.path.join(REPO_ROOT, "python-agent")
    if os.path.isdir(py_agent_dir):
        print(f"  {TermColor.GREEN}[+] Python SDK:{TermColor.RESET} Local SDK available at {py_agent_dir}")
        detected_agents.append("Python Agent SDK (Available)")

    return detected_agents


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
        "copilot-wrap.bat", "copilot-wrap.ps1", "copilot-wrap.sh"
    ]
    for _base in [
        "run_antigravity_cli_bap", "run_antigravity_ide_bap",
        "run_copilot_cli_bap", "run_copilot_ide_bap",
        "run_claude_cli_bap", "run_claude_ide_bap",
        "run_claude_bap", "run_cursor_bap", "run_gemini_cli_bap"
    ]:
        for _ext in [".bat", ".ps1", ".sh", ""]:
            bap_files.append(_base + _ext)

    default_dir = resolve_default_install_dir()
    candidate_dirs = [target_dir]
    if os.path.abspath(target_dir).lower() == os.path.abspath(default_dir).lower():
        if sys.platform == "win32":
            if os.environ.get("APPDATA"):
                candidate_dirs.append(os.path.join(os.environ["APPDATA"], "BAP", "bin"))
            if os.environ.get("LOCALAPPDATA"):
                candidate_dirs.append(os.path.join(os.environ["LOCALAPPDATA"], "BAP", "bin"))
            candidate_dirs.append(os.path.join(home, "bin"))
        else:
            candidate_dirs.append(os.path.join(home, "bin"))
            candidate_dirs.append(os.path.expanduser("~/.local/bin"))

    # Remove duplicates
    seen = set()
    unique_dirs = []
    for d in candidate_dirs:
        norm = os.path.normpath(d)
        if norm.lower() not in seen:
            seen.add(norm.lower())
            unique_dirs.append(norm)

    # 1. Clean BAP files from candidate directories without wiping entire user folders
    for d in unique_dirs:
        if not os.path.isdir(d):
            continue
        removed_count = 0
        for f in bap_files:
            fp = os.path.join(d, f)
            if os.path.isfile(fp):
                try:
                    os.remove(fp)
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

    print("\n" + "=" * 80)
    print(f"  {TermColor.GREEN}[SUCCESS] BAP Uninstallation Complete.{TermColor.RESET}")
    print("=" * 80)


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
    print(f"  5. Verification  : {TermColor.CYAN}bap doctor{TermColor.RESET} (Pre-flight diagnostic health check)")
    print(f"  6. Cockpit       : {TermColor.CYAN}bap launch{TermColor.RESET} (Open developer cockpit & monitor fleet)")
    print(f"  7. Uninstall     : {TermColor.CYAN}bap uninstall{TermColor.RESET} (Clean removal)")
    print("=" * 80)


if __name__ == "__main__":
    main()
