"""Bounded release integrity checks. A hash manifest is not a publisher signature."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess

SCHEMA = 1
PLATFORMS = {"windows-amd64", "windows-arm64", "linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64"}
SCRIPTS = {"installer": "bap_install.py", "startup": "bap_startup.py", "doctor": "bap_doctor.py", "release_checker": "bap_release.py"}


def component_paths(binary_dir, package_dir, launcher_dir, platform):
    if platform not in PLATFORMS:
        raise ValueError("unsupported release platform")
    binary_dir, package_dir, launcher_dir = map(Path, (binary_dir, package_dir, launcher_dir))
    suffix = ".exe" if platform.startswith("windows-") else ""
    paths = {"edge": binary_dir / ("bapedge" + suffix), "interceptor": binary_dir / ("interceptor" + suffix)}
    paths.update({key: package_dir / name for key, name in SCRIPTS.items()})
    for key, name in (("claude", "run_claude_bap"), ("claude_cli", "run_claude_cli_bap"), ("claude_ide", "run_claude_ide_bap")):
        paths[key + "_sh"] = launcher_dir / (name + ".sh")
        if platform.startswith("windows-"):
            paths[key + "_ps1"] = launcher_dir / (name + ".ps1")
            paths[key + "_bat"] = launcher_dir / (name + ".bat")
    if platform.startswith("windows-"):
        paths["launcher_engine"] = launcher_dir / "bap_launcher_engine.ps1"
    return paths


def fingerprint(path):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or path.is_symlink() or before.st_size > 128 * 1024 * 1024:
        raise ValueError("component must be a bounded regular file")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(512 * 1024), b""):
            digest.update(block)
        opened = os.fstat(stream.fileno())
    after = path.stat()
    fields = lambda record: (record.st_dev, record.st_ino, record.st_size, record.st_mtime_ns)
    if fields(before) != fields(opened) or fields(before) != fields(after):
        raise ValueError("component changed during integrity inspection")
    return {"sha256": digest.hexdigest(), "size": after.st_size}


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def build_identity(path):
    """Read Go's embedded metadata without executing a target-platform binary."""
    result = {"commit": "unknown", "dirty": None}
    try:
        response = subprocess.run(["go", "version", "-m", str(path)], capture_output=True, text=True, timeout=10)
        if response.returncode == 0:
            for line in response.stdout.splitlines():
                if "vcs.revision=" in line:
                    result["commit"] = line.split("vcs.revision=", 1)[1].strip()
                if "vcs.modified=" in line:
                    result["dirty"] = line.split("vcs.modified=", 1)[1].strip() != "false"
    except (OSError, subprocess.SubprocessError):
        pass
    return result


def create_manifest(platform, paths, packaging_commit, identities):
    expected = component_paths("binary", "package", "launchers", platform)
    if set(paths) != set(expected):
        raise ValueError("release component set is incomplete or unsupported")
    manifest = {"schema_version": SCHEMA, "platform": platform, "profile": "claude-reference",
                "packaging_commit": packaging_commit, "binary_builds": identities,
                "files": {key: fingerprint(path) for key, path in sorted(paths.items())}}
    manifest["release_id"] = hashlib.sha256(canonical(manifest)).hexdigest()
    return manifest


def verify_manifest(manifest_path, paths, platform, require_qualified=False):
    path = Path(manifest_path)
    if path.is_symlink() or path.stat().st_size > 64 * 1024:
        raise ValueError("invalid release manifest file")
    manifest = json.loads(path.read_text(encoding="utf-8"))
    fields = {"schema_version", "platform", "profile", "packaging_commit", "binary_builds", "files", "release_id"}
    if not isinstance(manifest, dict) or set(manifest) != fields or manifest["schema_version"] != SCHEMA or manifest["platform"] != platform or manifest["profile"] != "claude-reference":
        raise ValueError("unsupported release manifest schema or platform")
    expected = component_paths("binary", "package", "launchers", platform)
    if set(paths) != set(expected) or not isinstance(manifest["files"], dict) or set(manifest["files"]) != set(expected):
        raise ValueError("unsupported release component set")
    content = {key: value for key, value in manifest.items() if key != "release_id"}
    release_id = hashlib.sha256(canonical(content)).hexdigest()
    if manifest["release_id"] != release_id:
        raise ValueError("release manifest digest mismatch")
    for key, filename in paths.items():
        record = manifest["files"][key]
        if not isinstance(record, dict) or set(record) != {"sha256", "size"} or fingerprint(filename) != record:
            raise ValueError("release component mismatch: " + key)
    commit = manifest["packaging_commit"]
    identities = manifest["binary_builds"]
    valid_commit = lambda value: isinstance(value, str) and (value == "unknown" or re.fullmatch(r"[0-9a-f]{40,64}", value) is not None)
    if not valid_commit(commit) or not isinstance(identities, dict) or set(identities) != {"edge", "interceptor"}:
        raise ValueError("invalid release build metadata")
    for identity in identities.values():
        if not isinstance(identity, dict) or set(identity) != {"commit", "dirty"} or not valid_commit(identity["commit"]) or not any(identity["dirty"] is allowed for allowed in (True, False, None)):
            raise ValueError("invalid release component build identity")
    qualified = isinstance(commit, str) and re.fullmatch(r"[0-9a-f]{40,64}", commit) is not None
    qualified = qualified and isinstance(identities, dict) and set(identities) == {"edge", "interceptor"}
    if qualified:
        qualified = all(isinstance(record, dict) and record.get("commit") == commit and record.get("dirty") is False for record in identities.values())
    if require_qualified and not qualified:
        raise ValueError("release source identity is unknown, dirty or mixed")
    return {"status": "integrity_verified", "release_id": release_id, "platform": platform,
            "packaging_commit": commit, "source_qualified": bool(qualified),
            "publisher_signature": "not_checked", "scope": "hashes match the supplied manifest; publisher authenticity requires an approved package trust anchor"}
