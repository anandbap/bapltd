#!/usr/bin/env python3
"""
Setup script for bap-ltd package
"""

from setuptools import setup, find_packages
import os

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

# Dynamically collect all files under bap/plugins, explicitly capturing hidden dot-directories like .claude-plugin
plugin_files = []
bap_plugins_dir = os.path.join(here, "bap", "plugins")
if os.path.isdir(bap_plugins_dir):
    for root, dirs, files in os.walk(bap_plugins_dir):
        for f in files:
            rel = os.path.relpath(os.path.join(root, f), os.path.join(here, "bap"))
            plugin_files.append(rel.replace("\\", "/"))

setup(
    name="bap-ltd",
    version="1.12.10",
    description="Bounded Authority Plane (BAP) - Zero-Trust Local Trusted Daemon & Governance for AI Developer Agents",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="BAP Security Architecture Team",
    author_email="security@bapltd.com",
    url="https://bap-controlplane.onrender.com",
    packages=find_packages(include=["bap", "bap.*", "bap_sdk", "bap_sdk.*"]),
    package_data={
        "bap": [
            "bin/*/*",
            "bin/*",
            "*.py",
            "*.cedar",
            "*.json",
            "*.ps1",
            "*.bat",
            "*.sh",
            "launchers/*",
            "plugins/**/*",
            "plugins/*/*/*",
            "plugins/*/*/*/*",
        ] + plugin_files,
    },
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[],
    entry_points={
        "console_scripts": [
            "bap = bap.cli:main",
            "bapedge = bap.cli:bapedge_proxy",
            "bap-install = bap.install:main",
            "bap-launch = bap.launch:main",
            "bap-doctor = bap.doctor:main",
        ]
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Programming Language :: Python :: 3",
    ],
)
