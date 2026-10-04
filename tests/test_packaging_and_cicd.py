import os
import unittest
import xml.etree.ElementTree as ET

try:
    import yaml
except ImportError:
    yaml = None


class TestPackagingAndCICD(unittest.TestCase):
    def setUp(self):
        self.root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.workflows_dir = os.path.join(self.root_dir, ".github", "workflows")
        self.packaging_dir = os.path.join(self.root_dir, "packaging")

    def test_ci_workflow_structure(self):
        """Verify CI workflow YAML exists and covers multi-platform matrix."""
        ci_path = os.path.join(self.workflows_dir, "ci.yml")
        self.assertTrue(os.path.exists(ci_path), "ci.yml must exist")
        with open(ci_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("ubuntu-latest", content)
        self.assertIn("windows-latest", content)
        self.assertIn("macos-latest", content)
        self.assertIn("bap-edge", content)
        self.assertIn("bap-controlplane", content)

    def test_release_workflow_matrix_and_signing(self):
        """Verify release workflow YAML covers darwin-arm64, linux-amd64, windows-amd64, and signing."""
        release_path = os.path.join(self.workflows_dir, "release.yml")
        self.assertTrue(os.path.exists(release_path), "release.yml must exist")
        with open(release_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Check required target platforms from Gap 4
        self.assertIn("darwin-arm64", content, "Must include darwin-arm64 (macOS Apple Silicon)")
        self.assertIn("linux-amd64", content, "Must include linux-amd64")
        self.assertIn("windows-amd64", content, "Must include windows-amd64")

        # Check code signing steps
        self.assertIn("codesign", content, "Must have macOS codesign step")
        self.assertIn("signtool", content, "Must have Windows signtool step")

        # Check packaging steps
        self.assertIn("build_pkg.sh", content, "Must package macOS .pkg")
        self.assertIn("build_msi.ps1", content, "Must package Windows .msi")
        self.assertIn("mobileconfig", content, "Must include Jamf .mobileconfig")
        self.assertIn("SHA256SUMS.txt", content, "Must publish cryptographic checksums")

    def test_jamf_mobileconfig_profile(self):
        """Verify Jamf mobileconfig is a valid XML plist with required keys."""
        mobileconfig_path = os.path.join(self.packaging_dir, "jamf", "com.bap.edge.mobileconfig")
        self.assertTrue(os.path.exists(mobileconfig_path), "Jamf mobileconfig must exist")

        tree = ET.parse(mobileconfig_path)
        root = tree.getroot()
        self.assertEqual(root.tag, "plist")

        with open(mobileconfig_path, "r", encoding="utf-8") as f:
            xml_text = f.read()

        self.assertIn("com.bap.edge.settings", xml_text)
        self.assertIn("ControlPlaneURL", xml_text)
        self.assertIn("OIDCProvider", xml_text)
        self.assertIn("com.apple.TCC.configuration-profile-policy", xml_text)

    def test_jamf_support_files(self):
        """Verify macOS LaunchDaemon and packaging scripts exist."""
        plist_path = os.path.join(self.packaging_dir, "jamf", "com.bap.edge.plist")
        self.assertTrue(os.path.exists(plist_path), "LaunchDaemon plist must exist")

        postinstall_path = os.path.join(self.packaging_dir, "jamf", "postinstall.sh")
        self.assertTrue(os.path.exists(postinstall_path), "postinstall.sh must exist")

        build_pkg_path = os.path.join(self.packaging_dir, "jamf", "build_pkg.sh")
        self.assertTrue(os.path.exists(build_pkg_path), "build_pkg.sh must exist")

    def test_intune_csp_and_scripts(self):
        """Verify Microsoft Intune CSP XML and deployment scripts exist."""
        intune_xml = os.path.join(self.packaging_dir, "intune", "Intune-BAP-Policy.xml")
        self.assertTrue(os.path.exists(intune_xml), "Intune CSP XML must exist")

        tree = ET.parse(intune_xml)
        root = tree.getroot()
        self.assertTrue(root.tag.endswith("SyncML"))

        with open(intune_xml, "r", encoding="utf-8") as f:
            xml_text = f.read()

        self.assertIn("./Device/Vendor/MSFT/Policy/Config/BAP~Policy~BAPEdge/ControlPlaneURL", xml_text)
        self.assertIn("./Device/Vendor/MSFT/Policy/Config/BAP~Policy~BAPEdge/OIDCProvider", xml_text)

        install_ps1 = os.path.join(self.packaging_dir, "intune", "Install-BAPEdge.ps1")
        self.assertTrue(os.path.exists(install_ps1), "Install-BAPEdge.ps1 must exist")

        uninstall_ps1 = os.path.join(self.packaging_dir, "intune", "Uninstall-BAPEdge.ps1")
        self.assertTrue(os.path.exists(uninstall_ps1), "Uninstall-BAPEdge.ps1 must exist")

        detect_ps1 = os.path.join(self.packaging_dir, "intune", "Detect-BAPEdge.ps1")
        self.assertTrue(os.path.exists(detect_ps1), "Detect-BAPEdge.ps1 must exist")

        wxs_file = os.path.join(self.packaging_dir, "intune", "bapedge.wxs")
        self.assertTrue(os.path.exists(wxs_file), "bapedge.wxs WiX source must exist")

        build_msi_ps1 = os.path.join(self.packaging_dir, "intune", "build_msi.ps1")
        self.assertTrue(os.path.exists(build_msi_ps1), "build_msi.ps1 must exist")

    def test_linux_packaging_files(self):
        """Verify Linux systemd unit and debian packager exist."""
        service_path = os.path.join(self.packaging_dir, "linux", "bapedge.service")
        self.assertTrue(os.path.exists(service_path), "bapedge.service must exist")

        build_deb_path = os.path.join(self.packaging_dir, "linux", "build_deb.sh")
        self.assertTrue(os.path.exists(build_deb_path), "build_deb.sh must exist")


if __name__ == "__main__":
    unittest.main()
