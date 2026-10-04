import os
import subprocess
import unittest


class TestPrivateCredentialsAndCerts(unittest.TestCase):
    def setUp(self):
        self.root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.edge_dir = os.path.join(self.root_dir, "bap-edge")
        self.gateway_dir = os.path.join(self.root_dir, "bap-gateway")
        self.cchook_dir = os.path.join(self.root_dir, "cchook")

    def test_gitignore_protects_private_credentials(self):
        """Ensure .gitignore blocks certificates, keys, and credentials from public git commits."""
        gitignore_path = os.path.join(self.root_dir, ".gitignore")
        self.assertTrue(os.path.exists(gitignore_path), ".gitignore must exist")
        with open(gitignore_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertIn("*.pem", content, "Private PEM files must be gitignored")
        self.assertIn("*.key", content, "Private keys must be gitignored")
        self.assertIn("*.crt", content, "Certificates must be gitignored")
        self.assertIn("*.pfx", content, "PFX credentials must be gitignored")

    def test_certs_placeholder_exists(self):
        """Ensure placeholder.txt exists so embed.FS compiles in clean public repo clones."""
        for d in [
            os.path.join(self.edge_dir, "internal", "httptransport", "certs"),
            os.path.join(self.gateway_dir, "internal", "httptransport", "certs"),
            os.path.join(self.cchook_dir, "certs"),
        ]:
            placeholder = os.path.join(d, "placeholder.txt")
            self.assertTrue(os.path.exists(placeholder), f"placeholder.txt must exist at {placeholder}")

    def test_edge_httptransport_compiles_without_local_cert(self):
        """Verify bap-edge httptransport compiles and tests successfully without embedded_ca.crt."""
        res = subprocess.run(
            ["go", "test", "./internal/httptransport"],
            cwd=self.edge_dir,
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"go test failed: {res.stderr}\n{res.stdout}")
        self.assertNotIn("no matching files found", res.stderr)

    def test_bap_gateway_compiles_without_local_cert(self):
        """Verify bap-gateway compiles successfully without embedded_ca.crt."""
        res = subprocess.run(
            ["go", "build", "."],
            cwd=self.gateway_dir,
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"bap-gateway build failed: {res.stderr}\n{res.stdout}")
        self.assertNotIn("no matching files found", res.stderr)

    def test_cchook_compiles_without_local_cert(self):
        """Verify cchook compiles successfully without embedded_ca.crt."""
        res = subprocess.run(
            ["go", "build", "interceptor.go"],
            cwd=self.cchook_dir,
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, f"cchook build failed: {res.stderr}\n{res.stdout}")
        self.assertNotIn("no matching files found", res.stderr)


if __name__ == "__main__":
    unittest.main()
