"""CI and release must work with unset variables and honor enterprise-only sources."""
from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ("ci.yml", "release.yml")
DEFAULTS = {
    "GOPROXY": "https://proxy.golang.org,direct",
    "GOSUMDB": "sum.golang.org",
    "PIP_INDEX_URL": "https://pypi.org/simple",
    "PIP_EXTRA_INDEX_URL": "",
}


def dependency_environment(name, variables):
    workflow = yaml.load((ROOT / ".github/workflows" / name).read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    result = {}
    for key in DEFAULTS:
        value = workflow["env"][key]
        if value.startswith("${{"):
            expression = re.fullmatch(r"\$\{\{\s*vars\.(\w+)\s*(?:\|\|\s*'([^']*)'\s*)?\}\}", value)
            if not expression:
                raise ValueError("Unsupported dependency source expression: " + key)
            variable, fallback = expression.groups()
            value = variables.get(variable) or fallback or ""
        result[key] = value
    return result


class DependencySourceWorkflowTests(unittest.TestCase):
    def test_clean_runner_without_variables_gets_usable_defaults(self):
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow):
                self.assertEqual(dependency_environment(workflow, {}), DEFAULTS)

    def test_empty_variables_use_the_same_defaults(self):
        variables = {"BAP_GO_PROXY": "", "BAP_GO_SUMDB": "", "BAP_PYPI_INDEX": ""}
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow):
                self.assertEqual(dependency_environment(workflow, variables), DEFAULTS)

    def test_enterprise_override_does_not_add_public_fallback(self):
        variables = {
            "BAP_GO_PROXY": "https://packages.example.test/go",
            "BAP_GO_SUMDB": "off",
            "BAP_PYPI_INDEX": "https://packages.example.test/pypi/simple",
        }
        expected = {"GOPROXY": variables["BAP_GO_PROXY"], "GOSUMDB": "off",
                    "PIP_INDEX_URL": variables["BAP_PYPI_INDEX"], "PIP_EXTRA_INDEX_URL": ""}
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow):
                self.assertEqual(dependency_environment(workflow, variables), expected)


if __name__ == "__main__":
    unittest.main()
