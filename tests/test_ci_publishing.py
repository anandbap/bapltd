"""Protect automatic publishing and qualification-only release calls."""

from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


def workflow(name):
    return yaml.load(
        (ROOT / '.github/workflows' / name).read_text(encoding='utf-8'),
        Loader=yaml.BaseLoader,
    )


class PublishingWorkflowTests(unittest.TestCase):
    def test_ci_publishes_only_after_both_test_jobs_succeed(self):
        ci = workflow('ci.yml')
        self.assertEqual(ci['on']['push']['branches'], ['main'])
        job = ci['jobs']['publish-pypi']
        self.assertEqual(job['needs'], ['test-go', 'test-python'])
        self.assertEqual(
            job['if'],
            "${{ !inputs.validation_only && ((github.event_name == 'push' && github.ref == 'refs/heads/main') || github.event_name == 'workflow_dispatch') }}",
        )
        self.assertEqual(job['environment']['name'], 'pypi')
        download = next(s for s in job['steps'] if s.get('uses', '').startswith('actions/download-artifact@'))
        self.assertEqual(download['with']['name'], 'bap-windows-amd64-executables')
        publish = next(s for s in job['steps'] if s.get('uses', '').startswith('pypa/gh-action-pypi-publish@'))
        self.assertEqual(publish['with']['password'], '${{ secrets.PYPI_API_TOKEN }}')
        self.assertEqual(publish['with']['skip-existing'], 'true')

    def test_reusable_release_qualification_does_not_publish_twice(self):
        ci = workflow('ci.yml')
        self.assertEqual(ci['on']['workflow_call']['inputs']['validation_only']['default'], 'true')
        release = workflow('release.yml')
        qualify = release['jobs']['qualify']
        self.assertEqual(qualify['with']['validation_only'], 'true')
        self.assertEqual(qualify['permissions']['id-token'], 'write')
        self.assertIn('publish-pypi', release['jobs'])


if __name__ == '__main__':
    unittest.main()
