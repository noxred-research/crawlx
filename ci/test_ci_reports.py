"""Offline regressions for artifact-backed CI reports (standard library only)."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


HERE = Path(__file__).resolve().parent


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), HERE / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


UPGRADE = load('chromium-upgrade-report')
RELEASE = load('release-evidence')
GOOD_LOG = 'test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n'


class UpgradeReportTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.pin = self.root / 'pin.toml'
        self.pin.write_text('[chromium]\nversion = "1.2.3.4"\nsha256 = "abc"\ncdp_revision = "1.3"\n')
        self.build = {'chromium_version': '1.2.3.4', 'cdp_revision': '1.3', 'pinned': True}

    def trace(self, **changes):
        value = {'fixture': 'g03', 'golden_build': self.build, 'fresh_build': self.build,
                 'origin_comparable': True, 'step_count': None, 'steps': []}
        value.update(changes)
        path = self.root / 'golden-trace-diff.g03.json'
        path.write_text(json.dumps(value))
        return path

    def test_success_needs_executed_cases_and_successful_step(self):
        path = self.root / 'suite.log'
        path.write_text(GOOD_LOG)
        self.assertEqual(UPGRADE.suite(path, 'success')['state'], 'pass')
        self.assertEqual(UPGRADE.suite(path, 'failure')['state'], 'fail')
        self.assertEqual(UPGRADE.suite(path, 'skipped')['state'], 'unmeasured')
        self.assertEqual(len(UPGRADE.suite(path, 'success')['artifact']['sha256']), 64)

    def test_skips_ignored_zero_cases_and_missing_logs_are_not_passes(self):
        path = self.root / 'suite.log'
        self.assertEqual(UPGRADE.suite(path, 'success')['state'], 'unmeasured')
        for text in ('', GOOD_LOG.replace('2 passed', '0 passed'),
                     GOOD_LOG.replace('0 ignored', '1 ignored'), 'skipped: missing browser\n' + GOOD_LOG):
            with self.subTest(text=text):
                path.write_text(text)
                self.assertEqual(UPGRADE.suite(path, 'success')['state'], 'unmeasured')

    def test_golden_diff_exposes_builds_and_differences(self):
        path = self.trace()
        row = UPGRADE.golden(path)
        self.assertEqual(row['state'], 'pass')
        self.assertEqual(row['diff']['fresh_build'], self.build)
        for changes in ({'steps': [{'index': 2, 'differences': ['identity differs']}]},
                        {'step_count': 'expected 16, got 15'}):
            with self.subTest(changes=changes):
                self.assertEqual(UPGRADE.golden(self.trace(**changes))['state'], 'fail')

    def test_partial_origin_comparison_and_malformed_diff_never_pass(self):
        path = self.trace(origin_comparable=False)
        self.assertEqual(UPGRADE.golden(path)['state'], 'unmeasured')
        for text in ('{', '{}', 'null'):
            with self.subTest(text=text):
                path.write_text(text)
                self.assertEqual(UPGRADE.golden(path)['state'], 'fail')

    def test_missing_trace_blocks_canary_even_with_successful_logs(self):
        for name in ('cdp', 'browser', 'golden'):
            (self.root / f'chromium-next-{name}.log').write_text(GOOD_LOG)
        outcomes = {f'{name}_OUTCOME': 'success' for name in ('CDP', 'BROWSER', 'GOLDEN')}
        with patch.dict(os.environ, outcomes):
            self.assertEqual(UPGRADE.report(self.root, self.pin)['canary_state'], 'unmeasured')
            self.trace()
            value = UPGRADE.report(self.root, self.pin)
        self.assertEqual(value['canary_state'], 'pass')
        self.assertIn('upgrade_suite', value['unmeasured'])
        self.assertFalse((self.root / 'suites/chromium_upgrade.json').exists())

    def test_cli_writes_reports_without_claiming_missing_evidence(self):
        subprocess.run([sys.executable, '-B', str(HERE / 'chromium-upgrade-report.py'),
                        '--evidence', str(self.root), '--pin', str(self.pin)], check=True)
        value = json.loads((self.root / 'chromium-upgrade-report.json').read_text())
        self.assertEqual(value['canary_state'], 'unmeasured')
        self.assertIn('no golden-trace diff artifact', (self.root / 'chromium-upgrade-report.md').read_text())


class ReleaseEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.artifacts = self.root / 'artifacts'
        self.out = self.root / 'out'

    def test_transfers_only_known_artifacts_without_changing_bytes(self):
        for source, destination, _ in RELEASE.TRANSFERS:
            path = self.artifacts / source
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'{"actual": true}\n')
        unknown = self.artifacts / 'release-evidence-other/findings.json'
        unknown.parent.mkdir(parents=True)
        unknown.write_text('{"open_s1": 0, "open_s2": 0}')
        jobs = {'gate-g1': {'result': 'failure'}}
        value = RELEASE.collect(self.artifacts, self.out, jobs)
        for source, destination, _ in RELEASE.TRANSFERS:
            self.assertEqual((self.artifacts / source).read_bytes(), (self.out / destination).read_bytes())
        self.assertTrue(all(row['state'] == 'transferred' for row in value['inputs']))
        self.assertEqual(value['inputs'][0]['producer_result'], 'failure')
        self.assertFalse((self.out / 'findings.json').exists())
        self.assertFalse((self.out / 'flake-report.json').exists())

    def test_absent_producers_remain_unmeasured(self):
        value = RELEASE.collect(self.artifacts, self.out, {'gate-g1': {'result': 'skipped'}})
        self.assertTrue(all(row['state'] == 'unmeasured' for row in value['inputs']))
        self.assertIn('signing keys', value['inputs'][0]['reason'])
        self.assertEqual(list(self.out.iterdir()), [])
        self.assertIn('soak-report.json', value['remaining_inputs'])
        self.assertIn('flake-report.json', value['remaining_inputs'])

    def test_cli_preserves_provenance_and_explains_gaps(self):
        env = {**os.environ, 'RELEASE_JOBS': '{"gate-g1": {"result": "skipped"}}'}
        subprocess.run([sys.executable, '-B', str(HERE / 'release-evidence.py'),
                        '--artifacts', str(self.artifacts), '--out', str(self.out)], check=True, env=env)
        value = json.loads((self.out / 'release-evidence.json').read_text())
        self.assertEqual(value['producers']['gate-g1']['result'], 'skipped')
        self.assertIn('not a claim', (self.out / 'release-evidence.md').read_text())
        self.assertFalse((self.out / 'suites').exists())


if __name__ == '__main__':
    unittest.main()
