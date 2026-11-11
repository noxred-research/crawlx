#!/usr/bin/env python3
"""Summarize actual chromium-next logs and golden diffs; never approve a pin bump.

Run after the canary suites, including after failure:
  python3 -B ci/chromium-upgrade-report.py --evidence bench/out
CDP_OUTCOME, BROWSER_OUTCOME, REPLAY_OUTCOME and GOLDEN_OUTCOME carry the CI step outcomes.
The replay suite (`crawlx-bench --test replay_chromium`, the recorded-path replays on the candidate
build) counts like every other suite: a missing log is unmeasured, a failed run is a failure, and a run
that skipped its cases because no browser started is unmeasured, never a pass.
JSON and Markdown retain missing measurements instead of substituting passing claims.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tomllib


SUITES = ('cdp', 'browser', 'replay', 'golden')


def artifact(path):
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {'path': path.name, 'sha256': digest}


def suite(path, outcome):
    row = {'outcome': outcome, 'state': 'unmeasured', 'reason': 'suite log is absent'}
    if not path.is_file():
        return row
    row['artifact'] = artifact(path)
    text = path.read_text(errors='replace')
    summaries = re.findall(
        r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored;', text)
    if outcome == 'failure' or any(result == 'FAILED' for result, *_ in summaries):
        row.update(state='fail', reason='suite command failed; inspect the retained log')
    elif outcome != 'success':
        row['reason'] = f'suite outcome is {outcome}, not success'
    elif not summaries or sum(int(passed) for _, passed, _, _ in summaries) == 0:
        row['reason'] = 'no executed libtest cases in the log'
    elif re.search(r'^\s*(skipped|SKIP):', text, re.MULTILINE) or any(
            int(failed) or int(ignored) for _, _, failed, ignored in summaries):
        row['reason'] = 'suite contains skipped, failed or ignored cases'
    else:
        row.update(state='pass', reason='successful command with executed, non-skipped libtest cases')
    return row


def golden(path):
    row = {'artifact': artifact(path)}
    try:
        value = json.loads(path.read_text())
        for build in ('golden_build', 'fresh_build'):
            info = value[build]
            if not all(isinstance(info[key], str) and info[key]
                       for key in ('chromium_version', 'cdp_revision')):
                raise ValueError('missing browser build identity')
        if not isinstance(value['steps'], list) or not isinstance(value['origin_comparable'], bool):
            raise ValueError('invalid golden diff fields')
        comparable = value['origin_comparable']
        clean = not value['steps'] and value.get('step_count') is None
        row.update(
            state='fail' if not clean else ('pass' if comparable else 'unmeasured'),
            reason='derived trace matches' if clean and comparable else
                   ('origin-bearing digests were excluded' if clean else 'derived trace differs'),
            diff=value,
        )
    except (OSError, ValueError, KeyError, TypeError) as error:
        row.update(state='fail', reason=f'invalid golden diff: {error}')
    return row


def report(evidence, pin):
    suites = {name: suite(evidence / f'chromium-next-{name}.log',
                          os.environ.get(f'{name.upper()}_OUTCOME', 'unknown'))
              for name in SUITES}
    traces = [golden(path) for path in sorted(evidence.glob('golden-trace-diff.*.json'))]
    states = [row['state'] for row in suites.values()] + [row['state'] for row in traces]
    state = 'fail' if 'fail' in states else (
        'pass' if traces and all(item == 'pass' for item in states) else 'unmeasured')
    with pin.open('rb') as stream:
        pin_value = tomllib.load(stream)['chromium']
    return {
        'version': 1,
        'scope': 'next-stable protocol and derived-trace canary, not release approval',
        'canary_state': state,
        'pin': {'version': pin_value['version'], 'sha256': pin_value['sha256'],
                'cdp_revision': pin_value['cdp_revision']},
        'suites': suites,
        'golden_traces': traces,
        'unmeasured': {
            'paired_release_metrics': 'No restored-snapshot previous-pin/candidate runs across the release seed set; '
                'coverage confidence interval, collision/split rates, timeout-rate delta, checkpoint p95 '
                'and trusted-lane share are not inferred from the single golden trace.',
            'upgrade_suite': 'The canary is not the complete pin-match, browser-plane SSRF and full fixture/seed '
                'upgrade suite. No suites/chromium_upgrade.json is minted from these results.',
            'deployment': 'No candidate-image scan/SBOM, 24-hour staging fault soak, production canary, '
                'drained rollout or rollback evidence is produced by this job.',
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, default=Path('bench/out'))
    parser.add_argument('--pin', type=Path, default=Path('chromium-pin.toml'))
    args = parser.parse_args()
    args.evidence.mkdir(parents=True, exist_ok=True)
    value = report(args.evidence, args.pin)
    (args.evidence / 'chromium-upgrade-report.json').write_text(
        json.dumps(value, indent=2, sort_keys=True) + '\n')
    lines = ['# Chromium upgrade canary', '', value['scope'], '',
             f"Canary: **{value['canary_state']}**", '', '## Suites', '']
    lines.extend(f"- {name}: {row['state']} — {row['reason']}"
                 for name, row in value['suites'].items())
    lines.extend(['', '## Golden traces', ''])
    lines.extend(f"- {row['artifact']['path']}: {row['state']} — {row['reason']}"
                 for row in value['golden_traces'])
    if not value['golden_traces']:
        lines.append('- unmeasured: no golden-trace diff artifact was produced')
    lines.extend(['', '## Release measurements not supplied', ''])
    lines.extend(f'- {name}: {reason}' for name, reason in value['unmeasured'].items())
    lines.extend(['', 'Artifact SHA-256 digests and full trace differences are retained in the JSON report.', ''])
    (args.evidence / 'chromium-upgrade-report.md').write_text('\n'.join(lines))


if __name__ == '__main__':
    main()
