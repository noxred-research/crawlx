#!/usr/bin/env python3
"""Transfer same-run producer artifacts into release-gate's evidence layout.

  python3 -B ci/release-evidence.py --artifacts DIR --out bench/out
RELEASE_JOBS optionally contains the CI needs JSON, retained as producer provenance.
Only known producer files are copied. Missing measurements remain missing and block
release-gate; this script never creates suite results, waivers or passing metrics.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil


TRANSFERS = (
    ('release-evidence-g1/g1-report.json', 'g1-report.json', 'gate-g1'),
    ('release-evidence-mutants/outcomes.json', 'mutants-safety/outcomes.json', 'mutants'),
    ('release-evidence-unit/flake-history.json', 'flake-history-unit.json', 'unit'),
    ('release-evidence-browser/flake-history.json', 'flake-history-browser.json', 'browser'),
)
MISSING = {
    'scorecards/*.json': 'G1 supplies only its D1 subset. No full release ablation matrix '
        'across all fixtures, profiles and 21 seeds is exported by this workflow.',
    'suites/*.json': 'Existing test jobs run commands directly, not through release-gate record; '
        'job success is not a libtest count/skip record. SSRF, scope, canary/ZDR, dependency audit, '
        'stale proposal, differential, snapshot, chaos SLO and migration suite evidence remains absent. '
        'The Chromium canary is not the complete upgrade suite. Model outage also needs a recorded suite.',
    'suites/criterion_gates.json': 'bench-nightly runs only on schedules and uploads raw samples. '
        'No reference runner with pinned CPU governor and isolated cores is configured; '
        'shared-runner trends must not become a passing release measurement.',
    'findings.json': 'No severity-classified security-finding tracker export is connected to this workflow. '
        'An image vulnerability scan cannot establish zero open S1/S2 findings.',
    'run-to-run.json': 'No previous-release/candidate different-seed comparison producer is connected.',
    'coverage-paired.json': 'No paired restored-snapshot previous-release/candidate coverage comparison is connected.',
    'soak-report.json': 'No 24-hour PostgreSQL staging soak with scheduled faults runs in this workflow. '
        'Short chaos or memory samples are not substituted.',
    'restore-drill.json': 'No completed production-shaped restore drill exports its actual completion date.',
    'flake-report.json': 'Unit and browser jobs export separate histories. No merge of their retry-classified '
        'executions into a complete 30-day PR-suite window is connected. Raw histories are retained, '
        'not relabeled as a complete passing flake-rate report.',
    'g3-report.json': 'No release model calibration/shadow producer is connected. This item applies only '
        'when release-gate is explicitly called with --model-tier-changed.',
    'bench/baselines/release-base.json (repository)': 'The previous-release pin baseline must be committed '
        'from an actual release. The current pin is never copied as its own baseline.',
}


def collect(artifacts, out, jobs):
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for source, destination, job in TRANSFERS:
        path = artifacts / source
        row = {'source': source, 'destination': destination, 'producer': job,
               'producer_result': jobs.get(job, {}).get('result', 'unknown')}
        if path.is_file():
            target = out / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            with target.open('rb') as stream:
                row['sha256'] = hashlib.file_digest(stream, 'sha256').hexdigest()
            row.update(state='transferred', reason='actual same-run artifact; release-gate judges its contents')
        else:
            row.update(state='unmeasured', reason='producer artifact absent; producer may have failed or skipped')
            if job == 'gate-g1':
                row['reason'] += '; authenticated G1 runs only on scheduled/default-branch dispatch events, '
                row['reason'] += 'not tags, because signing keys are restricted to the default-branch environment'
        rows.append(row)
    return {'version': 1, 'inputs': rows, 'producers': jobs, 'remaining_inputs': MISSING,
            'policy': 'No prior-run artifacts or synthesized passing evidence. Missing inputs block release.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, required=True)
    parser.add_argument('--out', type=Path, default=Path('bench/out'))
    args = parser.parse_args()
    value = collect(args.artifacts, args.out, json.loads(os.environ.get('RELEASE_JOBS', '{}')))
    (args.out / 'release-evidence.json').write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    lines = ['# Release evidence transfer', '', value['policy'], '', '## Same-run inputs', '']
    lines.extend(f"- {row['destination']}: {row['state']} ({row['producer']}={row['producer_result']}) — {row['reason']}"
                 for row in value['inputs'])
    lines.extend(['', '## Remaining producer gaps', '',
                  'These are producer limitations, not waivers. The checklist judges actual files and applicability.', ''])
    lines.extend(f'- {path}: {reason}' for path, reason in MISSING.items())
    lines.extend(['', 'Release tags run the checklist, not a claim that the complete release suite has run.', ''])
    (args.out / 'release-evidence.md').write_text('\n'.join(lines))


if __name__ == '__main__':
    main()
