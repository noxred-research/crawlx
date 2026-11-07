#!/usr/bin/env python3
"""Build an unpromoted Linux x64 candidate from an already synced/hooked checkout.

Python >= 3.11, Git, and the pinned depot_tools installation are required.
All writable inputs, outputs, caches and temporary files must reside under the work
directory (--workdir or CRAWLX_CHROMIUM_WORKDIR; default ~/.cache/crawlx).
This never fetches, syncs, resets, cleans, updates the pin, or runs browser tests.

  python3 -B ci/build-chromium.py --destination ~/.cache/crawlx/chromium-candidate
  python3 -B ci/build-chromium.py --build-only --target browser_tests --jobs 8

The checkout must retain sync-revisions.json from its completed pinned sync.
An exact already-applied prefix of ci/chromium-patches/*.patch is accepted.
Other source edits are rejected before any patch is applied. Existing edits are
never reverted. Failed builds retain their output; destinations are never reused.
"""

import argparse
import base64
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import tomllib
import zipfile
import zlib


REPO = Path(__file__).resolve().parent.parent
# Every path this script writes or trusts must reside under this directory; set in main().
WORK_BASE = None


def default_workdir():
    cache = os.environ.get('XDG_CACHE_HOME') or str(Path.home() / '.cache')
    return Path(cache) / 'crawlx'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def work_path(value):
    path = Path(value).resolve()
    require(path.is_relative_to(WORK_BASE) and path != WORK_BASE,
            f'path must reside under {WORK_BASE}: {value}')
    return path


def digest(path):
    with path.open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def json_file(path, value):
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + '\n')


def run(argv, cwd, env, capture=False):
    print('+ ' + ' '.join(map(str, argv)), file=sys.stderr)
    return subprocess.run(list(map(str, argv)), cwd=cwd, env=env, check=True,
                          stdout=subprocess.PIPE if capture else None).stdout


def git(path, env, *args):
    return run(['git', '-C', path, *args], path, env, capture=True)


def check_git(path, revision, env, clean=True):
    require(git(path, env, 'rev-parse', '--show-toplevel').decode().strip() == str(path),
            f'not an independent Git checkout: {path}')
    require(git(path, env, 'rev-parse', 'HEAD').decode().strip() == revision,
            f'wrong revision: {path}; expected {revision}')
    if clean:
        require(not git(path, env, 'status', '--porcelain=v1', '--untracked-files=normal'),
                f'dirty dependency/tool checkout: {path}')


def check_dependencies(root, config, env):
    receipt_path = root / 'sync-revisions.json'
    require(digest(receipt_path) == config['sync_receipt_sha256'],
            'sync-revisions.json does not match the pinned completed sync')
    require(digest(root / '.gclient') == config['gclient_sha256'],
            '.gclient differs from the pinned Linux sync configuration')
    receipt = json.loads(receipt_path.read_bytes())
    for name, entry in sorted(receipt['solutions'].items()):
        if not entry['was_processed']:
            continue
        require(entry['was_synced'], f'dependency was not synced: {name}')
        if entry['scm'] == 'git':
            check_git(work_path(root / name), entry['revision'], env, clean=name != 'src/')
    gcs_inventory = []
    for name, entry in sorted(receipt['solutions'].items()):
        if entry['scm'] != 'gcs' or not entry['was_processed']:
            continue
        directory, object_name = name.rstrip('/').split(':', 1)
        # Match GcsDependency.file_prefix in the pinned depot_tools/gclient.py.
        prefix = object_name.replace('/', '_').replace('\\', '_').replace('.', '_')
        marker = work_path(root / directory) / f'.{prefix}_hash'
        value = marker.read_text().strip()
        require(re.fullmatch(r'[0-9a-f]{64}', value), f'invalid GCS checksum receipt: {marker}')
        gcs_inventory.append({'dependency': name, 'sha256': value})
    require(hashlib.sha256(canonical(gcs_inventory)).hexdigest() == config['gcs_inventory_sha256'],
            'installed GCS object receipts differ from the pinned sync')

    # Verify installed package identities AND their actual installed file bytes.
    # This reads CIPD's pinned local receipts; it never resolves mutable tags online.
    inventory = []
    manifests = []
    for package in sorted((root / '.cipd/pkgs').iterdir()):
        description = json.loads((package / 'description.json').read_bytes())
        current = work_path(package / '_current')
        manifest = current / '.cipdpkg/manifest.json'
        inventory.append({**description, 'instance_id': current.name,
                          'manifest_sha256': digest(manifest)})
        manifests.append((description, json.loads(manifest.read_bytes())))
    inventory.sort(key=lambda p: (p['subdir'], p['package_name']))
    require(hashlib.sha256(canonical(inventory)).hexdigest() == config['cipd_inventory_sha256'],
            'installed CIPD package inventory differs from the pinned sync')
    for description, manifest in manifests:
        directory = work_path(root / description['subdir'])
        for entry in manifest['files']:
            path = directory / entry['name']
            require(work_path(path).is_relative_to(directory), f'package file escapes root: {path}')
            if 'symlink' in entry:
                require(path.is_symlink() and os.readlink(path) == entry['symlink'],
                        f'changed CIPD symlink: {path}')
            else:
                require(path.is_file() and path.stat().st_size == entry['size'],
                        f'missing or changed CIPD file: {path}')
                value = base64.urlsafe_b64encode(bytes.fromhex(digest(path))).decode().rstrip('=') + 'C'
                require(value == entry['hash'], f'changed CIPD file: {path}')
                require(bool(path.stat().st_mode & 0o111) == bool(entry.get('executable')),
                        f'changed CIPD executable mode: {path}')
    return inventory, gcs_inventory


def owned_patch_prefix(source, temporary, env, patches):
    paths = set()
    for patch in patches:
        for line in patch.read_text().splitlines():
            if line.startswith('diff --git '):
                match = re.fullmatch(r'diff --git a/([^ ]+) b/([^ ]+)', line)
                require(match is not None, f'unsupported patch path syntax: {patch}')
                for name in match.groups():
                    require(not Path(name).is_absolute() and '..' not in Path(name).parts,
                            f'unsafe patch path: {name}')
                    paths.add(name)
    require(paths, 'no source changes found in the versioned patch set')
    changed = git(source, env, 'diff', '--name-only', '-z', 'HEAD').split(b'\0')
    untracked = git(source, env, 'ls-files', '--others', '--exclude-standard', '-z').split(b'\0')
    foreign = {p.decode() for p in changed + untracked if p} - paths
    require(not foreign, 'unrelated source changes: ' + ', '.join(sorted(foreign)))
    require(not git(source, env, 'diff', '--cached', '--name-only'),
            'source index has staged changes; leave the index untouched and unstage them first')
    actual = {}
    for name in sorted(paths):
        path = source / name
        if not path.exists():
            actual[name] = None
        else:
            require(path.is_file() and not path.is_symlink(), f'non-regular patch input: {path}')
            mode = '100755' if path.stat().st_mode & 0o111 else '100644'
            actual[name] = (mode, git(source, env, 'hash-object', '--no-filters', '--', name).decode().strip())

    # An isolated index models each exact patch prefix without changing the real index.
    index_env = {**env, 'GIT_INDEX_FILE': str(temporary / 'patch.index')}
    git(source, index_env, 'read-tree', 'HEAD')
    prefix = None
    for count in range(len(patches) + 1):
        expected = dict.fromkeys(paths)
        entries = git(source, index_env, 'ls-files', '--stage', '-z', '--', *sorted(paths))
        for entry in entries.split(b'\0'):
            if entry:
                metadata, name = entry.decode().split('\t', 1)
                mode, oid, stage = metadata.split()
                require(stage == '0', 'unmerged temporary patch index')
                expected[name] = (mode, oid)
        if actual == expected:
            prefix = count
        if count < len(patches):
            git(source, index_env, 'apply', '--cached', '--whitespace=error', patches[count])
    require(prefix is not None,
            'source edits are not an exact prefix of the current patches; no files were changed')
    return prefix


def stage_entry(source, relative, output, package):
    require(not relative.is_absolute() and '..' not in relative.parts,
            f'unsafe archive member: {relative}')
    require(source.resolve().is_relative_to(output), f'runtime asset escapes build output: {source}')
    require(source.exists(), f'missing required runtime asset: {source}')
    destination = package / relative
    if source.is_dir():
        destination.mkdir(parents=True, exist_ok=True)
        for child in sorted(source.iterdir()):
            stage_entry(child, relative / child.name, output, package)
    else:
        require(source.is_file(), f'not a regular runtime asset: {source}')
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            require(digest(destination) == digest(source), f'conflicting runtime asset: {relative}')
        else:
            shutil.copy2(source, destination)


def package_candidate(source, output, destination, config, env, provenance):
    package = destination / 'chrome-linux64'
    package.mkdir()
    archive_config = source / config['archive_config']
    archives = json.loads(archive_config.read_bytes())['archive_datas']
    browser = [a for a in archives if 'chrome' in a.get('files', [])]
    require(len(browser) == 1, 'upstream browser archive definition is not unique')
    require(not browser[0].get('file_globs'), 'unsupported upstream browser archive globs')
    members = set(browser[0]['files'] + browser[0].get('dirs', []))
    runtime = run([source / 'buildtools/linux64/gn', 'desc', output,
                   config['runtime_target'], 'runtime_deps'], source, env, capture=True).decode()
    runtime_paths = [line.strip() for line in runtime.splitlines() if line.strip()]
    require(runtime_paths, 'GN returned an empty browser runtime dependency list')
    for name in runtime_paths:
        path = Path(os.path.normpath(name))
        require(not path.is_absolute() and '..' not in path.parts,
                f'GN runtime dependency is not relocatable within the build output: {name}')
        members.add(str(path))
    for name in sorted(members):
        stage_entry(output / name, Path(name), output, package)
    require(os.access(package / 'chrome', os.X_OK), 'staged chrome is not executable')

    dictionary_path = REPO / 'ci/chromium-dictionaries.toml'
    dictionary = tomllib.loads(dictionary_path.read_text())
    require(dictionary['chromium_revision'] == config['source_revision'] and
            dictionary['chromium_version'] == config['chromium_version'],
            'dictionary manifest does not match this Chromium build')
    run(['bash', '-euc', dictionary['package']['install_command']], source,
        {**env, 'CHROMIUM_SRC': str(source), 'CHROMIUM_PACKAGE_ROOT': str(package)})
    for entry in dictionary['input']:
        path = package / dictionary['destination_directory'] / entry['path']
        require(digest(path) == entry['sha256'], f'packaged dictionary input changed: {path}')
        if 'size' in entry:
            require(path.stat().st_size == entry['size'], f'wrong dictionary size: {path}')
    shutil.copy2(source / 'LICENSE', package / 'LICENSE.chromium')
    run([sys.executable, '-B', source / 'tools/licenses/licenses.py', 'license_file',
         '--format=notice', '--gn-out-dir', output, '--gn-target', config['runtime_target'],
         '--target-os=linux', package / 'THIRD_PARTY_NOTICES'], source, env)

    records = package / 'SOURCE_PROVENANCE'
    records.mkdir()
    for path in [REPO / 'ci/chromium-build.toml', dictionary_path,
                 source.parent / 'sync-revisions.json', source.parent / '.gclient',
                 output / 'args.gn', archive_config, REPO / 'ci/build-chromium.py']:
        shutil.copy2(path, records / path.name)
    for patch in provenance['patches']:
        shutil.copy2(REPO / patch['path'], records / Path(patch['path']).name)
    json_file(records / 'cipd-inventory.json', provenance['cipd_inventory'])
    (records / 'chrome.runtime_deps').write_text(runtime)
    provenance['packaging'] = {
        'upstream_archive_config': config['archive_config'],
        'upstream_archive_config_sha256': digest(archive_config),
        'runtime_deps_sha256': hashlib.sha256(runtime.encode()).hexdigest(),
        'license_tool_sha256': digest(source / 'tools/licenses/licenses.py'),
        'dictionary_manifest_sha256': digest(dictionary_path),
        'layout': 'chrome-linux64/chrome',
        'zip_timestamp': '1980-01-01T00:00:00',
    }
    provenance['files'] = [
        {'path': str(path.relative_to(package)), 'sha256': digest(path),
         'size': path.stat().st_size, 'mode': oct(stat.S_IMODE(path.stat().st_mode))}
        for path in sorted(package.rglob('*')) if path.is_file()
    ]
    json_file(package / 'PROVENANCE.json', provenance)
    archive = destination / 'chrome-linux64.zip'
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as bundle:
        for path in sorted(package.rglob('*')):
            if path.is_file():
                member = zipfile.ZipInfo(str(path.relative_to(destination)), (1980, 1, 1, 0, 0, 0))
                member.create_system = 3
                member.external_attr = (stat.S_IFREG | stat.S_IMODE(path.stat().st_mode)) << 16
                member.compress_type = zipfile.ZIP_DEFLATED
                with path.open('rb') as reader, bundle.open(member, 'w', force_zip64=True) as writer:
                    shutil.copyfileobj(reader, writer, length=1024 * 1024)
    checksum = digest(archive)
    (destination / 'chrome-linux64.zip.sha256').write_text(f'{checksum}  {archive.name}\n')
    json_file(destination / 'archive-provenance.json', {
        'schema_version': 1, 'promoted': False, 'archive': archive.name,
        'sha256': checksum, 'size': archive.stat().st_size,
        'embedded_provenance_sha256': digest(package / 'PROVENANCE.json'),
        'source_revision': config['source_revision'], 'patches': provenance['patches'],
    })
    print(archive)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--workdir', help='directory every path must reside under (default: $CRAWLX_CHROMIUM_WORKDIR or ~/.cache/crawlx)')
    parser.add_argument('--root', help='prepared checkout root containing src and depot_tools (default: WORKDIR/chromium-build)')
    parser.add_argument('--output', help='GN output directory; default: ROOT/src/out/Crawlx')
    parser.add_argument('--destination', help='new candidate directory under the work directory; must not already exist')
    parser.add_argument('--jobs', type=int, default=8, help='local build parallelism (default: 8)')
    parser.add_argument('--target', action='append', default=[], help='additional Ninja target to build, not run')
    parser.add_argument('--build-only', action='store_true', help='build selected targets without packaging')
    args = parser.parse_args()
    global WORK_BASE
    WORK_BASE = Path(args.workdir or os.environ.get('CRAWLX_CHROMIUM_WORKDIR') or default_workdir()).expanduser().resolve()
    require(platform.system() == 'Linux' and platform.machine() == 'x86_64', 'only Linux x86_64 is supported')
    require(args.jobs > 0, '--jobs must be positive')
    require(args.build_only != bool(args.destination), 'supply either --destination or --build-only')
    require(all(re.fullmatch(r'[A-Za-z0-9_./:+-]+', t) and not t.startswith('-') for t in args.target),
            'invalid Ninja target')
    root = work_path(args.root or WORK_BASE / 'chromium-build')
    source = work_path(root / 'src')
    depot = work_path(root / 'depot_tools')
    output = work_path(args.output or source / 'out/Crawlx')
    require(output.is_relative_to(source / 'out') and output != source / 'out',
            '--output must be a child of ROOT/src/out')
    destination = work_path(args.destination) if args.destination else None
    if destination:
        require(not destination.exists(), 'candidate destination already exists; choose a new directory')
        require(not destination.is_relative_to(source) and not destination.is_relative_to(depot),
                'candidate destination must not reside in a source/tool checkout')
    config = tomllib.loads((REPO / 'ci/chromium-build.toml').read_text())
    pin = tomllib.loads((REPO / 'chromium-pin.toml').read_text())['chromium']
    require(pin['version'] == config['chromium_version'], 'build configuration does not match chromium-pin.toml')
    for directory in ('tmp', 'home', 'cache', 'cache/cipd', 'cache/vpython'):
        work_path(root / directory).mkdir(parents=True, exist_ok=True)
    env = {
        'PATH': f'{depot}:/usr/local/bin:/usr/bin:/bin', 'HOME': str(root / 'home'),
        'TMPDIR': str(root / 'tmp'), 'TMP': str(root / 'tmp'), 'TEMP': str(root / 'tmp'),
        'XDG_CACHE_HOME': str(root / 'cache'), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
        'DEPOT_TOOLS_UPDATE': '0', 'DEPOT_TOOLS_METRICS': '0',
        'DEPOT_TOOLS_COLLECT_METRICS': '0', 'DEPOT_TOOLS_BUILD_TELEMETRY': '0',
        'CIPD_CACHE_DIR': str(root / 'cache/cipd'),
        'VPYTHON_VIRTUALENV_ROOT': str(root / 'cache/vpython'),
        'PYTHONDONTWRITEBYTECODE': '1', 'GIT_OPTIONAL_LOCKS': '0',
        'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': '/dev/null',
    }
    with (root / '.crawlx-build.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        check_git(depot, config['depot_tools_revision'], env)
        check_git(source, config['source_revision'], env, clean=False)
        inventory, gcs_inventory = check_dependencies(root, config, env)
        patches = sorted((REPO / 'ci/chromium-patches').glob('[0-9][0-9][0-9][0-9]-*.patch'))
        patch_records = [{'path': str(p.relative_to(REPO)), 'sha256': digest(p)} for p in patches]
        inputs = [REPO / name for name in (
            'ci/build-chromium.py', 'ci/chromium-build.toml',
            'ci/chromium-dictionaries.toml', 'chromium-pin.toml')]
        input_hashes = {str(path): digest(path) for path in inputs}
        with tempfile.TemporaryDirectory(prefix='crawlx-patch-', dir=root / 'tmp') as directory:
            prefix = owned_patch_prefix(source, Path(directory), env, patches)
        for patch in patches[prefix:]:
            git(source, env, 'apply', '--check', '--whitespace=error', patch)
            git(source, env, 'apply', '--whitespace=error', patch)
        gn_args = '\n'.join(config['gn_args']) + '\n'
        args_path = output / 'args.gn'
        normalize = lambda text: re.sub(r'\s+', '', re.sub(r'#[^\n]*', '', text))
        if args_path.exists():
            require(normalize(args_path.read_text()) == normalize(gn_args),
                    'existing args.gn differs from pinned arguments; choose a new --output')
        else:
            require(not output.exists() or not any(output.iterdir()),
                    'nonempty output directory has no args.gn; choose a new --output')
            output.mkdir(parents=True, exist_ok=True)
            args_path.write_text(gn_args)
        env['SOURCE_DATE_EPOCH'] = git(source, env, 'show', '-s', '--format=%ct', 'HEAD').decode().strip()
        commands = [
            [str(source / 'buildtools/linux64/gn'), 'gen', str(output), '--fail-on-unused-args'],
            [str(depot / 'autoninja'), '--offline', '-C', str(output), '-j', str(args.jobs),
             *config['build_targets'], *args.target],
        ]
        for command in commands:
            run(command, source, env)
        if args.build_only:
            print(f'build completed: {output}; no browser tests were run', file=sys.stderr)
            return
        # Refuse packaging if source, configuration or dependency inputs changed.
        current_patches = sorted((REPO / 'ci/chromium-patches').glob('[0-9][0-9][0-9][0-9]-*.patch'))
        require(patch_records == [{'path': str(p.relative_to(REPO)), 'sha256': digest(p)} for p in current_patches],
                'patch inputs changed during build; no candidate was packaged')
        require(input_hashes == {str(path): digest(path) for path in inputs},
                'build/package configuration changed during build')
        require(normalize(args_path.read_text()) == normalize(gn_args),
                'GN arguments changed during build')
        check_git(depot, config['depot_tools_revision'], env)
        check_git(source, config['source_revision'], env, clean=False)
        check_dependencies(root, config, env)
        with tempfile.TemporaryDirectory(prefix='crawlx-patch-', dir=root / 'tmp') as directory:
            require(owned_patch_prefix(source, Path(directory), env, patches) == len(patches),
                    'source patches changed during build; no candidate was packaged')
        destination.mkdir(parents=True)
        provenance = {
            'schema_version': 1, 'promoted': False, 'test_evidence': [],
            'source': {'url': config['source_url'], 'revision': config['source_revision'],
                       'version': config['chromium_version'], 'source_date_epoch': env['SOURCE_DATE_EPOCH']},
            'depot_tools_revision': config['depot_tools_revision'],
            'sync_receipt_sha256': config['sync_receipt_sha256'],
            'gclient_sha256': config['gclient_sha256'], 'cipd_inventory': inventory,
            'gcs_inventory': gcs_inventory,
            'patches': patch_records, 'gn_args': config['gn_args'], 'build_commands': commands,
            'tools': {name: digest(source / name) for name in (
                'buildtools/linux64/gn', 'third_party/llvm-build/Release+Asserts/bin/clang',
                'third_party/llvm-build/Release+Asserts/bin/ld.lld',
                'third_party/ninja/ninja', 'third_party/siso/cipd/siso')},
            'host': {'system': platform.system(), 'machine': platform.machine(),
                     'release': platform.release(), 'python': platform.python_version(),
                     'zlib': zlib.ZLIB_VERSION},
        }
        package_candidate(source, output, destination, config, env, provenance)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f'build-chromium: {error}', file=sys.stderr)
        sys.exit(1)
