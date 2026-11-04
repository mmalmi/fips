#!/usr/bin/env python3
"""Validate and optionally upload an already prepared crate without running Cargo.

Wire format: https://doc.rust-lang.org/cargo/reference/registry-web-api.html
The private plan binds the exact source, artifact, signed-source proof and
resource admission. Credentials stay on the established publishing machine.
"""
import hashlib
import gzip
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import time
import tomllib
import urllib.error
import urllib.request

if not __debug__ or sys.version_info < (3, 11):
    raise RuntimeError('Publisher requires Python >=3.11 with optimization disabled')

MAX_ARCHIVE = 2_200_000
MAX_TAR = 20 * 1024**2
MAX_EXPANDED = 16 * 1024**2
MAX_FILE = 512 * 1024
MAX_MEMBERS = 1200


def bounded_read(path, limit):
    with Path(path).open('rb') as source:
        data = source.read(limit + 1)
    assert len(data) <= limit, 'input exceeds admitted bound'
    return data


def open_archive(data):
    assert len(data) <= MAX_ARCHIVE
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
        expanded = compressed.read(MAX_TAR + 1)
    assert len(expanded) <= MAX_TAR, 'tar expansion exceeds admitted bound'
    archive = tarfile.open(fileobj=io.BytesIO(expanded), mode='r:')
    members = archive.getmembers()
    assert 0 < len(members) <= MAX_MEMBERS
    assert sum(item.size for item in members) <= MAX_EXPANDED
    assert len({item.name for item in members}) == len(members), 'duplicate archive path'
    for item in members:
        assert item.isfile() or item.isdir(), 'unsupported archive entry'
        assert 0 <= item.size <= MAX_FILE
        assert not Path(item.name).is_absolute() and '..' not in Path(item.name).parts
    return archive


def metadata_from_archive(data):
    with open_archive(data) as archive:
        names = archive.getnames()
        prefix = names[0].split('/')[0] + '/'
        manifest = tomllib.loads(archive.extractfile(prefix + 'Cargo.toml').read().decode())
        package = manifest['package']
        assert prefix == package['name'] + '-' + package['version'] + '/'
        deps = []
        groups = [(None, manifest), *manifest.get('target', {}).items()]
        for target, group in groups:
            for table, kind in [('dependencies', 'normal'), ('dev-dependencies', 'dev'), ('build-dependencies', 'build')]:
                for alias, value in group.get(table, {}).items():
                    dependency = {'version': value} if isinstance(value, str) else value
                    assert 'path' not in dependency and 'git' not in dependency
                    assert not dependency.get('registry'), 'unexpected nonstandard registry'
                    deps.append({'name': dependency.get('package', alias),
                                 'version_req': dependency['version'],
                                 'features': dependency.get('features', []),
                                 'optional': dependency.get('optional', False),
                                 'default_features': dependency.get('default-features', True),
                                 'target': target, 'kind': kind, 'registry': None,
                                 'explicit_name_in_toml': alias if 'package' in dependency else None})
        readme = package.get('readme')
        assert readme is None or isinstance(readme, (str, bool))
        metadata = {'name': package['name'], 'vers': package['version'], 'deps': deps,
                    'features': manifest.get('features', {}), 'authors': package.get('authors', []),
                    'readme': archive.extractfile(prefix + readme).read().decode() if isinstance(readme, str) else None,
                    'readme_file': readme if isinstance(readme, str) else None,
                    'keywords': package.get('keywords', []), 'categories': package.get('categories', []),
                    'badges': manifest.get('badges', {}), 'rust_version': package.get('rust-version')}
        for key in ('description', 'documentation', 'homepage', 'license', 'repository', 'links'):
            metadata[key] = package.get(key)
        metadata['license_file'] = package.get('license-file')
        return metadata


def verify_source(data, root, relative, head):
    assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True, timeout=10).strip() == head
    assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=root, text=True, timeout=10).strip()
    count = 0
    with open_archive(data) as archive:
        prefix = archive.getnames()[0].split('/')[0] + '/'
        assert prefix + 'Cargo.toml.orig' in archive.getnames()
        vcs = json.load(archive.extractfile(prefix + '.cargo_vcs_info.json'))
        assert vcs['git']['sha1'] == head and not vcs['git'].get('dirty', False)
        assert vcs['path_in_vcs'] == relative
        for item in archive.getmembers():
            assert item.name.startswith(prefix) and not item.issym() and not item.islnk()
            name = item.name[len(prefix):]
            assert not any(part in ('..', '.git', '.env', 'work') for part in Path(name).parts)
            if not item.isfile() or name in ('.cargo_vcs_info.json', 'Cargo.toml', 'Cargo.lock'):
                continue
            path = root / relative / ('Cargo.toml' if name == 'Cargo.toml.orig' else name)
            assert path.is_file() and bounded_read(path, MAX_FILE) == archive.extractfile(item).read(), name
            assert bool(item.mode & 0o111) == bool(path.stat().st_mode & 0o111), name
            count += 1
        normalized = archive.extractfile(prefix + 'Cargo.toml').read()
        assert str(root).encode() not in normalized and b'[patch.' not in normalized
    assert count > 0
    return count


def verify_package_producer(data, plan):
    proof_data = bounded_read(plan['package_proof'], 1024 * 1024)
    assert hashlib.sha256(proof_data).hexdigest() == plan['package_proof_sha256']
    proof = json.loads(proof_data)
    assert proof['passed'] and proof['clean_before_and_after']
    assert proof['all_sources_match_git_blobs'] and proof['fresh_credentialless_cargo_home']
    assert proof['head'] == plan['head'] and proof['relative'] == plan['relative']
    assert proof['artifact_sha256'] == plan['sha256']
    assert proof['producer_sha256'] == plan['producer_sha256']
    assert proof['toolchain'] == plan['package_toolchain']
    assert proof['command'] == ['cargo', 'package', '--locked', '--no-verify', '-p', plan['name']]
    with open_archive(data) as archive:
        actual = {item.name: {'sha256': hashlib.sha256(archive.extractfile(item).read()).hexdigest(),
                             'bytes': item.size, 'mode': item.mode}
                  for item in archive.getmembers() if item.isfile()}
    assert actual == proof['files'], 'full Cargo-produced file set or contents differ'
    # The independently qualified credentialless producer ran pinned Cargo on
    # clean source. Its authenticated receipt binds generated manifests and
    # lockfiles too, including all features, targets and dependency changes.


def main():
    plan = json.loads(bounded_read(sys.argv[1], 64 * 1024))
    mode = sys.argv[2]
    assert mode in ('check', 'publish')
    output = Path(plan['output'])
    output.mkdir(parents=True, exist_ok=True)
    receipt_path = output / (plan['name'] + '-prepared-upload.json')
    if mode == 'publish':
        assert not receipt_path.exists(), 'reconcile any prior attempt before another upload'
    started = time.monotonic()
    initial = shutil.disk_usage(output).free
    assert initial >= plan['entry_bytes']

    def guard():
        free = shutil.disk_usage(output).free
        assert free >= plan['floor_bytes'] and initial - free <= plan['growth_bytes']
        assert time.monotonic() - started <= plan['seconds']

    def request(url, body=None, token=None, missing=False):
        guard()
        headers = {'User-Agent': 'FIPS prepared source archive publisher', 'Accept': 'application/json'}
        if token is not None:
            headers.update(Authorization=token, **{'Content-Type': 'application/octet-stream'})
        req = urllib.request.Request(url, data=body, headers=headers, method='PUT' if body is not None else 'GET')
        try:
            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *_args, **_kwargs):
                    raise RuntimeError('unexpected registry redirect')
            with urllib.request.build_opener(NoRedirect).open(req, timeout=20) as response:
                value = response.read(MAX_ARCHIVE + 1)
                assert len(value) <= MAX_ARCHIVE
                guard()
                return value
        except urllib.error.HTTPError as error:
            if missing and error.code == 404:
                return None
            raise

    receipt = {'passed': False, 'head': plan['head'], 'name': plan['name'], 'version': plan['version'],
               'cargo_or_compiler_started': False, 'upload_attempted': False}
    credential_accessed = False
    try:
        artifact = Path(plan['artifact'])
        data = bounded_read(artifact, MAX_ARCHIVE)
        digest = hashlib.sha256(data).hexdigest()
        assert digest == plan['sha256']
        verify_package_producer(data, plan)
        metadata = metadata_from_archive(data)
        assert metadata['name'] == plan['name'] and metadata['vers'] == plan['version']
        count = verify_source(data, Path(plan['root']), plan['relative'], plan['head'])
        for name, requirement in plan.get('exact_dependencies', {}).items():
            assert any(dep['name'] == name and dep['version_req'] == requirement for dep in metadata['deps'])
        proof_path = Path(plan['source_proof'])
        proof_bytes = bounded_read(proof_path, 1024 * 1024)
        assert hashlib.sha256(proof_bytes).hexdigest() == plan['source_proof_sha256']
        proof = json.loads(proof_bytes)
        assert proof['passed'] and proof['head'] == plan['head'] and proof['nonshallow']
        assert proof['source_url'] == plan['source_url']
        assert proof['verified_objects'] > 0 and proof['publisher_cache_or_daemon_used_for_readback'] is False
        encoded = json.dumps(metadata, separators=(',', ':')).encode()
        assert len(encoded) <= 128 * 1024
        receipt.update(sha256=digest, bytes=len(data), source_files_verified=count,
                       metadata_sha256=hashlib.sha256(encoded).hexdigest())
        api = 'https://crates.io/api/v1/crates/' + plan['name'] + '/' + plan['version']
        assert request(api, missing=True) is None, 'version exists; reconcile instead of uploading'
        if mode == 'publish':
            # Credential access occurs only for the explicitly selected publish
            # step. Never log it, persist it in a receipt, or send it off-host
            # except to the established crates.io HTTPS publication endpoint.
            credential_accessed = True
            token = os.environ.get('CARGO_REGISTRY_TOKEN')
            if token is None:
                cargo_home = Path(os.environ.get('CARGO_HOME', Path.home() / '.cargo'))
                token = tomllib.loads(bounded_read(cargo_home / 'credentials.toml', 64 * 1024).decode())['registry']['token']
            if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_-]{16,512}', token):
                raise RuntimeError('Invalid registry credential format')
            body = struct.pack('<I', len(encoded)) + encoded + struct.pack('<I', len(data)) + data
            receipt['upload_attempted'] = True
            receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
            response = json.loads(request('https://crates.io/api/v1/crates/new', body, token))
            assert not response.get('errors'), response.get('errors')
            receipt['warning_fields'] = sorted(response.get('warnings', {}))
            token = None
            for delay in (0, 2, 4, 8, 16):
                if delay:
                    time.sleep(delay)
                found = request(api, missing=True)
                if found is not None:
                    break
            assert found is not None, 'registry visibility pending; do not repeat upload'
            version = json.loads(found)['version']
            assert version['checksum'] == digest and not version['yanked']
            public = request('https://static.crates.io/crates/' + plan['name'] + '/' + plan['name'] + '-' + plan['version'] + '.crate')
            assert public == data, 'registry bytes differ'
            receipt['registry_byte_equal'] = True
            assert verify_source(data, Path(plan['root']), plan['relative'], plan['head']) == count
        guard()
        receipt['passed'] = True
    except BaseException as error:
        receipt['error'] = type(error).__name__ if credential_accessed else str(error)
    finally:
        receipt.update(seconds=time.monotonic() - started, final_free_bytes=shutil.disk_usage(output).free)
        destination = receipt_path if mode == 'publish' else output / (plan['name'] + '-prepared-check.json')
        destination.write_text(json.dumps(receipt, indent=2) + '\n')
        print(json.dumps(receipt))
    return 0 if receipt['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())
