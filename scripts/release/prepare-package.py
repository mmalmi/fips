#!/usr/bin/env python3
"""Credentialless, no-build Cargo packaging on the qualified Linux host.

Run under the admitted external CPU/memory/deadline supervisor. Transfer the
artifact and this receipt over the existing authenticated channel; pin both
hashes in the separate publisher plan. No registry upload occurs here.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import selectors
import subprocess
import sys
import tarfile
import time

if not __debug__ or sys.version_info < (3, 11):
    raise RuntimeError('Python >=3.11 without optimization is required')
plan = json.loads(Path(sys.argv[1]).read_text())
root, output = Path(plan['root']), Path(plan['output'])
inputs = json.loads(Path(plan['inputs']).read_text())
toolchain = inputs['remote_packaging_toolchain']
output.mkdir(parents=True, exist_ok=True)
receipt_path = output / (plan['name'] + '-package.json')
if receipt_path.exists():
    raise RuntimeError('Inspect existing packaging evidence first')
initial, started = shutil.disk_usage(output).free, time.monotonic()
assert initial >= plan['entry_bytes']
group = Path('/sys/fs/cgroup') / Path('/proc/self/cgroup').read_text().strip()[3:].lstrip('/')
assert {key: (group / key).read_text().strip() for key in ('memory.max', 'memory.swap.max', 'cpu.max')} == {
    'memory.max': '1073741824', 'memory.swap.max': '0', 'cpu.max': '100000 100000'}
home = output / (plan['name'] + '-cargo-home')
home.mkdir()  # Never reuse unknown configuration, credential providers or cache.
for ancestor in (root, *root.parents):
    for name in ('config', 'config.toml'):
        assert not (ancestor / '.cargo' / name).exists(), 'Ancestor Cargo configuration is not admitted'
env = {key: value for key, value in os.environ.items() if not key.startswith('CARGO_')}
env.update(RUSTUP_TOOLCHAIN=toolchain, CARGO_HOME=str(home),
           CARGO_TARGET_DIR=str(output / 'target'), TMPDIR=str(output),
           CARGO_BUILD_JOBS='1', CARGO_INCREMENTAL='0')
(home / 'config.toml').write_text('[registry]\nglobal-credential-providers = []\n')


def bounded_git(*args):
    child = subprocess.Popen(['git', '-C', str(root), *args], env=env,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    data, deadline = bytearray(), time.monotonic() + 15
    try:
        os.set_blocking(child.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while selector.get_map():
                assert time.monotonic() < deadline, 'Git observation deadline'
                for key, _ in selector.select(.1):
                    part = os.read(key.fileobj.fileno(), 64 * 1024)
                    if not part:
                        selector.unregister(key.fileobj)
                    else:
                        assert len(data) + len(part) <= 1024**2, 'Git observation bound'
                        data.extend(part)
        assert child.wait(timeout=max(.01, deadline - time.monotonic())) == 0
        return bytes(data)
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=2)
        child.stdout.close()


def git(*args):
    return bounded_git(*args).decode().strip()


def guard():
    free = shutil.disk_usage(output).free
    assert free >= plan['floor_bytes'] and initial - free <= plan['growth_bytes']
    assert time.monotonic() - started < plan['seconds']


def clean():
    assert git('rev-parse', 'HEAD') == plan['head']
    assert not git('status', '--porcelain')


def sha(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


receipt = dict(passed=False, head=plan['head'], relative=plan['relative'], toolchain=toolchain,
               producer_sha256=sha(Path(__file__)), cargo_upload=False, compiler_requested=False)
child = None
try:
    clean()
    rustc = subprocess.check_output(['rustc', '--version', '--verbose'], env=env, text=True, timeout=15)
    cargo = subprocess.check_output(['cargo', '--version', '--verbose'], env=env, text=True, timeout=15)
    assert 'release: ' + toolchain in rustc and inputs['qualification_rustc_commit'] in rustc
    assert cargo.startswith('cargo ' + toolchain + ' ')
    receipt.update(rustc=rustc, cargo=cargo)
    command = ['cargo', 'package', '--locked', '--no-verify', '-p', plan['name']]
    receipt['command'] = command
    log = output / (plan['name'] + '-package.log')
    with log.open('xb') as stream:
        child = subprocess.Popen(command, cwd=root, env=env, stdout=stream, stderr=stream)
        while child.poll() is None:
            guard()
            assert log.stat().st_size <= 4 * 1024**2
            time.sleep(.2)
        assert child.returncode == 0, 'Cargo package failed; inspect retained log'
    clean()
    artifact = output / 'target/package' / (plan['name'] + '-' + plan['version'] + '.crate')
    assert artifact.stat().st_size <= 2_200_000
    files = {}
    # The Git tree is the authority even if a worktree has ignored or symlinked
    # files. Blob ids bind every included source byte and executable bit.
    tree_bytes = bounded_git('ls-tree', '-r', '-z', plan['head'])
    tree = {}
    for row in tree_bytes.split(b'\0'):
        if row:
            meta, path = row.split(b'\t', 1)
            mode, kind, oid = meta.decode().split()
            tree[path.decode()] = (mode, kind, oid)
    with tarfile.open(artifact) as archive:
        for member in archive:
            assert member.isfile() and 0 <= member.size <= 512 * 1024
            assert member.name not in files
            data = archive.extractfile(member).read()
            prefix = plan['name'] + '-' + plan['version'] + '/'
            assert member.name.startswith(prefix)
            name = member.name[len(prefix):]
            if name not in ('Cargo.toml', 'Cargo.lock', '.cargo_vcs_info.json'):
                source = str(Path(plan['relative']) / ('Cargo.toml' if name == 'Cargo.toml.orig' else name))
                mode, kind, oid = tree[source]
                assert kind == 'blob' and mode in ('100644', '100755')
                assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == oid
                assert bool(member.mode & 0o111) == (mode == '100755')
            files[member.name] = dict(sha256=hashlib.sha256(data).hexdigest(),
                                      bytes=member.size, mode=member.mode)
    assert len(files) <= 1200 and sum(item['bytes'] for item in files.values()) <= 16 * 1024**2
    guard()
    receipt.update(passed=True, clean_before_and_after=True, all_sources_match_git_blobs=True,
                   fresh_credentialless_cargo_home=True, artifact_sha256=sha(artifact),
                   artifact_bytes=artifact.stat().st_size, files=files)
except BaseException as error:
    receipt['error'] = str(error)
finally:
    if child is not None and child.poll() is None:
        child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
    receipt.update(seconds=time.monotonic() - started, final_free_bytes=shutil.disk_usage(output).free,
                   peak_memory_bytes=int((group / 'memory.peak').read_text()))
    receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({key: receipt.get(key) for key in ('passed', 'error', 'artifact_sha256', 'artifact_bytes', 'seconds')}))
sys.exit(0 if receipt['passed'] else 1)
