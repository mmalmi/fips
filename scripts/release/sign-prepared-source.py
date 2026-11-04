#!/usr/bin/env python3
"""Sign an independently verified immutable root on the existing publisher.

No Git clone, package creation or object upload is performed here. Run only
through the reviewed small-operation guard and the existing atomic host lease.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time

if not __debug__ or sys.version_info < (3, 11):
    raise RuntimeError('Python >=3.11 without optimization is required')
def bounded_read(path, limit):
    with Path(path).open('rb') as source:
        value = source.read(limit + 1)
    if len(value) > limit:
        raise RuntimeError('Input exceeds admitted bound')
    return value


plan = json.loads(bounded_read(sys.argv[1], 64 * 1024))
out = Path(plan['output']) / 'sign-source.json'
if out.exists():
    raise RuntimeError('Reconcile existing signing evidence first')
proof_path = Path(plan['source_preparation'])
proof_bytes = bounded_read(proof_path, 1024**2)
assert hashlib.sha256(proof_bytes).hexdigest() == plan['source_preparation_sha256']
proof = json.loads(proof_bytes)
assert proof['passed'] and proof['actual_ordinary_reader_verified'] and proof['private_fixture_only']
assert proof['head'] == plan['head'] and proof['source_url'] == plan['source_url']
assert proof['mutable_ref_published'] is False
helper = Path(plan['helper'])
inputs = json.loads(bounded_read(plan['inputs'], 64 * 1024))
with helper.open('rb') as source:
    assert hashlib.file_digest(source, 'sha256').hexdigest() == inputs['git_remote_htree']['htree_sha256']
owner, repository = plan['source_url'].removeprefix('htree://').split('/')
assert re.fullmatch(r'npub1[a-z0-9]+', owner)
env = dict(os.environ, HTREE_PREFER_LOCAL_DAEMON='false', HTREE_LOCAL_DAEMON_ONLY='false',
           TOKIO_WORKER_THREADS='1', RAYON_NUM_THREADS='1')
receipt = dict(passed=False, signing_attempted=False, head=plan['head'],
               source_url=plan['source_url'], immutable_source=proof['immutable_source'])


def run(*args):
    child = subprocess.Popen([str(helper), *args], env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    stdout, stderr, counts, deadline = bytearray(), bytearray(), {}, time.monotonic() + 25
    try:
        with selectors.DefaultSelector() as selector:
            for stream in (child.stdout, child.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
                counts[stream] = 0
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise RuntimeError('Source helper deadline')
                for key, _ in selector.select(.1):
                    value = os.read(key.fileobj.fileno(), 64 * 1024)
                    if not value:
                        selector.unregister(key.fileobj)
                        continue
                    counts[key.fileobj] += len(value)
                    if counts[key.fileobj] > 1024**2:
                        raise RuntimeError('Source helper output bound')
                    if key.fileobj is child.stdout:
                        stdout.extend(value)
                    else:
                        stderr.extend(value)
            if child.wait(timeout=max(.01, deadline - time.monotonic())) != 0:
                raise RuntimeError('Source helper failed')
        # Neither identity output nor helper errors are persisted or printed.
        return stdout.decode() + '\n' + stderr.decode()
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=2)
        child.stdout.close()
        child.stderr.close()


try:
    identity = run('user')
    # The helper lists the active signing identity first, then other keys and
    # aliases. Compare that exact first identity without exposing the list.
    assert re.search(r'npub1[a-z0-9]+', identity).group(0) == owner
    del identity
    head_path = Path(plan['output']) / 'before-sign-HEAD'
    assert not head_path.exists()
    before = run('get', plan['source_url'] + '/.git/HEAD', '--output', str(head_path))
    current = re.search(r'Resolved to: ([0-9a-f]{64})', before).group(1)
    assert current == proof['original_public_root_hash'], 'Public source changed since preparation'
    receipt['signing_attempted'] = True
    out.write_text(json.dumps(receipt, indent=2) + '\n')
    result = run('publish', repository, proof['root_hash'], '--key', proof['public_chk_key'])
    assert 'Published: ' + owner + '/' + repository in result
    receipt['passed'] = True
except BaseException as error:
    receipt['error'] = type(error).__name__
finally:
    out.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({key: receipt.get(key) for key in ('passed', 'signing_attempted', 'error')}))
sys.exit(0 if receipt['passed'] else 1)
