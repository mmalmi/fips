#!/usr/bin/env python3
"""Check the actual packed-source fsck gate using a tiny, local Git repository.

No source preparation, clone, helper, signing, network or publishing is run.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

if not __debug__ or sys.version_info < (3, 11):
    raise RuntimeError('Python >=3.11 without optimization is required')

script = Path(__file__).with_name('packed-source.py')
parsed = ast.parse(script.read_text(), filename=str(script))
names = {'digest', 'guard', 'run', 'git', 'strict_fsck'}
functions = [node for node in parsed.body if isinstance(node, ast.FunctionDef) and node.name in names]
assert {node.name for node in functions} == names
# Load only the real gate functions, never the CLI's preparation side effects.
code = compile(ast.Module(body=functions, type_ignores=[]), str(script), 'exec')
sites = [node.args[1].value for node in ast.walk(parsed)
         if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
         and node.func.id == 'strict_fsck']
assert sorted(sites) == ['cold-fsck', 'ordinary-reader-fsck', 'signed-fsck']

base = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(tempfile.gettempdir())
floor, allowance = 40 * 1024**3 + 128 * 1024**2, 64 * 1024**2
initial = shutil.disk_usage(base).free
assert initial >= floor + allowance, 'insufficient headroom for the 64 MiB fixture allowance'
with tempfile.TemporaryDirectory(prefix='packed-source-fsck-', dir=base) as directory:
    work = Path(directory)
    output = work / 'logs'
    output.mkdir()
    ns = dict(Path=Path, hashlib=hashlib, shutil=shutil, subprocess=subprocess, time=time,
              OUT=output, MODE='fixture', INITIAL=initial, START=time.monotonic(),
              PLAN={'floor_bytes': floor, 'growth_bytes': allowance, 'seconds': 30},
              INTERRUPTED=False, STEPS=[], FSCK_CHECKS=[], CHILDREN=[])
    exec(code, ns)
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_NO_REPLACE_OBJECTS='1', GIT_NO_LAZY_FETCH='1', GIT_TERMINAL_PROMPT='0')
    for key in ('GIT_CONFIG_COUNT', 'GIT_CONFIG_PARAMETERS', 'GIT_DIR', 'GIT_WORK_TREE',
                'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES',
                'GIT_SHALLOW_FILE', 'GIT_GRAFT_FILE', 'GIT_NAMESPACE'):
        env.pop(key, None)
    run, git = ns['run'], ns['git']
    repo = work / 'fixture.git'
    try:
        run('init', ['git', 'init', '--bare', '--template=', '--object-format=sha1', str(repo)], env, 10)
        tree = run('tree', git(repo, 'mktree'), env, 10, input_text='').strip()
        commit = run('commit', git(repo, 'hash-object', '-t', 'commit', '-w', '--stdin'), env, 10,
                     input_text=f'tree {tree}\nauthor Fixture <fixture@example.invalid> 1 +0000\n'
                                'committer Fixture <fixture@example.invalid> 1 +0000\n\nfixture\n').strip()
        run('ref', git(repo, 'update-ref', 'refs/heads/main', commit), env, 10)
        run('head', git(repo, 'symbolic-ref', 'HEAD', 'refs/heads/main'), env, 10)
        ns['strict_fsck'](repo, 'valid-fsck', env)
        valid = ns['FSCK_CHECKS'][-1]
        assert valid['passed'] and valid['exit'] == 0
        assert valid['arguments'] == ['fsck', '--full', '--strict']

        before = run('closure-before', git(repo, 'rev-list', '--objects', '--missing=error', '--all'), env, 10)
        # Reachability alone cannot detect this malformed, unreachable object.
        run('malformed-tree', git(repo, 'hash-object', '--literally', '-t', 'tree', '-w', '--stdin'),
            env, 10, input_text='invalid tree')
        after = run('closure-after', git(repo, 'rev-list', '--objects', '--missing=error', '--all'), env, 10)
        assert before == after
        try:
            ns['strict_fsck'](repo, 'invalid-fsck', env)
        except AssertionError as error:
            assert 'invalid-fsck failed' in str(error)
        else:
            raise AssertionError('strict fsck accepted the malformed object')
        invalid = ns['FSCK_CHECKS'][-1]
        assert not invalid['passed'] and invalid['exit'] != 0
        assert len(ns['FSCK_CHECKS']) == 2
        for check in ns['FSCK_CHECKS']:
            for stream in ('stdout', 'stderr'):
                assert ns['digest'](output / check[stream]) == check[stream + '_sha256']
        ns['guard']()
        assert sum(path.stat().st_size for path in work.rglob('*') if path.is_file()) < allowance
        print(json.dumps({'passed': True, 'gate_sites': sites,
                          'unchanged_reachable_closure': True, 'checks': ns['FSCK_CHECKS']}))
        print((output / invalid['stderr']).read_text()[:2048])
    finally:
        for child in ns['CHILDREN']:
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=2)
