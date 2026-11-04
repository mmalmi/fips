#!/usr/bin/env python3
"""Watch one admitted publisher operation inside its existing host lease.

The lease launcher must make this supervisor the process-group leader and own
the outer deadline/group cleanup. This script never acquires or reaps a lease.
"""
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import sys
import time

if not __debug__ or sys.version_info < (3, 11):
    raise RuntimeError('Python >=3.11 without optimization is required')
if os.getpgrp() != os.getpid():
    raise RuntimeError('Run through the existing process-group-owning host lease')
if len(sys.argv) < 4 or sys.argv[2] != '--':
    raise RuntimeError('Expected private guard plan followed by -- and command')
plan = json.loads(Path(sys.argv[1]).read_text())
output = Path(plan['output'])
if not output.is_dir():
    raise RuntimeError('Private output directory must already exist')
floor, margin, growth = 12 * 1024**3, 128 * 1024**2, 16 * 1024**2
initial = shutil.disk_usage(output).free
if initial < floor + margin:
    raise RuntimeError('Admitted real filesystem entry reserve unavailable')
receipt_path = output / (plan['operation'] + '-guard.json')
log_path = output / (plan['operation'] + '-guard.log')
if receipt_path.exists() or log_path.exists():
    raise RuntimeError('Operation already has evidence; reconcile it first')
resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024**2, 8 * 1024**2))
resource.setrlimit(resource.RLIMIT_CPU, (110, 110))
interrupted = None


def handle_signal(number, _frame):
    global interrupted
    interrupted = number


for watched in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(watched, handle_signal)


def group_members():
    # Only numeric process metadata is inspected, never command lines or env.
    probe = subprocess.Popen(['ps', '-axo', 'pid=,pgid=,rss='], stdout=subprocess.PIPE, text=True)
    try:
        rows, _ = probe.communicate(timeout=2)
        if probe.returncode != 0:
            raise RuntimeError('Process enumeration failed')
    finally:
        if probe.poll() is None:
            probe.kill()
        probe.wait(timeout=2)
    result = []
    for row in rows.splitlines():
        pid, group, rss = map(int, row.split())
        if group == os.getpgrp() and pid != probe.pid:
            result.append((pid, rss * 1024))
    return result


started, peak, minimum, error = time.monotonic(), 0, initial, None
known_members = set()
env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', RAYON_NUM_THREADS='1',
           TOKIO_WORKER_THREADS='1', OMP_NUM_THREADS='1', VECLIB_MAXIMUM_THREADS='1')
child = None
try:
    with log_path.open('xb') as log:
        child = subprocess.Popen(sys.argv[3:], env=env, stdout=log, stderr=log)
        while True:
            free = shutil.disk_usage(output).free
            minimum = min(minimum, free)
            members = group_members()
            known_members.update(pid for pid, _ in members if pid != os.getpid())
            memory = sum(rss for _, rss in members)
            peak = max(peak, memory)
            if free < floor or initial - free > growth:
                raise RuntimeError('Filesystem reserve or growth bound')
            if memory > 256 * 1024**2:
                raise RuntimeError('Aggregate resident memory bound')
            if time.monotonic() - started >= 110 or interrupted:
                raise RuntimeError('Independent deadline or interruption')
            if log_path.stat().st_size > 1024**2:
                raise RuntimeError('Log size bound')
            if child.poll() is not None:
                if child.returncode != 0:
                    raise RuntimeError('Publisher child failed; inspect private log')
                break
            time.sleep(.1)
except BaseException as failure:
    error = type(failure).__name__ + ': ' + str(failure)
finally:
    # All child work remains in the outer launcher's process group. Close it
    # before returning; the lease launcher independently checks for stragglers.
    enumeration_failed = False
    if child is not None:
        known_members.add(child.pid)
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            known_members.update(pid for pid, _ in group_members() if pid != os.getpid())
        except BaseException:
            enumeration_failed = True
        for pid in known_members:
            try:
                # A PID remembered from an earlier sample may have exited and
                # been reused. Never signal it without current group ownership.
                if os.getpgid(pid) == os.getpgrp():
                    os.kill(pid, sig)
            except ProcessLookupError:
                pass
            except OSError:
                enumeration_failed = True
        if child is not None:
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                enumeration_failed = True
    try:
        remaining = [pid for pid, _ in group_members() if pid != os.getpid()]
    except BaseException:
        remaining = None
        enumeration_failed = True
    receipt = dict(passed=error is None and not enumeration_failed and remaining == [], error=error,
                   child_exit=None if child is None else child.returncode,
                   seconds=time.monotonic() - started, peak_sampled_rss_bytes=peak,
                   minimum_free_bytes=minimum, initial_free_bytes=initial,
                   final_free_bytes=shutil.disk_usage(output).free,
                   remaining_group_processes=remaining, sample_interval_seconds=.1,
                   process_enumeration_failed=enumeration_failed,
                   cpu_scope='one sequential worker; 110-second per-process CPU limit')
    receipt_path.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps(receipt))
sys.exit(0 if receipt['passed'] else 1)
