#!/usr/bin/env python3
"""Exercise failed process enumeration with a real live publisher substitute.

Uses no credentials or network and retains its bounded receipts. Run on an
admitted host with at least 20 GiB real filesystem headroom.
"""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys

output = Path(sys.argv[1])
output.mkdir(mode=0o700)
assert shutil.disk_usage(output).free >= 20 * 1024**3
guard = Path(__file__).with_name('guard-small-publish.py')
results = []
cases = [('broken', 'print("malformed")'), ('stuck', 'import time; time.sleep(30)'),
         ('stale', '''import os,pathlib
p=pathlib.Path(os.environ['PS_COUNT'])
first=not p.exists();p.touch()
print(os.environ['OUTSIDE_PID']+' '+str(os.getpgrp())+' 0' if first else 'malformed')''')]
for case, code in cases:
    if len(sys.argv) > 2 and case != sys.argv[2]:
        continue
    work = output / case
    work.mkdir()
    binary = work / 'bin'
    binary.mkdir()
    fake = binary / 'ps'
    fake.write_text('#!' + sys.executable + '\n' + code + '\n')
    fake.chmod(0o700)
    plan = work / 'plan.json'
    plan.write_text(json.dumps(dict(output=str(work), operation=case)))
    env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ['PATH'])
    outsider = None
    if case == 'stale':
        outsider = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)
        env.update(OUTSIDE_PID=str(outsider.pid), PS_COUNT=str(work / 'ps-count'))
    with (work / 'outer.log').open('xb') as log:
        child = subprocess.Popen([sys.executable, '-B', str(guard), str(plan), '--',
                                  sys.executable, '-c', 'import time; time.sleep(60)'],
                                 env=env, stdout=log, stderr=log, start_new_session=True)
        try:
            status = child.wait(timeout=25)
        finally:
            # Equivalent ultimate group ownership to the existing host lease.
            # Cleanup executes even if the tested supervisor fails outright.
            try:
                os.killpg(child.pid, 0)
                survived = True
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                survived = False
            child.wait(timeout=3)
    outside_preserved = None
    if outsider is not None:
        outside_preserved = outsider.poll() is None
        outsider.terminate()
        outsider.wait(timeout=3)
        assert outside_preserved, 'Supervisor signalled an unowned cached PID'
    receipt = json.loads((work / (case + '-guard.json')).read_text())
    assert status != 0 and receipt['passed'] is False
    assert receipt['process_enumeration_failed'] is True
    assert receipt['child_exit'] is not None and not survived
    results.append(dict(case=case, passed=True, no_survivor=True,
                        unowned_cached_pid_preserved=outside_preserved,
                        refused_success_receipt=True, seconds=receipt['seconds']))
(output / 'result.json').write_text(json.dumps(results, indent=2) + '\n')
print(json.dumps(results))
