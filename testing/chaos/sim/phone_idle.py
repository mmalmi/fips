"""Paid foreground-service continuity through one owned Android Doze window."""

from pathlib import Path
import hashlib
import re
import secrets
import time

from .paid_relay import eventually
from .paid_settlement import require
from .phone_customer import save
from .phone_restart import process
from .stream_probe import duplex, validate_stream


def idle_state(text):
    fields = {}
    for name, pattern in (('forced', r'\bmForceIdle=(true|false)\b'),
                          ('deep', r'\bmState=([A-Z_]+)\b'),
                          ('light', r'\bmLightState=([A-Z_]+)\b')):
        values = re.findall(pattern, text)
        require(len(values) == 1, 'missing or ambiguous Android idle state')
        fields[name] = values[0]
    fields['forced'] = fields['forced'] == 'true'
    return fields


def foreground_network_policy(text, uid):
    """Doze can allow a foreground service without a battery exemption."""
    require(re.findall(r'^Device idle: (true|false)$', text, re.MULTILINE) == ['true'],
            'network policy is not in device idle')
    rows = re.findall(r'^\s*UID=' + re.escape(str(uid))
                      + r' state=\{procState=FGS\s*,[^}]*\} blocked_state=\{'
                      r'blocked=([^,]+),allowed=([^,]+),effective=([^}]+)\}',
                      text, re.MULTILINE)
    require(len(rows) == 1, 'missing or ambiguous foreground-service network policy')
    blocked, allowed, effective = rows[0]
    require('DOZE' in blocked.split('|') and 'FOREGROUND' in allowed.split('|')
            and effective == 'NONE', 'Doze did not allow foreground-service networking')
    return {'blocked': blocked, 'allowed': allowed, 'effective': effective}


def guard_script(directory, token, seconds=90):
    return f'''#!/system/bin/sh
set -eu
for tick in $(seq 1 {seconds}); do
  test ! -f {directory}/restore || break
  sleep 1
done
test "$(cat {directory}/owner)" = {token}
dumpsys deviceidle unforce >{directory}/restore.log
echo restored >{directory}/done
'''


class IdleGuard:
    def __init__(self, phone):
        self.phone = phone
        self.directory = '/data/local/tmp/fips-relay-idle-test'
        self.token = secrets.token_hex(16)
        self.attempted = False

    def state(self):
        return idle_state(self.phone.shell('dumpsys', 'deviceidle').decode())

    def start(self):
        before = self.state()
        require(not before['forced'] and before['deep'] == before['light'] == 'ACTIVE',
                'phone is already under another idle policy')
        require(self.phone.package.startswith('org.fips.relaybench.acceptance.'),
                'idle acceptance requires a temporary app')
        whitelist = self.phone.shell('dumpsys', 'deviceidle', 'whitelist').decode()
        require(not any(self.phone.package in line.split(',') for line in whitelist.splitlines()),
                'phone test app is exempt from idle restrictions')
        self.before = before
        save(self.phone.root / 'idle-intent.json', {'before': before, 'owner': self.token,
             'directory': self.directory, 'watchdog_seconds': 90,
             'battery_optimization_exempt': False})
        self.attempted = True
        d = self.directory
        # The shell UID can restore DeviceIdle independently of the test app and
        # controller. Battery simulation and exemption lists are never changed.
        script = f'''set -eu
umask 077
mkdir {d}
printf %s {self.token} >{d}/owner
cat >{d}/guard.sh <<'GUARD'
{guard_script(d, self.token)}
GUARD
nohup sh {d}/guard.sh </dev/null >{d}/guard.log 2>&1 &
echo $! >{d}/pid
'''
        self.phone.adb('shell', 'sh', data=script.encode())
        self.phone.shell('sh', '-c', f'set -eu; test "$(cat {d}/owner)" = {self.token}; '
                         f'test -d /proc/$(cat {d}/pid); dumpsys deviceidle force-idle deep')
        return eventually('Android forced deep idle', self.check, 10)

    def check(self):
        state = self.state()
        require(state['forced'] and state['deep'] == 'IDLE', 'Android left forced idle')
        return state

    def restore(self):
        if not self.attempted:
            return None
        d = self.directory
        self.phone.shell('sh', '-c', f'set -eu; test "$(cat {d}/owner)" = {self.token}; touch {d}/restore')

        def restored():
            state = self.state()
            done = self.phone.shell('sh', '-c', f'test ! -f {d}/done || cat {d}/done').strip()
            active = self.phone.shell('sh', '-c', f'cat /proc/$(cat {d}/pid)/cmdline 2>/dev/null || true')
            return state if done == b'restored' and not active and state == self.before else None

        after = eventually('original Android idle policy restored', restored, 15)
        self.phone.shell('sh', '-c', f'set -eu; test "$(cat {d}/owner)" = {self.token}; '
                         f'test -z "$(cat /proc/$(cat {d}/pid)/cmdline 2>/dev/null)"; rm -r {d}')
        self.attempted = False
        save(self.phone.root / 'idle-restored.json', after)
        return after


def exercise(run):
    """Require fresh paid delivery during forced idle and retain the same process."""
    guard = IdleGuard(run.phone)
    row = {'before_process': process(run.phone), 'samples': [], 'passed': False,
           'natural_idle': False, 'battery_simulated': False,
           'battery_optimization_exempt': False, 'network_interrupted': False}
    require(row['before_process'] is not None, 'phone transit process is absent')
    run.evidence['forced_idle'] = row
    run.evidence['harness_sha256']['phone_idle.py'] = hashlib.sha256(
        Path(__file__).read_bytes()).hexdigest()
    run.save()
    try:
        row['entered'] = guard.start()
        started = time.monotonic()
        uid = int(run.phone.shell('run-as', run.phone.package, 'id', '-u'))

        def observe():
            require(process(run.phone) == row['before_process'], 'idle restarted the phone app')
            policy = foreground_network_policy(
                run.phone.shell('dumpsys', 'netpolicy').decode(), uid)
            return {**guard.check(), **run.screen('background'), 'network_policy': policy}

        duplex(run, row, label='forced-idle', count=512 * 1024, duration=30,
               rate=32 * 1024, observe=observe)
        for name, report in row['results'].items():
            validate_stream(report, row['shapes'][name])
        while time.monotonic() - started < 45:
            run.monitor.check()
            row['samples'].append({'at': time.monotonic(), **observe()})
            run.save()
            time.sleep(3)
        row['idle_seconds'] = time.monotonic() - started
        row['after_process'] = process(run.phone)
        require(row['after_process'] == row['before_process'], 'idle changed the phone process')
        row['passed'] = True
    finally:
        row['restored'] = guard.restore()
        run.save()
