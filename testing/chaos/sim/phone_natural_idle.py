"""Observe real unplugged Android idle before opening fresh paid transit channels."""

import hashlib
from pathlib import Path
import re
import time

from .paid_phone_transit import PhoneTransitRun
from .paid_relay import eventually
from .paid_settlement import require
from .phone_idle import foreground_network_policy, idle_state
from .phone_restart import process


def natural_state(battery, deviceidle):
    require(not re.search(r'updates?\s+stopped|mUpdatesStopped\s*=\s*true', battery, re.I),
            'battery state is simulated; preserve its owner and refuse natural idle')
    power = {}
    for name in ('AC', 'USB', 'Wireless', 'Dock'):
        values = re.findall(r'^\s*' + name + r' powered: (true|false)\s*$', battery, re.M)
        require(values == ['false'], 'natural idle requires every external power source disconnected')
        power[name] = False
    state = idle_state(deviceidle)
    require(not state['forced'], 'natural idle cannot use forced Doze')
    for name in ('mCharging', 'mScreenOn'):
        values = re.findall(r'\b' + name + r'=(true|false)\b', deviceidle)
        require(len(values) == 1, 'missing or ambiguous natural idle environment')
        state[name] = values[0] == 'true'
    require(not state['mCharging'], 'Android still considers the phone charging')
    return dict(state, external_power=power, battery_simulated=False)


class NaturalIdleRun(PhoneTransitRun):
    def __init__(self, args):
        require(not any(getattr(args, name, False) for name in (
            'forced_idle', 'screen_off', 'sustained_transit', 'phone_outage',
            'phone_renewal', 'phone_expiry', 'impaired_transit', 'compare_transit_rates')),
            'natural idle requires its own transit workload')
        super().__init__(args)
        self.evidence['harness_sha256']['phone_natural_idle.py'] = hashlib.sha256(
            Path(__file__).read_bytes()).hexdigest()

    def environment(self):
        return natural_state(self.phone.shell('dumpsys', 'battery').decode(),
                             self.phone.shell('dumpsys', 'deviceidle').decode())

    def setup(self):
        # Refuse a charging or simulated phone before starting the mint or issuing funds.
        self.environment()
        super().setup()

    def observe(self, row, *, ready=False):
        self.monitor.check()
        state = self.environment()
        require(not state['mScreenOn'], 'screen woke during natural idle observation')
        require(process(self.phone) == row['before_process'], 'natural idle restarted the routing app')
        observation = dict(at=time.monotonic(), environment=state)
        if ready:
            require(state['deep'] == 'IDLE', 'Android left natural deep idle')
            observation.update(self.screen('screen_off'))
            observation['network_policy'] = foreground_network_policy(
                self.phone.shell('dumpsys', 'netpolicy').decode(), row['uid'])
        return observation

    def wait_idle(self):
        whitelist = self.phone.shell('dumpsys', 'deviceidle', 'whitelist').decode()
        require(not any(self.phone.package in line.split(',') for line in whitelist.splitlines()),
                'natural idle app has a battery-optimization exemption')
        row = dict(before_process=process(self.phone), samples=[], passed=False,
                   natural_idle=True, forced_idle=False, battery_optimization_exempt=False,
                   uid=int(self.phone.shell('run-as', self.phone.package, 'id', '-u')),
                   maximum_wait_seconds=3600)
        require(row['before_process'] is not None, 'routing process is absent before natural idle')
        self.evidence['natural_idle'] = row
        self.background = True
        self.phone.shell('input', 'keyevent', 'KEYCODE_HOME')
        self.phone.shell('input', 'keyevent', 'KEYCODE_SLEEP')
        started = time.monotonic()
        while time.monotonic() - started < row['maximum_wait_seconds']:
            observed = self.observe(row)
            row['samples'].append(observed)
            self.save()
            if observed['environment']['deep'] == 'IDLE':
                row['entered'] = self.observe(row, ready=True)
                row['wait_seconds'] = time.monotonic() - started
                self.save()
                return row
            time.sleep(15)
        raise RuntimeError('natural deep idle not observed within one hour; preserve the failed result')

    def exercise(self):
        eventually('exact four-node phone transit line', self.topology, 90)
        self.check_unpaid()
        row = self.wait_idle()
        # No paid channel ages while waiting for Android's own idle policy.
        self.buy_routes()
        self.observe(row, ready=True)
        self.stream('screen_off', observe=lambda: self.observe(row, ready=True))
        started = row['entered']['at']
        while time.monotonic() - started < 60:
            row['samples'].append(self.observe(row, ready=True))
            self.save()
            time.sleep(5)
        row['after'] = self.observe(row, ready=True)
        row['idle_seconds'] = time.monotonic() - started
        row['passed'] = True
        self.save()
        self.complete_transit()
