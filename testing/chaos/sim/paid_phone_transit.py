"""Paid phone transit on the existing LAN, including background/screen-off delivery.

Reuses the guarded router profiles, mint and four-account collection. This tests
FIPS hops over UDP, not phone 802.11s participation or customer-network isolation.
Screen-off samples use ADB and USB power; they are not a battery-life benchmark.
"""

from concurrent.futures import ThreadPoolExecutor
import hashlib
from pathlib import Path
import re
import secrets
import time
from urllib.parse import urlsplit

from .paid_finances import financial_snapshot, payments_credited
from .paid_phone import PaidPhoneRun
from .paid_phone_checks import guest_source
from .paid_relay import eventually, relay_config
from .paid_settlement import require
from .phone_customer import ACTIVITY, save
from .phone_diagnostics import control, native, resources
from .wifi_profiles import configure_stopped


def validate_stream(report, shape):
    require(report['shape'] == shape and report['ready'] and report['connected']
            and report['finished'] and report['stopped_reason'] is None
            and report['completed_us'] is not None
            and 0 <= report['completed_us'] <= report['elapsed_us']
            <= (shape['duration_secs'] + 5) * 1_000_000,
            'stream shape or completion differs')
    require(all(report[key] == shape['bytes'] for key in
                ('accepted_bytes', 'received_bytes', 'acknowledged_bytes')),
            'stream did not deliver and acknowledge every byte')
    identifier = bytes.fromhex(shape['stream_id'])
    block = bytes((pos % 251) ^ identifier[pos % 16] for pos in range(251 * 16))
    complete, tail = divmod(shape['bytes'], len(block))
    expected = hashlib.sha256(block * complete + block[:tail]).hexdigest()
    require(report['received_sha256'] == expected, 'stream payload digest differs')


class PhoneTransitRun(PaidPhoneRun):
    def __init__(self, args):
        require(args.transit and not args.open_mesh, 'LAN transit cannot change radio profiles')
        super().__init__(args)
        require(self.customer['interface'] == self.nodes['n01'].management,
                'transit must use the existing management LAN')
        self.addresses = self.scenario['router_addresses']
        self.evidence.update(radio_mode='existing_lan_udp', customer_isolation_tested=False,
                             physical_phone_transit=True,
                             screen_off_requested=bool(getattr(args, 'screen_off', False)), windows=[])
        self.evidence['harness_sha256']['paid_phone_transit.py'] = hashlib.sha256(
            Path(__file__).read_bytes()).hexdigest()
        self.background = False

    def endpoint(self, name):
        return f"{self.addresses[name]}:{self.customer['entry_port']}"

    def profile_config(self, node):
        name = next(name for name, candidate in self.nodes.items() if candidate is node)
        config = relay_config([], self.mint_url)
        config['state_directory'] = node.state
        config['transports'] = {'udp': {'bind_addr': self.endpoint(name),
                                         'advertise_on_nostr': False}}
        # Match the phone's low tariff so the finite stream fits one original
        # channel per account. All other financial authority stays unchanged.
        config['terms'].update(fee_msat_per_kib=1, quote_max_units=128 * 1024 * 1024)
        config['return_allowance'] = False
        return config

    def configure_access(self):
        self.evidence['customer_access'] = {'mode': 'existing_lan', 'network_changes': False}

    def check_customer_access(self):
        source, _ = guest_source(self.phone, self.customer)
        mint = urlsplit(self.mint_url)
        self.phone.shell('toybox', 'nc', '-4', '-n', '-z', '-s', source, '-w', '3',
                         mint.hostname, str(mint.port))
        self.phase('phone can reach the isolated mint on its unchanged Wi-Fi')

    def customer_profile(self):
        return {**super().customer_profile(), 'neighbor_admission': 'authenticated_adjacent'}

    def expected_edges(self):
        return [('n01', 'phone'), ('phone', 'n02'), ('n03', 'n02'), ('n02', 'phone')]

    def launch_profiles(self):
        self.before_launch()
        first = self.nodes['n01']
        first.start()
        eventually('entry listener', lambda: self.ctl('n01', 'status'), 60)
        require(self.ui('start')['customer']['running'], 'phone did not start')
        adapters = native(self.phone, 'show_transports')['data']['transports']
        require(len(adapters) == 1 and adapters[0]['type'] == 'udp',
                'phone has an unexpected transport')
        port = int(adapters[0]['local_addr'].rsplit(':', 1)[1])
        require(0 < port <= 65535, 'phone UDP listener has no bound port')
        source, _ = guest_source(self.phone, self.customer)
        self.evidence['phone_udp_address'] = f'{source}:{port}'
        neighbors = [
            {'npub': self.evidence['phone_npub'],
             'addresses': [{'transport': 'udp', 'addr': f'{source}:{port}'}]},
            {'npub': self.nodes['n03'].npub,
             'addresses': [{'transport': 'udp', 'addr': self.endpoint('n03')}]},
        ]
        configure_stopped(self.nodes['n02'], neighbors=neighbors)
        for name in ('n02', 'n03'):
            self.nodes[name].start()
            eventually('transit relay listener', lambda name=name: self.ctl(name, 'status'), 60)

    def topology(self):
        identities = {name: node.npub for name, node in self.nodes.items()}
        identities['phone'] = self.evidence['phone_npub']
        line = ('n01', 'phone', 'n02', 'n03')
        states = {name: self.accounts.ctl(name, 'status') for name in line}
        self.evidence['last_peer_observation'] = {n: s['peers'] for n, s in states.items()}
        self.save()
        for index, name in enumerate(line):
            wanted = {identities[other] for i, other in enumerate(line) if abs(i - index) == 1}
            peers = states[name]['peers']
            if ({peer['npub'] for peer in peers} != wanted
                    or any(not peer['connected'] or peer['transport'] != 'udp' for peer in peers)):
                return None
        return states

    def finances(self):
        return financial_snapshot(self.accounts, wallet=None)

    def screen(self, mode):
        power = self.phone.shell('dumpsys', 'power').decode()
        activity = self.phone.shell('dumpsys', 'activity', 'activities').decode()
        service = self.phone.shell('dumpsys', 'activity', 'services', self.phone.package).decode()
        awake = re.search(r'^\s*mWakefulness=(\w+)', power, re.MULTILINE)
        require(awake is not None, 'phone wakefulness unavailable')
        require(awake[1] in (('Asleep', 'Dozing') if mode == 'screen_off' else ('Awake',)),
                'phone screen state changed during transfer')
        components = re.findall(r'(?:topResumedActivity|mResumedActivity)[^\n]*?\bu\d+\s+(\S+/\S+)', activity)
        ours = self.phone.package + '/' + ACTIVITY
        require((mode == 'foreground' and components and all(x == ours for x in components))
                or (mode != 'foreground' and ours not in components),
                'phone foreground state changed during transfer')
        require('isForeground=true' in service and 'RoutingService' in service,
                'routing foreground service is absent')
        return {'wakefulness': awake[1], 'activities': components, 'foreground_service': True}

    def stream(self, mode, *, unpaid=False):
        identifier = secrets.token_hex(16)
        count, duration = (1024, 4) if unpaid else (512 * 1024, 30)
        shapes = {name: {'peer': self.nodes[other].npub, 'stream_id': identifier,
                         'bytes': count, 'bytes_per_second': 32 * 1024,
                         'duration_secs': duration, 'connect': name == 'n01'}
                  for name, other in (('n01', 'n03'), ('n03', 'n01'))}
        row = {'mode': mode, 'unpaid': unpaid, 'shapes': shapes, 'samples': [],
               'before': resources(self.phone), 'battery_before':
                   self.phone.shell('dumpsys', 'battery').decode()}
        self.evidence['windows'].append(row)
        self.save()
        def run(name):
            return self.once(('unpaid-' if unpaid else '') + mode + '-stream-' + name,
                             lambda: self.ctl(name, 'stream_probe', probe=shapes[name],
                                              operation_timeout=duration + 20))
        with ThreadPoolExecutor(max_workers=2) as pool:
            jobs = {name: pool.submit(run, name) for name in shapes}
            while not all(job.done() for job in jobs.values()):
                self.monitor.check()
                require(self.topology() is not None, 'transit topology changed during transfer')
                row['samples'].append({'at': time.monotonic(), 'line_verified': True, **self.screen(mode)})
                self.save()
                time.sleep(3)
            row['results'] = {name: job.result()['probe'] for name, job in jobs.items()}
        row['after'] = resources(self.phone)
        require(row['before']['process'] == row['after']['process'], 'phone process changed')
        row['cpu_seconds'] = (row['after']['cpu_ticks'] - row['before']['cpu_ticks']) / row['before']['ticks_per_second']
        self.save()
        if unpaid:
            require(all(result['received_bytes'] == result['acknowledged_bytes'] == 0
                        for result in row['results'].values()), 'unpaid payload was delivered')
        else:
            for name, result in row['results'].items():
                validate_stream(result, shapes[name])
            row['cpu_seconds_per_delivered_mib'] = row['cpu_seconds'] / (2 * count / 1024 ** 2)
        row['passed'] = True
        self.phase('unpaid denial verified' if unpaid else mode + ' paid duplex delivered')

    def restore_foreground(self):
        if self.background:
            self.phone.shell('input', 'keyevent', 'KEYCODE_WAKEUP')
            self.phone.shell('wm', 'dismiss-keyguard')
            def unlocked():
                self.phone.check(foreground=False)
                return True
            self.phase('waiting for unlocked phone to restore the app and settle')
            eventually('operator unlock after background test', unlocked, 90)
            self.phone.launch()
            self.background = False

    def exercise(self):
        eventually('exact four-node phone transit line', self.topology, 90)
        self.stream('foreground', unpaid=True)
        require(all(not self.accounts.ctl(name, 'status')['purchases'] for name in self.accounts.nodes),
                'unpaid check created a purchase')
        for name, other in (('n01', 'n03'), ('n03', 'n01')):
            self.once('buy-' + name, lambda name=name, other=other:
                      self.ctl(name, 'buy', destination=self.nodes[other].npub))
        self.stream('foreground')
        self.background = True
        self.phone.shell('input', 'keyevent', 'KEYCODE_HOME')
        self.stream('background')
        if self.evidence['screen_off_requested']:
            self.phone.shell('input', 'keyevent', 'KEYCODE_SLEEP')
            eventually('phone screen off or ambient display', lambda: self.screen('screen_off'), 10)
            self.stream('screen_off')
        self.restore_foreground()
        eventually('unchanged paid transit line', self.topology, 30)
        def paid():
            state = self.finances()
            return state if payments_credited(state) and all(x['authorized'] > 0 for x in state.values()) else None
        final = eventually('provider credit on every paying direction', paid, 45)
        require(len(final['phone']['credited']) == 2 and len(final['phone']['signed']) == 1,
                'phone did not both sell and buy onward forwarding')
        require(control(self.phone, 'status')['received']['packets'] == 0,
                'phone was an application endpoint instead of transit')
        save(self.root / 'paid-finances.json', final)
        self.journals('paid')
        self.settle()

    def finish(self):
        try:
            self.restore_foreground()
        finally:
            super().finish()
