"""Five minutes of bidirectional paid phone traffic, including finite frame loss.

Uses the unchanged app-private service diagnostics and the existing guarded
four-account phone fixture. Each original is submitted once. Healthy windows
must deliver completely; impaired delivery is measured without replay.
"""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import time
from types import SimpleNamespace

from . import phone_diagnostics, wifi_probes as probes
from .paid_finances import FinancialObservationChanged, payments_credited
from .paid_phone import PaidPhoneRun
from .paid_phone_finances import validate_reopened
from .paid_relay import eventually
from .paid_settlement import require
from .wifi_frame_loss import EVERY, FrameLoss
from .wifi_priority_checks import received, submitted
from .wifi_remote import digest


ENDPOINTS = ('phone', 'n03')
EDGES = [('phone', 'n01'), ('n01', 'n02'), ('n03', 'n02'), ('n02', 'n01')]
PACKETS, RATE, SECONDS, BYTES = 4000, 40, 100, 1000


def destination(source):
    return 'n03' if source == 'phone' else 'phone'


def validate_window(row, identities):
    require(set(row['streams']) == set(ENDPOINTS) and len(row['samples']) >= 2,
            'phone load lacks both streams or live observations')
    for source, stream in row['streams'].items():
        shape = stream['shape']
        require(shape['packet_count'] == PACKETS and shape['payload_bytes'] == BYTES,
                'phone workload changed')
        submitted(stream['sender'], shape)
        count = received(stream['receiver'], shape, identities[source], complete=not row['impaired'])
        require(stream['sender']['elapsed_us'] >= (PACKETS - 1) * 1_000_000 // RATE,
                'phone stream finished before its paced window')
        if row['impaired']:
            require(0 < count < PACKETS, 'impaired phone stream did not measure partial delivery')
        live = [sample for sample in row['samples'] if sample['ended_at']
                < stream['started_at'] + (PACKETS - 1) / RATE]
        require(len(live) >= 2, 'phone stream lacks observations while sending')
        require(live[-1]['receivers'][source]['unique_packets']
                > live[0]['receivers'][source]['unique_packets'], 'phone delivery stalled')
    live = [sample for sample in row['samples'] if sample['ended_at'] < min(
        stream['started_at'] for stream in row['streams'].values()) + (PACKETS - 1) / RATE]
    require(len(live) >= 2, 'no overlapping live payment observations')
    first, last = live[0]['financial'], live[-1]['financial']
    require(all(last[name]['authorized'] > first[name]['authorized'] for name in first),
            'automatic payment did not advance at every paying hop during the window')
    credits = [{key: value for account in sample['financial'].values()
                for key, value in account['credited'].items()} for sample in (live[0], live[-1])]
    require(all(credits[1].get(key, 0) > credits[0].get(key, 0)
                for account in first.values() for key in account['signed']),
            'provider credit did not advance at every paying hop while sending')
    for endpoint in ('before', 'after'):
        require(row[endpoint]['process'] == row['before']['process'], 'phone process restarted')
    require(row['after']['cpu_ticks'] >= row['before']['cpu_ticks']
            and row['after']['ticks_per_second'] == row['before']['ticks_per_second'],
            'phone CPU observation regressed')
    if row['impaired']:
        require(set(row['loss_after']) == {'n01', 'n03'}
                and all(value['enabled'] and value['dropped_packets'] > 0
                        for value in row['loss_after'].values()), 'loss injection was not observed')


class PhoneLoadRun(PaidPhoneRun):
    def __init__(self, args):
        require(not getattr(args, 'phone_restart', False), 'load and restart are separate scenarios')
        super().__init__(args)
        self.evidence['phone_load'] = {'passed': False, 'windows': [],
            'packets_per_direction_per_window': PACKETS, 'packets_per_second': RATE,
            'seconds_per_window': SECONDS, 'payload_bytes': BYTES, 'frame_loss_every': EVERY,
            'physical_power_loss': False, 'maximum_throughput': False}
        for name in ('paid_phone_load.py', 'phone_diagnostics.py', 'wifi_probes.py', 'wifi_frame_loss.py'):
            self.evidence['harness_sha256'][name] = digest(Path(__file__).with_name(name).read_bytes())

    def participants(self):
        nodes = super().participants()
        if 'phone_npub' not in self.evidence:
            return nodes
        return {**nodes, 'phone': SimpleNamespace(npub=self.evidence['phone_npub'])}

    def ctl(self, node, kind, **fields):
        if node == 'phone':
            return phone_diagnostics.control(self.phone, kind, **fields)
        return super().ctl(node, kind, **fields)

    def profile_config(self, node):
        config = super().profile_config(node)
        # Keep the fixture's original channels/budgets; price permits five
        # minutes of continuous traffic without exhausting a 32-sat channel.
        config['terms'].update(fee_msat_per_kib=1, quote_max_units=32 * 1024 * 1024)
        return config

    def transfer(self, label, count, initial):
        baseline = self.journals('before-load')
        filters = {name: FrameLoss(self.nodes[name], self.nodes['n02'].mac)
                   for name in ('n01', 'n03')}
        identities = {name: node.npub for name, node in self.participants().items()}
        for name in ('healthy', 'impaired', 'recovered'):
            row = {'name': name, 'impaired': name == 'impaired', 'streams': {},
                   'samples': [], 'sample_errors': []}
            self.evidence['phone_load']['windows'].append(row)
            try:
                if row['impaired']:
                    row['loss_before'] = {name: fault.enable() for name, fault in filters.items()}
                self.window(row)
                if row['impaired']:
                    row['loss_after'] = {name: fault.observe() for name, fault in filters.items()}
                validate_window(row, identities)
            finally:
                row['loss_cleared'] = {name: fault.clear() for name, fault in filters.items()}
                self.save()
            validate_reopened(self.journals('after-' + name), baseline, self.mint_url, EDGES)
            self.phase('paid phone load window complete', window=name)
        final = eventually('all phone load payments credited',
                           lambda: self.credited(initial), 60)
        self.evidence['phone_load']['passed'] = True
        self.save()
        return final

    def credited(self, initial):
        current = self.finances()
        return current if payments_credited(current) and all(
            current[name]['authorized'] > initial[name]['authorized'] for name in current) else None

    def window(self, row):
        row['before'] = phone_diagnostics.resources(self.phone)
        for source in ENDPOINTS:
            row['streams'][source] = {'shape': probes.arm(
                self, source, destination(source), PACKETS, BYTES, lifetime_secs=160)}
        self.save()

        def send(source):
            started = time.monotonic()
            sent = probes.send(self, source, destination(source), row['streams'][source]['shape'], RATE,
                               max_duration_secs=SECONDS, operation_timeout=130)
            return {'sender': sent, 'started_at': started, 'finished_at': time.monotonic()}

        failure, last_observed = None, time.monotonic()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {source: pool.submit(send, source) for source in ENDPOINTS}
            try:
                while not all(future.done() for future in futures.values()):
                    self.monitor.check()
                    started = time.monotonic()
                    try:
                        financial = self.finances()
                        receivers = {source: probes.receive(self, source, destination(source),
                            row['streams'][source]['shape']) for source in ENDPOINTS}
                        last_observed = time.monotonic()
                        row['samples'].append({'started_at': started, 'ended_at': last_observed,
                                               'financial': financial, 'receivers': receivers})
                    except FinancialObservationChanged as error:
                        row['sample_errors'].append({'at': started, 'reason': str(error)[:240]})
                        require(time.monotonic() - last_observed < 30,
                                'phone load finances unobservable for 30 seconds')
                    self.save()
                    if not all(future.done() for future in futures.values()):
                        time.sleep(max(0, 10 - (time.monotonic() - started)))
            except Exception as error:
                failure = error
                row['observation_failure'] = str(error)[:240]
            finally:
                # Drain the original operations even after a failed observation.
                for source, future in futures.items():
                    try:
                        row['streams'][source].update(future.result(timeout=130))
                    except Exception as error:
                        row['streams'][source]['sender_error'] = str(error)[:240]
                        failure = failure or error
                time.sleep(3)
                for source, stream in row['streams'].items():
                    try:
                        stream['receiver'] = self.ctl(destination(source), 'status')['probe']
                    except Exception as error:
                        stream['receiver_error'] = str(error)[:240]
                        failure = failure or error
                self.save()
        row['after'] = phone_diagnostics.resources(self.phone)
        if failure:
            raise failure
