"""Ten minutes of paid background transit across ordinary channel renewals.

The two paced TCP/FIPS streams reuse the phone fixture's four capped accounts.
No mint faults, network changes, manual successor purchase or service restart.
"""

import hashlib
from pathlib import Path
import time

from .paid_phone_transit import PhoneTransitRun
from .paid_settlement import require, verified_refund
from .phone_diagnostics import control
from .phone_outage import processes
from .phone_renewal import successor


MIN_CHANNELS = {'n01': 3, 'phone': 3, 'n02': 1, 'n03': 3}
WINDOW_BYTES, WINDOW_SECONDS, RATE = 9 * 1024**2, 300, 32 * 1024
RENEWAL = {'at_capacity_percent': 80, 'before_expiry_secs': 30}


def validate_successors(row, before, after):
    """Bind live delivery/payment advances to each exact funded successor."""
    require(row['before_processes'] == row['after_processes'], 'a paid participant restarted')
    require(2 <= len(row['samples']) <= 240, 'missing or unbounded live renewal observations')
    for name, minimum in MIN_CHANNELS.items():
        prior, final = before[name], after[name]
        controller = final['controller']
        count = len(controller['funding'])
        require(controller['policy'] == prior['controller']['policy']
                and controller['local'] == prior['controller']['local']
                and final['buyer']['total_budget_sat'] == prior['buyer']['total_budget_sat'] == 64
                and final['buyer']['local'] == prior['buyer']['local'],
                'renewal changed identity or lifetime authority')
        require(minimum <= count <= 4
                and all(controller['funding'].get(key) == value
                        for key, value in prior['controller']['funding'].items()),
                'renewal changed original funding or its expected count')
        current = row['original'][name]
        ordered, observations = [current], {current['channel']['id']: {}}
        for sample in row['samples']:
            state = sample['states'][name]
            budget = state['funding_budget']
            require(0 <= budget['pending_reserved_sat'] <= budget['locked_sat'] <= 64
                    and 0 <= budget['wallet_refunded_sat'] <= budget['wallet_debited_sat']
                    and 0 <= budget['exposure_sat'] == budget['wallet_debited_sat']
                    + budget['pending_reserved_sat'] - budget['wallet_refunded_sat']
                    <= controller['policy']['max_wallet_spend_sat']
                    and 0 <= state['remaining_budget_sat'] <= 64,
                    'live renewal exceeded original capital or spending limits')
            require(len(state['purchases']) <= 1, 'renewal created competing purchases')
            if not state['purchases']:
                continue
            purchase = state['purchases'][0]
            channel = purchase['channel']['id']
            if channel != current['channel']['id']:
                require(channel not in observations, 'renewal returned to a predecessor')
                current = successor(state, current)
                ordered.append(current)
                observations[channel] = {}
            else:
                require(purchase == current, 'active purchase authority changed')
            probes = [sample['states'][endpoint]['stream_probe'] for endpoint in ('n01', 'n03')]
            if all(p and not p['finished'] and p['shape']['stream_id'] == sample['stream_id']
                   for p in probes):
                progress = state['payment_progress'].get(channel, {})
                observations[channel].setdefault(sample['stream_id'], []).append(
                    (progress.get('acknowledged_msat', 0), *[p['received_bytes'] for p in probes]))
        funded = {intent['funded']['terms']['id'] for intent in controller['funding'].values()
                  if intent['funded'] is not None}
        require(len(ordered) == count and funded == set(observations),
                'live observations did not cover every funded channel')
        for index, purchase in enumerate(ordered):
            channel = purchase['channel']['id']
            if index:
                require(any(len(points) >= 2 and all(last > first
                        for first, last in zip(points[0], points[-1]))
                        for points in observations[channel].values()),
                        'successor lacked advancing payment and delivery in both directions')
            if index < len(ordered) - 1:
                require(verified_refund(controller, channel, purchase['channel']) is not None,
                        'predecessor refund is unresolved')
        row.setdefault('channels', {})[name] = [p['channel']['id'] for p in ordered]
    return {name: len(channels) for name, channels in row['channels'].items()}


class PhoneRenewalLoadRun(PhoneTransitRun):
    def __init__(self, args):
        require(not any(getattr(args, flag, False) for flag in (
            'screen_off', 'sustained_transit', 'forced_idle', 'phone_outage',
            'phone_restart', 'impaired_transit', 'compare_transit_rates')),
            'sustained renewal requires its own healthy background workload')
        super().__init__(args)
        self.evidence['renewable_transit'] = {'passed': False, 'samples': [], 'windows': []}
        self.evidence['harness_sha256'][Path(__file__).name] = hashlib.sha256(
            Path(__file__).read_bytes()).hexdigest()
        self.active_stream = None

    def profile_config(self, node):
        config = super().profile_config(node)
        config['terms']['controller']['renewal'] = dict(RENEWAL)
        if node is self.nodes['n02']:
            config['terms']['quote_lifetime_secs'] = 300
        return config

    def stream_shape(self, mode, unpaid):
        if mode.startswith('background-renewal-') and not unpaid:
            return WINDOW_BYTES, WINDOW_SECONDS, RATE, WINDOW_SECONDS
        return super().stream_shape(mode, unpaid)

    def topology(self):
        states = super().topology()
        if states and self.active_stream:
            samples = self.evidence['renewable_transit']['samples']
            require(len(samples) < 240, 'renewal observations exceeded their finite bound')
            stream = self.evidence['windows'][-1]
            samples.append({'at': time.monotonic(), 'stream_id': stream['shapes']['n01']['stream_id'],
                            'states': {name: {key: state[key] for key in (
                                'purchases', 'funding_budget', 'remaining_budget_sat',
                                'payment_progress', 'stream_probe')} for name, state in states.items()}})
        return states

    def stream(self, mode, *, unpaid=False, observe=None):
        if mode != 'background' or unpaid:
            return super().stream(mode, unpaid=unpaid, observe=observe)
        row = self.evidence['renewable_transit']
        before = self.journals('before-renewable-transit')
        states = self.topology()
        require(states is not None and all(len(s['purchases']) == 1 for s in states.values()),
                'renewal load requires exactly one original purchase per participant')
        row.update(original={n: s['purchases'][0] for n, s in states.items()},
                   before_processes=processes(self))
        for index in range(2):
            label = 'background-renewal-' + str(index + 1)
            window = {'started_at': time.monotonic()}
            if row['windows']:
                require(0 <= window['started_at'] - row['windows'][-1]['ended_at'] <= 30,
                        'renewal traffic paused for more than 30 seconds')
            row['windows'].append(window)
            self.active_stream = label
            try:
                super().stream(label)
            finally:
                self.active_stream = None
                window['ended_at'] = time.monotonic()
                self.save()
            results = self.evidence['windows'][-1]['results']
            require(all(r['completed_us'] >= (WINDOW_BYTES // RATE - 1) * 1_000_000
                        for r in results.values()), 'traffic finished before its paced interval')
        self.restore_foreground()
        for name in self.nodes:
            self.once('pause-renewals-' + name, lambda name=name: self.ctl(name, 'pause_renewals'))
        control(self.phone, 'pause_renewals')
        row['after_processes'] = processes(self)
        self.settlement_channel_counts = validate_successors(
            row, before, self.journals('after-renewable-transit'))
        row['passed'] = True
        self.phase('ten minutes of background transit delivered across automatic paid successors')
