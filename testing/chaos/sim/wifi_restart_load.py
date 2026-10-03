"""Finite bidirectional router load across a real middle-relay process crash.

Reuse guarded Wi-Fi discovery, persistent accounts, probes and test-money closure.
This is neither a matched cadence comparison nor physical power-loss acceptance.
"""

import argparse
import os
from pathlib import Path
import signal
import time

from .cadence_workloads import stream
from .paid_finances import payments_credited
from .paid_relay import eventually
from .paid_settlement import amount, original_channels, require
from .paid_wifi import PaidWifiRun
from .wifi_measurements import snapshot
from .wifi_priority_checks import received, submitted
from .wifi_remote import digest
from .wifi_restart import crash_profile


PACKETS, RATE, ROUNDS, QUOTE_UNITS = 4000, 200, 6, 32 * 1024 * 1024


def recovered_exposure(journal):
    """Derive exact unbilled exposure from the stopped provider's durable ceiling."""
    require(journal['version'] == 2 and journal['window_msat'] == 4000,
            'unexpected durable-window policy')
    channels = journal['ledger']['channels']
    require(len(channels) == 2 and len(journal['ceilings']) == 2,
            'restart requires exactly two original provider channels')
    result = {}
    for channel in channels:
        terms, usage = channel['terms'], channel['usage']
        key = terms['id']
        require(key not in result and channel['active'] and terms['capacity_sat'] == 32
                and terms['grace_msat'] == 8000, 'provider channel terms changed')
        ceiling = amount(journal['ceilings'][key])
        reserved, lost = amount(usage['reserved_msat']), amount(usage['lost_msat'])
        require(lost == 0 and 0 <= ceiling - reserved <= 4000
                and ceiling <= min(32000, amount(usage['paid_msat']) + 8000),
                'stopped allowance exceeds the original exposure bound')
        result[key] = lost + ceiling - reserved
    require(set(result) == set(journal['ceilings']), 'durable ceiling membership differs')
    return result


def retained_finances(anchor, current, expected_lost):
    require(original_channels(anchor, anchor) == original_channels(current, current),
            'load or restart replaced an original channel')
    credited = current['n02']['credited']
    require(set(credited) == set(expected_lost), 'provider channel membership changed')
    for name, state in current.items():
        old = anchor[name]
        require(state['funding'] == old['funding'] and state['budget'] == old['budget'],
                'load or restart changed funding or capital')
        for channel, signed in state['signed'].items():
            require(old['signed'][channel] <= amount(signed) <= 32
                    and credited[channel] <= state['signed_after'][channel] * 1000,
                    'authorization decreased or provider credit exceeds signed liability')
        for kind in ('buyer_units', 'seller_units'):
            require(set(state[kind]) == set(old[kind])
                    and all(old[kind][key] <= amount(value) <= QUOTE_UNITS
                            for key, value in state[kind].items()),
                    'route agreement changed or usage decreased/exceeded its grant')
    require(set(current['n02']['seller_channels']) == set(credited),
            'provider usage membership changed')
    for channel, usage in current['n02']['seller_channels'].items():
        require(usage['paid_msat'] == credited[channel]
                and 0 <= usage['submitted_msat'] <= usage['reserved_msat']
                <= min(32000, credited[channel] + 8000)
                and usage['submitted_msat'] + usage['lost_msat'] <= usage['reserved_msat']
                and usage['lost_msat'] == expected_lost[channel],
                'provider recovery changed the exact unbilled exposure or credit bound')
    return current if payments_credited(current) else None


class RestartLoadRun(PaidWifiRun):
    stream = stream

    def __init__(self, args):
        super().__init__(args)
        self.anchor = None
        self.expected_lost = {}
        self.restart_attempted = False
        self.evidence.update(workload={'rounds': ROUNDS, 'packets_per_direction_per_round': PACKETS,
                                      'packets_per_second': RATE, 'payload_bytes': 1000},
                             crash_after_round=ROUNDS // 2, physical_power_loss=False,
                             streams=[], warmup=[])
        self.evidence['harness_sha256']['wifi_restart_load.py'] = digest(Path(__file__).read_bytes())

    def profile_config(self, node):
        config = super().profile_config(node)
        config['terms'].update(fee_msat_per_kib=1, max_rate_msat_per_kib=1,
                               quote_max_units=QUOTE_UNITS)
        return config

    def checkpoint(self, *, advance=False):
        current = retained_finances(self.anchor, self.finances(), self.expected_lost)
        if current and (not advance or all(current[n]['authorized'] > self.anchor[n]['authorized']
                                          for n in ('n01', 'n03'))):
            return current
        return None

    def warmup(self):
        for source, destination in (('n01', 'n03'), ('n03', 'n01')):
            for _ in range(6):
                probe = self.stream(1, 1, source=source, destination=destination)
                self.evidence['warmup'].append({'source': source, 'destination': destination, **probe})
                self.save()
                if probe['receiver']['unique_packets'] == 1:
                    break
            require(probe['receiver']['unique_packets'] == 1, 'native session warmup failed')

    def middle_sample(self):
        self.monitor.check()
        return snapshot(self.nodes['n02'], 'n02', native_counters=True)

    def restart_middle(self):
        node = self.nodes['n02']
        state = self.evidence['restart'] = {'before': self.middle_sample(), 'attempted_at': time.monotonic()}
        self.restart_attempted = True
        self.save()
        state['crash'] = crash_profile(node, state['before'])
        journal = self.state_json('n02', 'seller/ledger.json')
        state['stopped_journal'] = journal
        self.expected_lost = recovered_exposure(journal)
        state['expected_lost_msat'] = self.expected_lost
        self.save()
        node.start()
        after = eventually('middle relay restarted', self.middle_sample, 60)
        old, new = state['before']['host_process'], after['host_process']
        require(after['npub'] == state['before']['npub'] == node.npub
                and old['host'] == new['host'] == 'n02' and new['start_ticks'] > old['start_ticks'],
                'middle restart did not retain its identity with a new process epoch')
        state['after'] = after
        eventually('original authenticated line after restart', lambda: self.ready(line=True), 150)
        self.warmup()
        state['financial'] = eventually('exact durable exposure retained after restart', self.checkpoint, 60)
        state['completed_at'] = time.monotonic()
        self.phase('middle process restarted; original channels and exact unbilled exposure retained')

    def restore_middle(self):
        if not self.restart_attempted:
            return
        try:
            self.middle_sample()
        except RuntimeError:
            # Cleanup can observe an ambiguous dispatch, but never replay the kill.
            self.nodes['n02'].start()
            eventually('middle control restored for financial closure', self.middle_sample, 60)

    def exercise(self):
        self.form_line()
        for source, destination in (('n01', 'n03'), ('n03', 'n01')):
            self.ctl(source, 'buy', destination=self.nodes[destination].npub)
        self.anchor = eventually('original funded accounts', self.finances)
        original_channels(self.nodes, self.anchor)
        self.expected_lost = dict.fromkeys(self.anchor['n02']['credited'], 0)
        try:
            self.warmup()
            for round_id in range(ROUNDS):
                if round_id == ROUNDS // 2:
                    self.restart_middle()
                for source, destination in (('n01', 'n03'), ('n03', 'n01')):
                    before = self.middle_sample()
                    started = time.monotonic()
                    probe = self.stream(PACKETS, RATE, source=source, destination=destination)
                    row = {'round': round_id, 'source': source, 'destination': destination,
                           'seconds': time.monotonic() - started, 'before': before,
                           'after': self.middle_sample(), **probe}
                    self.evidence['streams'].append(row)
                    self.save()  # Failed delivery remains evidence and still requires collection.
                    require(all(row['before']['host_process'][key] == row['after']['host_process'][key]
                                for key in ('host', 'pid', 'start_ticks')),
                            'middle relay restarted inside a measured load stream')
                    shape = {'stream_id': probe['sender']['stream_id'],
                             'packet_count': PACKETS, 'payload_bytes': 1000}
                    submitted(probe['sender'], shape)
                    received(probe['receiver'], shape, self.nodes[source].npub, complete=True)
                    require(row['seconds'] >= (PACKETS - 1) / RATE,
                            'finite load completed before its pacing duration')
                current = eventually('automatic payments for the load cohort',
                                     lambda: self.checkpoint(advance=True), 30)
                self.anchor = current
                self.phase('bidirectional load cohort delivered and paid', round=round_id, financial=current)
            self.verify_shortcuts()
        finally:
            signal.alarm(0)
            self.restore_middle()
            self.collect()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('inventory', 'binary', 'mint-binary', 'mint-host', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--mint-address', required=True)
    args = parser.parse_args()
    args.mint_ssh_forward = False
    os.umask(0o077)

    def deadline(_signum, _frame):
        raise TimeoutError('router restart/load acceptance exceeded its bounded window')

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(900)
    RestartLoadRun(args).execute()


if __name__ == '__main__':
    main()
