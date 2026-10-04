"""Exact paid TCP/FIPS delivery before, during and after test-only frame loss."""

from pathlib import Path
import signal

from .paid_finances import payments_credited
from .paid_relay import PaidRelayRun, eventually
from .paid_settlement import original_channels, require
from .paid_wifi import PaidWifiRun, retain_channels
from .stream_probe import duplex, validate_stream
from .wifi_frame_loss import FrameLoss
from .wifi_measurements import snapshot
from .wifi_remote import digest


class WifiStreamRun(PaidWifiRun):
    def __init__(self, args):
        require(not any(getattr(args, key, None) for key in (
            'active_outage', 'brief_outage', 'outage_node', 'recovery_timing',
            'beacon_interval_secs', 'interrupted_promotion')),
            'reliable streams use their own bounded frame-loss scenario')
        super().__init__(args)
        self.evidence['reliable_streams'] = []
        for name in ('wifi_stream.py', 'stream_probe.py', 'wifi_frame_loss.py'):
            self.evidence['harness_sha256'][name] = digest(Path(__file__).with_name(name).read_bytes())

    def profile_config(self, node):
        config = super().profile_config(node)
        config['return_allowance'] = False
        config['terms'].update(fee_msat_per_kib=1, quote_max_units=128 * 1024 * 1024)
        return config

    def window(self, label):
        row = {'label': label, 'passed': False,
               'before': {name: snapshot(node, name) for name, node in self.nodes.items()}}
        self.evidence['reliable_streams'].append(row)
        prior = eventually('consistent stream financial baseline', self.finances)
        self.save()

        def observe():
            require(self.ready(line=True), 'stream no longer follows the physical two-hop line')
            return {'line_verified': True}

        try:
            duplex(self, row, label=label, count=512 * 1024, duration=30,
                   rate=32 * 1024, observe=observe)
        finally:
            row['after'] = {name: snapshot(node, name) for name, node in self.nodes.items()}
            self.save()
        for name, report in row['results'].items():
            validate_stream(report, row['shapes'][name])
        row['cpu_seconds_per_delivered_mib'] = {}
        for name in self.nodes:
            before, after = row['before'][name], row['after'][name]
            require(all(before['host_process'][key] == after['host_process'][key]
                        for key in ('pid', 'start_ticks')), 'stream relay process changed')
            cpu = after['measurements']['process_cpu_ns'] - before['measurements']['process_cpu_ns']
            require(cpu >= 0, 'process CPU counter went backward')
            row['cpu_seconds_per_delivered_mib'][name] = cpu / 1_000_000_000

        def paid():
            current = self.finances()
            retain_channels(prior, current)
            return current if payments_credited(current) and all(
                current[name]['authorized'] > 0 and
                sum(current[name]['buyer_units'].values()) > sum(prior[name]['buyer_units'].values())
                for name in ('n01', 'n03')) else None

        row['financial'] = eventually('priced stream usage and provider credit', paid, 45)
        row['passed'] = True
        self.phase(label + ' reliable paid duplex delivered and acknowledged')

    def exercise(self):
        self.form_line()
        PaidRelayRun.unpaid_probe(self, self.assert_finances())
        for source, destination in (('n01', 'n03'), ('n03', 'n01')):
            self.ctl(source, 'buy', destination=self.nodes[destination].npub)
        self.channel_anchor = eventually('original funded stream channels', self.finances)
        original_channels(self.nodes, self.channel_anchor)
        try:
            self.window('healthy')
            losses = {name: FrameLoss(self.nodes[name], self.nodes['n02'].mac)
                      for name in ('n01', 'n03')}
            self.evidence['frame_loss'] = {'enabled': {}, 'cleared': {}}
            try:
                for name, loss in losses.items():
                    self.evidence['frame_loss']['enabled'][name] = loss.enable()
                    self.save()
                self.window('frame_loss')
            finally:
                for name, loss in losses.items():
                    self.evidence['frame_loss']['cleared'][name] = loss.clear()
                    self.save()
            require(all(state['before']['dropped_packets'] > 0
                        for state in self.evidence['frame_loss']['cleared'].values()),
                    'frame loss had no observed drop on one direction')
            self.window('recovered')
            self.verify_shortcuts()
        finally:
            signal.alarm(0)
            self.collect()
