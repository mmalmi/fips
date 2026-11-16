"""Recover one committed successor funding operation on physical radio routers."""

import argparse
import os
from pathlib import Path
import signal

from .cadence_workloads import stream
from . import initial_funding
from .paid_finances import payments_credited
from .paid_relay import PaidRelayRun, eventually
from .paid_settlement import original_channels, require, settle_and_collect
from .renewal_interruption import RENEWAL, RenewalCut
from .restart_finances import QUOTE_UNITS
from .wifi_account_recovery import RouterAccountRecovery
from .wifi_measurements import snapshot
from .wifi_priority_checks import received, submitted
from .wifi_remote import digest


class FundingRun(RouterAccountRecovery):
    interruption_key = 'funding_interruption'
    stream = stream

    def __init__(self, args):
        super().__init__(args)
        self.initial = getattr(args, 'initial', False)
        self.evidence.update(streams=[], topology_samples=[], warmup=[], initial_purchase=self.initial)
        for name in ('funding_checks.py', 'initial_funding.py', 'renewal_interruption.py', 'wifi_funding.py'):
            self.evidence['harness_sha256'][name] = digest(Path(__file__).with_name(name).read_bytes())

    def profile_config(self, node):
        config = super().profile_config(node)
        config['terms'].update(fee_msat_per_kib=1, max_rate_msat_per_kib=1, quote_max_units=QUOTE_UNITS)
        config['return_allowance'] = False
        if node is self.nodes['n01'] and not self.initial:
            config['terms']['controller']['renewal'] = RENEWAL
        return config

    def launch_profiles(self):
        super().launch_profiles()
        if not self.initial:
            self.ctl('n01', 'pause_renewals')

    def warmup(self):
        for source, destination in (('n01', 'n03'), ('n03', 'n01')):
            for _ in range(6):
                probe = self.stream(1, 1, source=source, destination=destination)
                self.evidence['warmup'].append(dict(source=source, destination=destination, **probe))
                self.save()
                if probe['receiver']['unique_packets'] == 1:
                    break
            require(probe['receiver']['unique_packets'] == 1, 'radio session warmup failed')

    def payloads(self):
        for source, destination in (('n01', 'n03'), ('n03', 'n01')):
            self.evidence['topology_samples'].append(eventually('exact paid radio line', self.recovery_ready, 90))
            row = dict(source=source, destination=destination,
                       **self.stream(1280, 200, source=source, destination=destination))
            self.evidence['streams'].append(row)
            self.save()
            shape = dict(stream_id=row['sender']['stream_id'], packet_count=1280, payload_bytes=1000)
            submitted(row['sender'], shape)
            received(row['receiver'], shape, self.nodes[source].npub, complete=True)
            self.evidence['topology_samples'].append(eventually('same radio line after stream', self.recovery_ready, 90))
            self.save()

    def exercise(self):
        self.form_line()
        PaidRelayRun.unpaid_probe(self, self.assert_finances())
        self.save()
        if self.initial:
            return initial_funding.exercise(self)
        for source, destination in (('n01', 'n03'), ('n03', 'n01')):
            self.ctl(source, 'buy', destination=self.nodes[destination].npub)
        anchor = eventually('original funded radio accounts', self.finances)
        original_channels(self.nodes, anchor)
        fixture = None
        try:
            self.warmup()
            self.payloads()
            anchor = eventually('initial paid credit', lambda: (
                current if payments_credited(current := self.finances()) else None), 30)
            original_channels(self.nodes, anchor)
            self.evidence['initial_finances'] = anchor
            self.samples = {name: snapshot(node, name, native_counters=True) for name, node in self.nodes.items()}
            self.save()
            renewal = RenewalCut(self)
            renewal.interrupt(anchor)
            self.phase('one successor committed; original routes still paid before process interruption')
            anchor, fixture = renewal.recover()
            self.verify_shortcuts()
            self.phase('original successor recovered, paid, and predecessor refunded automatically')
        finally:
            signal.alarm(0)
            fault = self.mint.request({'type': 'fault', 'command': {'action': 'status'}})
            if fault['phase'] == 'held':
                self.mint.request({'type': 'fault', 'command': {'action': 'release', 'generation': fault['generation']}})
            if fixture is not None:
                self.restore_controls()
                settle_and_collect(self, anchor, execute=self.account_execute, fixture=fixture,
                                   stop=lambda name: self.nodes[name].stop(),
                                   export_path=lambda name, relative: self.nodes[name].state + '/' + relative)
                self.phase('all 384 original test sats collected; three channels closed and wallets empty')
            else:
                self.phase('preserving original pending funding and mint for deliberate recovery')


def main(run_class=FundingRun):
    parser = argparse.ArgumentParser(description=run_class.__doc__ or __doc__)
    for name in ('inventory', 'binary', 'mint-binary', 'mint-host', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--mint-address', required=True)
    parser.add_argument('--initial', action='store_true', help='interrupt the first purchase before any paid route exists')
    args = parser.parse_args()
    args.mint_ssh_forward = args.open_mesh = False
    os.umask(0o077)

    def deadline(_signal, _frame):
        raise TimeoutError('physical funding acceptance exceeded its bounded window')

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(900)
    run_class(args).execute()


if __name__ == '__main__':
    main()
