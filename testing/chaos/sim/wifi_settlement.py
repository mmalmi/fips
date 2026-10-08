"""Physical process interruption after a committed mint close, before its reply.

Uses ordinary router executables, persistent accounts, saved radio settings and
the shared mint barrier/settlement checks. Does not interrupt the device kernel.
"""

import argparse
from pathlib import Path
import os
import signal

from .committed_settlement import CommittedSettlement
from .paid_relay import PaidRelayRun, eventually
from .paid_settlement import original_channels, settle_and_collect
from .wifi_account_recovery import RouterAccountRecovery
from .wifi_measurements import snapshot
from .wifi_remote import digest


class SettlementRun(CommittedSettlement, RouterAccountRecovery):
    def __init__(self, args):
        super().__init__(args)
        for name in ('committed_settlement.py', 'wifi_settlement.py'):
            self.evidence['harness_sha256'][name] = digest(Path(__file__).with_name(name).read_bytes())

    def profile_config(self, node):
        config = super().profile_config(node)
        config['return_allowance'] = False
        return config

    def exercise(self):
        self.form_line()
        PaidRelayRun.unpaid_probe(self, self.assert_finances())
        self.save()
        for source, destination in (('n01', 'n03'), ('n03', 'n01')):
            self.ctl(source, 'buy', destination=self.nodes[destination].npub)
        funded = eventually('two original physical channels', self.finances)
        original_channels(self.nodes, funded)
        anchor = funded
        try:
            anchor = self.paid_streams(funded, 'original bidirectional paid radio delivery')
            self.evidence['initial_finances'] = anchor
            self.samples = {name: snapshot(node, name, native_counters=True) for name, node in self.nodes.items()}
            self.save()
            channel, pending = self.interrupt_settlement(anchor)
            self.recover_settlement(channel, pending)
            self.verify_shortcuts()
            self.phase('provider restores without its buyer; original buyer refund completes automatically')
        finally:
            signal.alarm(0)
            fault = self.mint.request({'type': 'fault', 'command': {'action': 'status'}})
            if fault['phase'] == 'held':
                self.mint.request({'type': 'fault', 'command': {'action': 'release', 'generation': fault['generation']}})
            self.restore_controls()
            # Use the original pre-interruption accounts, including the channel
            # whose original refund/release was independently observed above.
            settle_and_collect(self, anchor, execute=self.account_execute,
                               stop=lambda name: self.nodes[name].stop(),
                               export_path=lambda name, relative: self.nodes[name].state + '/' + relative)
            self.phase('all 384 original test sats collected; every test wallet empty')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('inventory', 'binary', 'mint-binary', 'mint-host', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--mint-address', required=True)
    args = parser.parse_args()
    args.mint_ssh_forward = args.open_mesh = False
    os.umask(0o077)

    def deadline(_signal, _frame):
        raise TimeoutError('physical settlement acceptance exceeded its bounded window')

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(900)
    SettlementRun(args).execute()


if __name__ == '__main__':
    main()
