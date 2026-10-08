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
from .paid_settlement import original_channels, require, settle_and_collect
from .paid_wifi import PaidWifiRun
from .wifi_measurements import snapshot
from .wifi_remote import digest
from .wifi_restart import crash_profile


class SettlementRun(CommittedSettlement, PaidWifiRun):
    def __init__(self, args):
        super().__init__(args)
        self.crash_attempts = []
        self.samples = {}
        self.evidence.update(physical_power_loss=False, physical_process_interruption=True)
        for name in ('committed_settlement.py', 'wifi_settlement.py'):
            self.evidence['harness_sha256'][name] = digest(Path(__file__).with_name(name).read_bytes())

    def profile_config(self, node):
        config = super().profile_config(node)
        config['return_allowance'] = False
        return config

    def settlement_ready(self):
        return self.ready(line=True)

    def settlement_cut_metadata(self):
        return {'processes_before': {name: row['host_process'] for name, row in self.samples.items()}}

    def cut_settlement_participants(self):
        evidence = self.evidence[self.settlement_evidence_key]
        evidence['crashes'] = {}
        for name, node in self.nodes.items():
            # Save dispatch intent first; never repeat an uncertain signal.
            self.crash_attempts.append(name)
            evidence['crash_attempts'] = list(self.crash_attempts)
            self.save()
            evidence['crashes'][name] = crash_profile(node, self.samples[name])
            self.save()
        self.phase('owned relay processes stopped while the committed mint reply is withheld')

    def launch(self, name):
        node = self.nodes[name]
        node.start()
        after = eventually('original router identity after restart',
                           lambda: snapshot(node, name, native_counters=True), 60)
        old, new = self.samples[name]['host_process'], after['host_process']
        require(after['npub'] == node.npub and old['host'] == new['host']
                and new['start_ticks'] > old['start_ticks'],
                'settlement recovery did not retain identity in a new process epoch')
        self.evidence.setdefault('restarted_processes', {})[name] = new
        self.save()

    def restore_controls(self):
        for name in self.crash_attempts:
            node = self.nodes[name]
            try:
                self.ctl(name, 'status')
            except RuntimeError:
                node.remote(['sh', node.temporary + '/guard.sh', 'stopped'])
                self.launch(name)

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
