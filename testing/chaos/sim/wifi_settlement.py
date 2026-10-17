"""Physical process interruption after a committed mint close, before its reply.

Uses ordinary router executables, persistent accounts, saved radio settings and
the shared mint barrier/settlement checks. The opposite buyer stays stopped until
its provider settles at expiry, then recovers automatically on restart. Does not
interrupt the device kernel.
"""

import argparse
from pathlib import Path
import os
import signal
import time

from .committed_settlement import CommittedSettlement
from .paid_relay import PaidRelayRun, eventually
from .paid_settlement import original_channels, require, settle_and_collect, validate_report
from .wifi_account_recovery import RouterAccountRecovery
from .wifi_measurements import snapshot
from .wifi_remote import digest


class SettlementRun(CommittedSettlement, RouterAccountRecovery):
    channel_lifetime_seconds = 180
    expiry_wait_seconds = 150

    def __init__(self, args):
        super().__init__(args)
        for name in ('committed_settlement.py', 'wifi_settlement.py'):
            self.evidence['harness_sha256'][name] = digest(Path(__file__).with_name(name).read_bytes())

    def profile_config(self, node):
        config = super().profile_config(node)
        config['return_allowance'] = False
        config['terms']['controller']['channel_lifetime_secs'] = self.channel_lifetime_seconds
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


    def recover_settlement(self, channel, pending):
        funding = list(pending['n03']['funding'].values())
        require(len(funding) == 1, 'expected one original reverse channel')
        self.reverse_id = funding[0]['funded']['terms']['id']
        self.reverse_pending = pending['n03']
        super().recover_settlement(channel, pending)

        def reverse_recovered():
            self.monitor.check()
            buyer = self.state_json('n03', 'controller/controller.json')
            sale = self.state_json('n02', 'controller/controller.json')['seller_settlements'][self.reverse_id]
            purchase = buyer['buyer_settlements'].get(self.reverse_id)
            if not purchase or not (purchase['refunded'] and purchase['released'] and sale['released']):
                return None
            require(purchase['report'] == sale['report'] == self.expiry_sale['report'],
                    'late buyer did not receive the original expiry report')
            require(sale['payment'] is None, 'late recovery applied a new cooperative payment')
            require(purchase['payment']['balance'] == sale['report']['signed_sat']
                    and purchase['wallet_refund_sat'] == sale['report']['refunded_sat'],
                    'late recovery changed payment or refund')
            require(buyer['funding'] == self.reverse_pending['funding']
                    and buyer['next_funding'] == self.reverse_pending['next_funding'],
                    'late recovery allocated new funding')
            return {'report': sale['report'], 'refunded': True, 'released': True,
                    'provider_payment_absent': True, 'original_funding_preserved': True,
                    'buyer_process': self.evidence['restarted_processes']['n03']}

        self.evidence['late_expiry_recovery'] = eventually('automatic late-buyer refund', reverse_recovered, 60)
        self.phase('late buyer recovered the original automatic-expiry report and refund')

    def launch(self, name):
        if name == 'n03' and hasattr(self, 'reverse_pending') and not getattr(self, 'expiry_wait_attempted', False):
            self.expiry_wait_attempted = True
            self.nodes[name].remote(['sh', self.nodes[name].temporary + '/guard.sh', 'stopped'])

            def expired():
                self.monitor.check()
                sale = self.state_json('n02', 'controller/controller.json')['seller_settlements'].get(self.reverse_id)
                return sale if sale and sale['report'] is not None else None

            sale = eventually('provider expiry while reverse buyer remains stopped', expired,
                              self.expiry_wait_seconds)
            require(sale['payment'] is None and not sale['released'],
                    'expiry was not completed independently of its buyer')
            report = validate_report(sale['report'])
            require(report['channel_id'] == self.reverse_id and 0 < report['paid_sat'] < 32,
                    'expiry report differs from the original paid reverse channel')
            self.nodes[name].remote(['sh', self.nodes[name].temporary + '/guard.sh', 'stopped'])
            require(self.state_json(name, 'controller/controller.json') == self.reverse_pending,
                    'stopped buyer changed before its late restart')
            self.expiry_sale = sale
            self.evidence['provider_expiry_without_buyer'] = {'sale': sale, 'observed_at': time.time(),
                                                            'buyer_confirmed_stopped': True}
            self.phase('provider completed reverse-channel expiry with its buyer stopped')
        super().launch(name)

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
