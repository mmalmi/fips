"""Retire paid radio channels while an isolated wallet's SQLite writer is held."""

import argparse
import json
import os
from pathlib import Path
import shlex
import signal
import time

from .cadence_workloads import stream
from .paid_finances import payments_credited
from .paid_relay import eventually
from .paid_settlement import (SettlementFixture, collect_settled_wallets, original_channels,
                              require, validate_finances, validate_report)
from .paid_wifi import PaidWifiRun
from .restart_finances import QUOTE_UNITS
from .wifi_priority_checks import received, submitted
from .wifi_remote import Router, digest


class HeldWalletRouter(Router):
    def guard_restore_command(self):
        return (f'if [ -f {self.temporary}/sqlite-armed ]; then '
                f'touch {self.temporary}/sqlite-release; fi')

    def hold_wallet(self, helper, seconds=150):
        require(type(seconds) is int and 1 <= seconds <= 420, 'invalid SQLite hold deadline')
        self.hold_seconds = seconds
        data = helper.read_bytes()
        path = self.temporary + '/sqlite-hold'
        self.guarded('umask 077; set -C; cat > ' + shlex.quote(path), data)
        require(self.remote(['sha256sum', path]).decode().split()[0] == digest(data),
                'SQLite hold executable changed')
        self.guarded(f'chmod 700 {path}\n'
                     f'touch {self.temporary}/sqlite-armed\n'
                     f'setsid {path} {self.state}/wallet/cashu/wallet.sqlite '
                     f'{self.temporary}/sqlite-release {seconds} </dev/null 9>&- '
                     f'>{self.temporary}/sqlite-hold.log 2>{self.temporary}/sqlite-hold.err &')
        eventually('isolated SQLite write lock acquired', self.held, 8)

    def hold_events(self):
        raw = self.remote(['cat', self.temporary + '/sqlite-hold.log']).decode()
        return [json.loads(line) for line in raw.splitlines()]

    def held(self):
        events = self.hold_events()
        if len(events) != 1 or events[0].get('locked') is not True:
            return False
        pid = events[0]['pid']
        require(type(pid) is int and pid > 1, 'invalid hold process')
        expected = [self.temporary + '/sqlite-hold', self.state + '/wallet/cashu/wallet.sqlite',
                    self.temporary + '/sqlite-release', str(self.hold_seconds)]
        actual = self.remote(['cat', f'/proc/{pid}/cmdline']).decode().rstrip('\0').split('\0')
        return actual == expected

    def release_wallet(self):
        self.remote(self.guard_restore_command())
        def released():
            events = self.hold_events()
            return events if len(events) == 2 else None

        events = eventually('SQLite transaction rolled back', released, 8)
        require(events[-1] == {'released': True, 'reason': 'requested'},
                'SQLite hold ended outside the requested release')
        return events


class RetirementRun(PaidWifiRun):
    stream = stream
    quote_max_units = QUOTE_UNITS

    def make_router(self, spec, index):
        return HeldWalletRouter(spec, self.run, self.root, self.open_mesh)

    def profile_config(self, node):
        config = super().profile_config(node)
        config['terms'].update(fee_msat_per_kib=1, max_rate_msat_per_kib=1,
                               quote_max_units=QUOTE_UNITS, quote_lifetime_secs=30,
                               wallet_capacity_bytes=16 * 1024 * 1024)
        config['terms']['controller']['channel_lifetime_secs'] = 60
        config['return_allowance'] = False
        return config

    def exercise(self):
        self.evidence['harness_sha256']['wifi_retirement.py'] = digest(Path(__file__).read_bytes())
        self.evidence['sqlite_hold_sha256'] = digest(self.args.sqlite_hold.read_bytes())
        self.evidence['physical_power_loss'] = False
        self.form_line()
        held, reports, settled, owners = [], {}, None, None
        try:
            for source, destination in (('n01', 'n03'), ('n03', 'n01')):
                self.ctl(source, 'buy', destination=self.nodes[destination].npub)
                result = self.stream(1024, 200, source=source, destination=destination)
                shape = {'stream_id': result['sender']['stream_id'], 'packet_count': 1024,
                         'payload_bytes': 1000}
                submitted(result['sender'], shape)
                received(result['receiver'], shape, self.nodes[source].npub, complete=True)
                self.evidence.setdefault('streams', []).append(result)
                self.save()
            self.verify_shortcuts()
            prior = eventually('original paid channels credited', lambda:
                               (v if payments_credited(v := self.finances()) else None), 30)
            owners = original_channels(self.nodes, prior)
            for name in self.nodes:
                for report in self.ctl(name, 'settle')['settlements']:
                    channel = report['channel_id']
                    require(owners.get(channel) == name and channel not in reports,
                            'unexpected or duplicate original settlement')
                    reports[channel] = validate_report(report)
            require(set(reports) == set(owners), 'original settlement missing')
            settled = self.finances()
            validate_finances(prior, settled, reports)
            self.evidence['settled_before_retirement'] = {'reports': reports, 'financial': settled}
            self.phase('original paid radio channels settled before wallet contention')
            for name in ('n01', 'n02'):
                held.append(name)
                self.nodes[name].hold_wallet(self.args.sqlite_hold)
            blocked = eventually('durable sender retirement waiting for its wallet', lambda:
                                 self.pending_sender(), 100)
            self.evidence['pending_sender'] = {
                'funding_count': len(blocked['funding']),
                'through': blocked['history']['channels']['pending']['after']['through']}
            samples = []
            for _ in range(3):
                for name in held:
                    node = self.nodes[name]
                    require(node.held(), 'wallet contention ended before controller read')
                    started = time.monotonic()
                    status = node.control('status', operation_timeout=3)
                    elapsed = time.monotonic() - started
                    require(elapsed < 2 and node.held(), 'controller read stalled during wallet work')
                    require(status['funding_budget'] == settled[name]['budget']
                            and status['remaining_budget_sat'] == settled[name]['remaining'],
                            'pending cleanup changed financial authority')
                    samples.append({'node': name, 'seconds': elapsed})
            require(self.pending_sender(), 'sender cleanup bypassed the held writer')
            self.evidence['controller_reads'] = samples
            self.phase('controller reads completed while original wallet retirement remained pending')
            self.release_holds(held)
            retired = eventually('original sender and receiver retirement finished',
                                 lambda: self.retired(settled), 60)
            self.evidence['retirement'] = retired
            self.phase('original channel history retired after releasing SQLite writers')
        finally:
            signal.alarm(0)
            self.release_holds(held)
            if settled is not None:
                fixture = SettlementFixture(dict.fromkeys(self.nodes, 128),
                                            dict.fromkeys(self.nodes, self.buyer_budget), 32,
                                            owners, dict.fromkeys(owners, 'n02'))
                collect_settled_wallets(self, settled, reports, owners, self.mint_url,
                                       execute=self.account_execute,
                                       stop=lambda name: self.nodes[name].stop(),
                                       export_path=lambda name, relative: self.nodes[name].state + '/' + relative,
                                       fixture=fixture)
                self.phase('all 384 test sats collected; every test wallet empty')

    def release_holds(self, held):
        while held:
            name = held[-1]
            events = self.nodes[name].release_wallet()
            held.pop()
            self.evidence.setdefault('wallet_holds', {})[name] = events
            self.save()

    def pending_sender(self):
        journal = self.state_json('n01', 'controller/controller.json')
        history = (journal.get('history') or {}).get('channels') or {}
        return journal if history.get('pending') else None

    def retired(self, settled):
        journals = {name: self.state_json(name, 'controller/controller.json') for name in self.nodes}
        if any(j['funding'] or j['buyer_settlements'] or j['seller_settlements'] for j in journals.values()):
            return None
        for name in self.nodes:
            status = self.ctl(name, 'status')
            require(status['funding_budget'] == settled[name]['budget']
                    and status['remaining_budget_sat'] == settled[name]['remaining'],
                    'retirement reset spending or capital')
        require(all(journals[name]['history']['channels']['totals']['channels'] == 1
                    for name in ('n01', 'n03')), 'sender history did not retain both original channels')
        seller = journals['n02']['history']['seller']['totals']
        require(seller['accounting']['channels'] == 2
                and sum(t['channels'] for t in seller['receiver']['totals']) == 2,
                'receiver retirement did not finish the original handoff')
        return {'sender_channels': 2, 'receiver_channels': 2, 'original_budgets_retained': True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('inventory', 'binary', 'mint-binary', 'mint-host', 'sqlite-hold', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--mint-address', required=True)
    parser.add_argument('--fragmented-live', action='store_true',
                        help='paid traffic during cleanup of 480 original one-sat refund coins')
    parser.add_argument('--retirement-renewal', action='store_true',
                        help='one automatic successor deferred by fragmented retirement')
    args = parser.parse_args()
    if args.retirement_renewal and not args.fragmented_live:
        parser.error('--retirement-renewal requires --fragmented-live')
    args.mint_ssh_forward = False
    os.umask(0o077)

    def deadline(_signal, _frame):
        raise TimeoutError('router retirement acceptance exceeded its bounded window')

    signal.signal(signal.SIGALRM, deadline)
    if args.fragmented_live:
        from .wifi_retirement_live import LiveRetirementRun, RUN_WINDOW
        signal.alarm(RUN_WINDOW)
        if args.retirement_renewal:
            from .wifi_retirement_renewal import RenewalRetirementRun
            RenewalRetirementRun(args).execute()
        else:
            LiveRetirementRun(args).execute()
    else:
        signal.alarm(600)
        RetirementRun(args).execute()


if __name__ == '__main__':
    main()
