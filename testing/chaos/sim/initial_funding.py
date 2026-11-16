"""Restart fresh participants during their first committed funding operation."""

from concurrent.futures import ThreadPoolExecutor
import signal
import time

from .funding_checks import PendingFunding, PendingQuote
from .paid_finances import payments_credited
from .paid_relay import PaidRelayRun, eventually
from .paid_settlement import SettlementFixture, original_channels, require, settle_and_collect
from .renewal_interruption import CONTROLLER_FIELDS, fingerprint
from .wifi_measurements import snapshot


class InitialFunding:
    def __init__(self, run):
        self.run = run

    def controllers(self):
        return {name: self.run.state_json(name, 'controller/controller.json') for name in self.run.nodes}

    def sdk(self):
        return self.run.state_json('n01', 'wallet/spilman-client.json')

    def interrupt(self):
        run = self.run
        before = self.controllers()
        require(all(not row['funding'] and not row['renewals'] and not row['outgoing']
                    and not row['requested'] for row in before.values()), 'first funding accounts are not fresh')
        run.samples = {name: snapshot(node, name, native_counters=True) for name, node in run.nodes.items()}
        armed = run.mint.request({'type': 'fault', 'command': {'action': 'arm_swap_reply'}})
        require(armed['phase'] == 'armed', 'first funding barrier did not arm')
        with ThreadPoolExecutor(max_workers=1) as pool:
            buying = pool.submit(run.ctl, 'n01', 'buy', destination=run.nodes['n03'].npub, operation_timeout=90)
            try:
                def committed():
                    status = run.mint.request({'type': 'fault', 'command': {'action': 'status'}})
                    return status if status['phase'] == 'held' else None

                held = eventually('first committed funding reply', committed, 45)
                require(held['generation'] == armed['generation'] and held['swaps'] == armed['swaps'] + 1
                        and not buying.done(), 'first purchase escaped its committed boundary')
                self.pending = self.controllers()
                require(len(self.pending['n01']['funding']) == 1
                        and not self.pending['n02']['funding'] and not self.pending['n03']['funding'],
                        'first purchase reserved more than one channel')
                self.request, self.intent = next(iter(self.pending['n01']['funding'].items()))
                journal = run.state_json('n02', 'quotes/offers.json')
                self.quote = PendingQuote(self.pending['n01']['requested'], journal,
                                          self.pending['n01']['local'])
                require(self.intent['funded'] is None and all(not row['outgoing'] and not row['renewals']
                        and not row['buyer_settlements'] and not row['seller_settlements']
                        for row in self.pending.values()), 'unacknowledged funding gained route authority')
                for name, state in self.pending.items():
                    require(all(state[key] == before[name][key] for key in ('local', 'epoch', 'policy'))
                            and state['next_funding'] == before[name]['next_funding'] + (name == 'n01'),
                            'first purchase changed policy or reserved another operation')
                self.operation = PendingFunding(self.request, self.intent, {}, self.sdk())
                finances = eventually('reserved first purchase', run.finances)
                require(all(not row['funding'] and not row['signed'] and not row['credited']
                            and row['remaining'] == 64 and row['budget']['wallet_debited_sat'] == 0
                            and row['budget']['pending_reserved_sat'] == (32 if name == 'n01' else 0)
                            for name, row in finances.items()), 'first funding escaped its reservation')
                PaidRelayRun.unpaid_probe(run, finances)
                self.operation.unchanged(self.sdk())
                require(all(state[key] == self.pending[name][key] for name, state in self.controllers().items()
                            for key in CONTROLLER_FIELDS), 'held purchase changed its durable authority')
                barrier = committed()
                require(barrier and all(barrier[key] == held[key] for key in ('phase', 'generation', 'swaps')),
                        'first funding reply escaped before the interruption')
                run.evidence[run.interruption_key] = {
                    'initial_purchase': True, 'funding_stage': self.operation.stage,
                    'mint_armed': armed, 'mint_held': held, 'at': time.time(),
                    **run.interruption_metadata(), 'finances_with_reply_held': finances,
                    'pending_controller_sha256': {name: fingerprint(state) for name, state in self.pending.items()},
                    'pending_sdk_sha256': fingerprint(self.operation.pending),
                    'pending_quote_sha256': fingerprint(self.quote.entry),
                }
                run.save()
                run.interrupt_participants()
                try:
                    buying.result(timeout=15)
                except RuntimeError:
                    pass
                else:
                    raise RuntimeError('interrupted first purchase unexpectedly completed')
            finally:
                fault = run.mint.request({'type': 'fault', 'command': {'action': 'status'}})
                if fault['phase'] == 'held':
                    released = run.mint.request({'type': 'fault', 'command': {
                        'action': 'release', 'generation': fault['generation']}})
                    require(released['phase'] == 'released', 'first funding reply remained held')

    def recover(self):
        run = self.run
        for name, state in self.controllers().items():
            require(all(state[key] == self.pending[name][key] for key in CONTROLLER_FIELDS),
                    'restart lost the original first-purchase authority')
        self.operation.unchanged(self.sdk())
        self.quote.retained(run.state_json('n02', 'quotes/offers.json'))
        for name in ('n02', 'n03', 'n01'):
            run.launch(name)
        eventually('first-purchase recovery line', run.recovery_ready, 90)

        def activated():
            state = run.state_json('n01', 'controller/controller.json')
            return state if state['funding'][self.request]['funded'] is not None and any(
                row['funding_id'] == self.request and row['accepted'] and not row['retired']
                for row in state['outgoing'].values()) else None

        current = eventually('automatic original first purchase', activated, 90)
        for name, state in self.controllers().items():
            require(all(state[key] == self.pending[name][key] for key in ('local', 'epoch', 'policy', 'next_funding'))
                    and set(state['funding']) == set(self.pending[name]['funding'])
                    and not state['renewals'], 'first-purchase recovery created another funding intent')
        channel = self.operation.recovered(current['funding'][self.request], self.sdk(),
                                           buyer=current['local'], mint=run.mint_url)
        self.quote.accepted(current, run.state_json('n02', 'controller/controller.json'), channel)
        restored = run.mint.request({'type': 'fault', 'command': {'action': 'status'}})
        require(restored['restores'] > run.evidence[run.interruption_key]['mint_held']['restores'],
                'first purchase did not restore the committed mint result')
        fixture = SettlementFixture(dict.fromkeys(run.nodes, 128), dict.fromkeys(run.nodes, 64), 32,
                                    {channel: 'n01'}, {channel: 'n02'})
        finances = eventually('recovered first-purchase finances', run.finances)
        original_channels(run.nodes, finances, fixture=fixture)
        run.evidence['automatic_initial_funding_recovery'] = {
            'channel_id': channel, 'funding_stage': self.operation.stage,
            'original_request_survived': True, 'one_channel_only': True,
            'original_quote_survived': True, 'accepted_quote_sha256': fingerprint(self.quote.entry),
            'mint_restored': restored, 'recovered_finances': finances,
        }
        run.save()
        return finances, fixture


def exercise(run):
    fixture = anchor = None
    try:
        first = InitialFunding(run)
        first.interrupt()
        anchor, fixture = first.recover()
        run.phase('first purchase recovered and activated without another buy request')
        # Reverse traffic has separate explicit authority and is purchased only now.
        fixture = None
        run.ctl('n03', 'buy', destination=run.nodes['n01'].npub)
        anchor = eventually('both original endpoint channels', run.finances)
        owners = original_channels(run.nodes, anchor)
        fixture = SettlementFixture(dict.fromkeys(run.nodes, 128), dict.fromkeys(run.nodes, 64), 32,
                                    owners, dict.fromkeys(owners, 'n02'))
        run.warmup()
        run.payloads()
        paid = eventually('both recovered routes pay', lambda: (
            value if payments_credited(value := run.finances()) else None), 30)
        require(all(paid[name]['authorized'] >= 2 for name in ('n01', 'n03')),
                'first purchase recovered without paid delivery')
        run.evidence['paid_finances_after_initial_recovery'] = paid
        run.verify_shortcuts()
    finally:
        signal.alarm(0)
        if fixture is not None:
            run.restore_controls()
            settle_and_collect(run, anchor, execute=run.account_execute, fixture=fixture,
                               stop=lambda name: run.nodes[name].stop(),
                               export_path=lambda name, relative: run.nodes[name].state + '/' + relative)
            run.phase('all 384 initial-purchase test sats collected; wallets empty')
        else:
            run.phase('preserving original first-purchase accounts and mint for recovery')
