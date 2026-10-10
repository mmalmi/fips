"""Shared committed-reply interruption and automatic settlement recovery checks."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import time

from .paid_relay import eventually
from .paid_settlement import require, validate_report


class CommittedSettlement:
    interruption_key = 'settlement_interruption'

    def interrupt_settlement(self, anchor):
        channel, _ = next(iter(anchor['n01']['funding'].values()))
        before = {node: self.state_json(node, 'controller/controller.json') for node in self.nodes}
        require(all(not state['buyer_settlements'] and not state['seller_settlements']
                    for state in before.values()), 'settlement already started')
        armed = self.mint.request({'type': 'fault', 'command': {'action': 'arm_swap_reply'}})
        require(armed['phase'] == 'armed', 'mint response barrier did not arm')
        with ThreadPoolExecutor(max_workers=1) as pool:
            settling = pool.submit(self.ctl, 'n01', 'settle')

            def committed():
                status = self.mint.request({'type': 'fault', 'command': {'action': 'status'}})
                return status if status['phase'] == 'held' else None

            held = eventually('committed settlement swap before participant interruption', committed, 30)
            require(held['generation'] == armed['generation']
                    and held['swaps'] == armed['swaps'] + 1 and not settling.done(),
                    'settlement did not reach its single committed swap boundary')
            pending = {node: self.state_json(node, 'controller/controller.json') for node in self.nodes}
            sale = pending['n02']['seller_settlements'][channel]
            purchase = pending['n01']['buyer_settlements'][channel]
            require(set(pending['n02']['seller_settlements']) == {channel}
                    and set(pending['n01']['buyer_settlements']) == {channel}
                    and sale['report'] is None and purchase['report'] is None
                    and not sale['released'] and not purchase['refunded']
                    and sale['channel'] == purchase['channel']
                    and sale['payment'] == purchase['payment']
                    and 0 < sale['payment']['balance'] < 32,
                    'the original paid channel is not pending settlement')
            for node in self.nodes:
                require(pending[node]['funding'] == before[node]['funding']
                        and pending[node]['next_funding'] == before[node]['next_funding'],
                        'settlement created or changed channel funding')
            self.evidence[self.interruption_key] = {
                'channel_id': channel, 'paid_sat': sale['payment']['balance'],
                'mint_armed': armed, 'mint_held': held, 'at': time.time(),
                **self.interruption_metadata(),
                'pending_controller_sha256': {node: hashlib.sha256(
                    json.dumps(state, sort_keys=True).encode()).hexdigest()
                    for node, state in pending.items()},
            }
            self.save()
            self.interrupt_participants()
            try:
                settling.result(timeout=15)
            except RuntimeError:
                pass
            else:
                raise RuntimeError('interrupted settlement unexpectedly completed')
        released = self.mint.request({'type': 'fault', 'command': {
            'action': 'release', 'generation': held['generation']}})
        require(released['phase'] == 'released', 'mint response barrier remained active')
        return channel, pending

    def recover_settlement(self, channel, pending):
        # Observe the recovered disk before starting any wallet or relay process.
        for node in self.nodes:
            stopped = self.state_json(node, 'controller/controller.json')
            for key in ('funding', 'next_funding', 'buyer_settlements', 'seller_settlements'):
                require(stopped[key] == pending[node][key], 'interruption lost durable settlement intent')
        self.launch('n02')

        def provider_recovered():
            sale = self.state_json('n02', 'controller/controller.json')['seller_settlements'][channel]
            return sale if sale['report'] is not None else None

        sale = eventually('provider recovery without its buyer', provider_recovered, 60)
        report = validate_report(sale['report'])
        require(sale == {**pending['n02']['seller_settlements'][channel], 'report': sale['report']}
                and report['channel_id'] == channel
                and report['paid_sat'] == pending['n01']['buyer_settlements'][channel]['payment']['balance'],
                'provider recovery changed the original settlement')
        restored = self.mint.request({'type': 'fault', 'command': {'action': 'status'}})
        held = self.evidence[self.interruption_key]['mint_held']
        require(restored['restores'] > held['restores']
                and all(restored[key] == held[key] for key in ('swaps', 'swap_attempts')),
                'provider did not restore the committed mint response without resubmitting it')
        for node in ('n01', 'n03'):
            self.launch(node)
        eventually('recovered participant line', self.recovery_ready, 90)

        def buyer_recovered():
            purchase = self.state_json('n01', 'controller/controller.json')['buyer_settlements'][channel]
            provider = self.state_json('n02', 'controller/controller.json')['seller_settlements'][channel]
            return purchase if purchase['refunded'] and purchase['released'] and provider['released'] else None

        purchase = eventually('automatic original buyer refund', buyer_recovered, 60)
        require(purchase == {**pending['n01']['buyer_settlements'][channel],
                             'report': sale['report'], 'released': True, 'refunded': True,
                             'wallet_refund_sat': report['refunded_sat']},
                'buyer recovery changed the original settlement or refund')
        for node in self.nodes:
            current = self.state_json(node, 'controller/controller.json')
            require(current['funding'] == pending[node]['funding']
                    and current['next_funding'] == pending[node]['next_funding'],
                    'recovery changed original funding or allocated a new operation')
        self.evidence['automatic_settlement_recovery'] = {
            'report': report, 'provider_recovered_without_buyer': True,
            'buyer_refunded_without_new_settle': True, 'mint_restored': restored,
        }
        self.save()
