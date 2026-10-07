"""Cut a guest while one successor's committed mint reply is withheld.

Raw wallet authority stays in memory. The existing settlement fixture closes
exactly the two original channels and the one durably reserved successor.
"""

import hashlib
import json
import time

from .paid_finances import payment_progress, payments_credited
from .paid_relay import eventually
from .paid_settlement import SettlementFixture, original_channels, require, verified_refund
from .restart_finances import recovered_exposure


RENEWAL = {'at_capacity_percent': 5, 'before_expiry_secs': 30}
CONTROLLER_FIELDS = ('local', 'epoch', 'policy', 'funding', 'next_funding',
                     'renewals', 'outgoing', 'requested', 'buyer_settlements', 'seller_settlements')
SDK_FIELDS = ('admissions', 'openings', 'open_requests', 'funding', 'pending_funding')


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


class RenewalCut:
    def __init__(self, run):
        self.run = run

    def controllers(self):
        return {node: self.run.state_json(node, 'controller/controller.json') for node in self.run.nodes}

    def sdk(self):
        return self.run.state_json('n01', 'wallet/spilman-client.json')

    def interrupt(self, anchor):
        run = self.run
        self.original = self.controllers()
        self.sdk_original = self.sdk()
        self.owners = original_channels(run.nodes, anchor)
        self.old_id, = (key for key, owner in self.owners.items() if owner == 'n01')
        self.old_terms = next(row['funded']['terms'] for row in self.original['n01']['funding'].values())
        require(all(not row['renewals'] and not row['buyer_settlements']
                    and not row['seller_settlements'] for row in self.original.values()),
                'guest renewal started before the funding barrier')
        require(not self.sdk_original.get('admissions') and not self.sdk_original.get('pending_funding')
                and all(key == 'r:' + opening['request']['client_request_id']
                        and self.sdk_original['open_requests'].get(key[2:]) == opening['channel_id']
                        and opening['channel_id'] in self.sdk_original['funding']
                        for key, opening in self.sdk_original.get('openings', {}).items()),
                'guest has unresolved original funding')
        armed = run.mint.request({'type': 'fault', 'command': {'action': 'arm_swap_reply'}})
        require(armed['phase'] == 'armed', 'mint funding barrier did not arm')
        run.ctl('n01', 'resume_renewals')

        def committed():
            status = run.mint.request({'type': 'fault', 'command': {'action': 'status'}})
            return status if status['phase'] == 'held' else None

        held = eventually('committed successor funding before guest power loss', committed, 45)
        require(held['generation'] == armed['generation'] and held['swaps'] == armed['swaps'] + 1,
                'successor funding did not reach one committed mint swap')
        pending = self.controllers()
        added = set(pending['n01']['funding']) - set(self.original['n01']['funding'])
        require(len(added) == 1, 'renewal did not reserve exactly one successor')
        self.funding_id, = added
        self.pending = pending
        self.check_pending()
        self.sdk_pending = self.sdk()
        admission = self.sdk_pending.get('admissions', {}).get(self.funding_id)
        opening = self.sdk_pending.get('openings', {}).get('r:' + self.funding_id)
        require((admission is None) != (opening is None), 'funding lacks one exact durable SDK stage')
        require(self.sdk_pending['open_requests'] == self.sdk_original['open_requests']
                and self.sdk_pending['funding'] == self.sdk_original['funding']
                and self.sdk_pending.get('pending_funding', {}) == self.sdk_original.get('pending_funding', {})
                and set(self.sdk_pending.get('admissions', {})) == ({self.funding_id} if admission else set())
                and self.sdk_pending.get('openings', {}) == {
                    **self.sdk_original.get('openings', {}),
                    **({'r:' + self.funding_id: opening} if opening else {})},
                'held reply changed acknowledged funding or introduced another SDK request')
        self.stage = 'wallet_preparation' if admission else 'channel_opening'
        if admission:
            require(admission['funding_started'] and admission['request']['client_request_id'] == self.funding_id,
                    'wallet preparation is not bound to the reserved request')
        else:
            require(opening['wallet_send']['operation_id']
                    and opening['request']['client_request_id'] == self.funding_id,
                    'channel opening is not bound to its saved wallet operation')
        # The paused mint operation must leave the original paid route usable.
        run.payloads()
        self.before_cut = eventually('paid progress with funding reply held',
            lambda: payment_progress(run.finances(), anchor), 30)
        self.pending = self.controllers()
        self.check_pending()
        sdk = self.sdk()
        require(all(sdk.get(key, {}) == self.sdk_pending.get(key, {}) for key in SDK_FIELDS),
                'pending SDK funding changed while its reply was held')
        current_barrier = run.mint.request({'type': 'fault', 'command': {'action': 'status'}})
        require(current_barrier['phase'] == 'held' and current_barrier['generation'] == held['generation']
                and current_barrier['swaps'] == held['swaps'], 'mint reply escaped before the power cut')
        run.evidence['power_cut'] = {
            'channel_id': self.old_id, 'funding_stage': self.stage,
            'mint_armed': armed, 'mint_held': current_barrier, 'at': time.time(),
            'guest_pid': run.guest.process.pid, 'finances_with_reply_held': self.before_cut,
            'pending_controller_sha256': {node: fingerprint(value) for node, value in self.pending.items()},
            'pending_sdk_sha256': fingerprint(self.sdk_pending),
        }
        run.save()
        run.guest.cut_power()
        released = run.mint.request({'type': 'fault', 'command': {
            'action': 'release', 'generation': held['generation']}})
        require(released['phase'] == 'released', 'mint funding reply remained held')

    def check_pending(self):
        for node, current in self.pending.items():
            original = self.original[node]
            for key in ('local', 'epoch', 'policy', 'outgoing', 'requested', 'buyer_settlements', 'seller_settlements'):
                require(current[key] == original[key], 'funding pause changed original authority or closed a channel')
            extra = {self.funding_id} if node == 'n01' else set()
            require(set(current['funding']) == set(original['funding']) | extra
                    and current['next_funding'] == original['next_funding'] + len(extra)
                    and all(current['funding'][key] == value for key, value in original['funding'].items()),
                    'funding pause replaced or duplicated an original intent')
            require(set(current['renewals']) == ({self.old_id} if node == 'n01' else set()),
                    'unexpected renewal while funding is paused')
        renewal = self.pending['n01']['renewals'][self.old_id]
        require(not renewal['completed'] and renewal['replacements'] is None
                and renewal['preopening']['funding_id'] == self.funding_id
                and self.pending['n01']['funding'][self.funding_id]['funded'] is None,
                'successor was activated before its committed funding reply')

    def recover(self):
        run = self.run
        stopped = self.controllers()
        for node in run.nodes:
            require(all(stopped[node][key] == self.pending[node][key] for key in CONTROLLER_FIELDS),
                    'guest lost durable replacement funding or original authority')
        recovered_sdk = self.sdk()
        require(all(recovered_sdk.get(key, {}) == self.sdk_pending.get(key, {}) for key in SDK_FIELDS),
                'guest lost the original pending SDK operation')
        lost = recovered_exposure(run.state_json('n02', 'seller/ledger.json'))
        for node in run.nodes:
            run.launch(node)
        eventually('recovered guest renewal line', run.ready, 90)

        def completed():
            record = run.state_json('n01', 'controller/controller.json')['renewals'].get(self.old_id)
            return record if record and record['completed'] else None

        eventually('automatic successor funding recovery', completed, 90)
        run.ctl('n01', 'pause_renewals')
        current = self.controllers()
        for node, state in current.items():
            require(all(state[key] == self.pending[node][key] for key in ('local', 'epoch', 'policy', 'next_funding'))
                    and set(state['funding']) == set(self.pending[node]['funding'])
                    and all(state['funding'][key] == value for key, value in self.original[node]['funding'].items()),
                    'recovery reset policy or duplicated original funding')
        pending_intent = self.pending['n01']['funding'][self.funding_id]
        successor = current['n01']['funding'][self.funding_id]
        require(all(successor[key] == value for key, value in pending_intent.items() if key != 'funded'),
                'recovery changed the reserved successor terms')
        funded = successor['funded']
        terms = funded['terms']
        self.new_id = terms['id']
        require(self.new_id not in self.owners and terms['buyer'] == self.old_terms['buyer']
                and terms['mint_url'] == self.old_terms['mint_url']
                and terms['capacity_sat'] == successor['capacity_sat'] == successor['max_wallet_debit_sat'] == 32
                and terms['grace_msat'] == successor['grace_msat'] == 8000
                and terms['expires_unix'] == successor['expires_unix']
                and terms['refund_after_unix'] == successor['refund_after_unix']
                and funded['wallet_cost'] == {'token_amount_sat': 32, 'wallet_debit_sat': 32, 'swap_fee_sat': 0},
                'recovered funding changed its authorized terms or cost')
        sdk = self.sdk()
        require(sdk['open_requests'] == {**self.sdk_original['open_requests'], self.funding_id: self.new_id}
                and not sdk.get('admissions') and not sdk.get('pending_funding')
                and set(sdk['funding']) == set(self.sdk_original['funding']) | {self.new_id}
                and all(sdk['funding'][key] == value for key, value in self.sdk_original['funding'].items())
                and set(sdk.get('openings', {})) == set(self.sdk_original.get('openings', {})) | {'r:' + self.funding_id}
                and all(sdk['openings'][key] == value for key, value in self.sdk_original.get('openings', {}).items())
                and sdk['openings']['r:' + self.funding_id]['channel_id'] == self.new_id,
                'recovery left unresolved or duplicated SDK funding')
        if self.stage == 'channel_opening':
            opening = self.sdk_pending['openings']['r:' + self.funding_id]
            require(self.new_id == opening['channel_id']
                    and funded['wallet_operation_id'] == opening['wallet_send']['operation_id'],
                    'recovery replaced the saved wallet operation or channel')
        restored = run.mint.request({'type': 'fault', 'command': {'action': 'status'}})
        require(restored['restores'] > run.evidence['power_cut']['mint_held']['restores'],
                'recovery did not restore a committed mint response')
        refund = verified_refund(current['n01'], self.old_id, self.old_terms)
        require(refund is not None, 'recovery did not return the original predecessor refund')
        self.owners[self.new_id] = 'n01'
        fixture = SettlementFixture(dict.fromkeys(run.nodes, 128), dict.fromkeys(run.nodes, 64), 32,
            self.owners, dict.fromkeys(self.owners, 'n02'), {self.old_id: refund})
        run.warmup()
        run.payloads()
        finances = eventually('recovered successor payment credit', lambda: (
            value if payments_credited(value := run.finances()) else None), 30)
        original_channels(run.nodes, finances, fixture=fixture)
        require(finances['n01']['signed'][self.new_id] >= 2
                and all(finances[node]['signed'].get(channel, -1) >= amount
                        for node, state in self.before_cut.items() for channel, amount in state['signed'].items()),
                'recovery lost prior authorization or failed to pay on the successor')
        for channel, expected in lost.items():
            usage = finances['n02']['seller_channels'][channel]
            require(usage['lost_msat'] == expected
                    and usage['submitted_msat'] + usage['lost_msat'] <= usage['reserved_msat']
                    <= min(32000, usage['paid_msat'] + 8000), 'recovery changed unbilled crash exposure')
        run.evidence['automatic_funding_recovery'] = {
            'original_channel_id': self.old_id, 'successor_channel_id': self.new_id,
            'funding_stage': self.stage, 'pending_intent_survived': True,
            'one_successor_only': True, 'predecessor_refund': refund, 'mint_restored': restored,
            'expected_lost_msat': lost, 'recovered_finances': finances,
        }
        run.save()
        return finances, fixture
