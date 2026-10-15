"""One automatic successor after the existing fragmented retirement releases."""

import json
from pathlib import Path
import time

from .paid_relay import eventually
from .paid_settlement import require, verified_refund
from .wifi_priority_checks import received, submitted
from .wifi_remote import digest
from .wifi_retirement_live import (CAPACITY, LIFETIME, OLD_CHANNELS,
                                   LiveRetirementRun, pending)


DUE_SAT = 2
RENEWAL = {'at_capacity_percent': 5, 'before_expiry_secs': 1}


def unchanged_pending(original, current):
    require(pending(original) and pending(current) == pending(original)
            and all(current[key] == original[key] for key in
                    ('local', 'epoch', 'policy', 'funding', 'next_funding',
                     'renewals', 'renewals_paused')),
            'pending retirement changed original funding or renewal authority')


class RenewalRetirementRun(LiveRetirementRun):
    completion_phase = 'due renewal deferred behind retirement, then one automatic successor delivered paid traffic'

    def profile_config(self, node):
        config = super().profile_config(node)
        if node is self.nodes['n01']:
            config['terms']['controller']['renewal'] = dict(RENEWAL)
        return config

    def exercise(self):
        self.renewal_resumed, self.renewal_before, self.due_required = False, None, False
        self.evidence['harness_sha256']['wifi_retirement_renewal.py'] = digest(Path(__file__).read_bytes())
        super().exercise()

    def active_ready(self):
        state = super().active_ready()
        require(state['payment_progress'][self.active]['authorized_sat'] < DUE_SAT,
                'warmup already made renewal due')
        self.renewal_resumed = True
        self.ctl('n01', 'resume_renewals', operation_timeout=8)
        return state

    def sample(self, shape, held):
        before = self.predecessor_selected() if held else None
        row = super().sample(shape, held)
        if held:
            row = {**row, 'predecessor': {'before': before, 'after': self.predecessor_selected()}}
        if self.due_required:
            require(row['authorized_sat'] >= DUE_SAT, 'automatic renewal is not due')
        return row

    def predecessor_selected(self):
        current = self.journal()
        unchanged_pending(self.renewal_before, current)
        state = self.ctl('n01', 'status', operation_timeout=8)
        terms, = [row['funded']['terms'] for row in self.renewal_before['funding'].values()
                  if row['funded'] and row['funded']['terms']['id'] == self.active]
        require(len(state['purchases']) == 1 and state['purchases'][0]['channel'] == terms
                and current['buyer_settlements'].get(self.active) is None
                and state['remaining_budget_sat'] == self.buyer_budget
                    - state['payment_progress'][self.active]['authorized_sat'],
                'due renewal replaced or settled its selected predecessor')
        return {'selected_channel': self.active, 'settlement': None,
                'funding_sha256': digest(json.dumps(current['funding'], sort_keys=True).encode()),
                'next_funding': current['next_funding'],
                'remaining_budget_sat': state['remaining_budget_sat'],
                'authorized_sat': state['payment_progress'][self.active]['authorized_sat']}

    def traffic(self, label, count, rate, *, held=False, release=False):
        if label == 'released':
            require(release and not held, 'renewal release lost its writer boundary')
            self.finish_renewal()
            return
        require(label == 'held' and held and not release, 'unexpected renewal workload')
        self.renewal_before = self.journal()
        self.evidence['fragmented']['renewal_original'] = self.renewal_before
        require(pending(self.renewal_before) and not self.renewal_before['renewals']
                and self.renewal_before['renewals_paused'] is False,
                'renewal was already started or paused before its due window')
        super().traffic(label, count, rate, held=True)
        state = self.caught_up()
        require(state['payment_progress'][self.active]['authorized_sat'] >= DUE_SAT,
                'automatic renewal is not due')
        # This second eight-second stream spans several upkeep scans after due.
        self.due_required = True
        try:
            super().traffic('renewal_due', 512, 64, held=True)
        finally:
            self.due_required = False
        require(len(self.evidence['fragmented']['renewal_due']['samples']) >= 3,
                'renewal lacked repeated due observations')
        self.save()

    def successor(self):
        before, current = self.renewal_before, self.journal()
        require(not pending(current) and all(current[key] == before[key]
                for key in ('local', 'epoch', 'policy')) and not current['renewals_paused'],
                'renewal changed lifetime authority or resumed before retirement')
        active_id, = [key for key, row in before['funding'].items()
                      if row['funded'] and row['funded']['terms']['id'] == self.active]
        original = before['funding'][active_id]
        require(current['funding'].get(active_id) == original,
                'renewal replaced its original predecessor funding')
        added = {key: row for key, row in current['funding'].items() if key not in before['funding']}
        require(len(added) <= 1 and current['next_funding'] == before['next_funding'] + len(added)
                and set(current['funding']) == {active_id} | set(added)
                and set(current['renewals']) <= {self.active},
                'renewal allocated more than one original successor')
        if not added:
            return None
        key, intent = next(iter(added.items()))
        require(intent['id'] == key and intent['capacity_sat'] == intent['max_wallet_debit_sat'] == CAPACITY
                and all(intent[field] == original[field]
                        for field in ('provider', 'receiver_pubkey_hex', 'grace_msat'))
                and intent['created_unix'] >= self.released_unix
                and intent['expires_unix'] == intent['created_unix'] + LIFETIME // 2
                and intent['refund_after_unix'] == intent['created_unix'] + LIFETIME,
                'successor changed its original capacity, provider or lifetime')
        authority = {name: value for name, value in intent.items() if name != 'funded'}
        if self.successor_authority is None:
            self.successor_authority = authority
        require(authority == self.successor_authority, 'successor reservation was replaced')
        renewal = current['renewals'].get(self.active) or {}
        require((renewal.get('preopening') or {}).get('funding_id') == key,
                'successor is not the original automatic renewal')
        if not renewal.get('completed'):
            return None
        state = self.ctl('n01', 'status', operation_timeout=8)
        purchase, = state['purchases']
        require(intent['funded'] and purchase['channel'] == intent['funded']['terms']
                and purchase['channel']['id'] != self.active,
                'completed renewal did not install the original successor')
        report = verified_refund(current, self.active, original['funded']['terms'])
        require(report and report['paid_sat'] == self.predecessor_paid
                and state['funding_budget'] == {
                    'wallet_debited_sat': (OLD_CHANNELS + 2) * CAPACITY,
                    'wallet_refunded_sat': (OLD_CHANNELS + 1) * CAPACITY - self.predecessor_paid,
                    'locked_sat': CAPACITY, 'exposure_sat': CAPACITY + self.predecessor_paid,
                    'pending_reserved_sat': 0}
                and state['remaining_budget_sat'] == self.buyer_budget - self.predecessor_paid,
                'renewal changed original refunds, capital or spending totals')
        return purchase, report, current

    def finish_renewal(self):
        state = self.caught_up()
        self.predecessor_paid = state['payment_progress'][self.active]['authorized_sat']
        unchanged_pending(self.renewal_before, self.journal())
        self.released_unix, self.successor_authority = int(time.time()), None
        self.release_holds(self.held_nodes)
        eventually('old history retired before automatic successor', self.old_retired, 120)
        purchase, report, journal = eventually('one original automatic successor completed', self.successor, 45)
        predecessor = self.active
        self.reports[predecessor] = report
        self.record_purchase(purchase)
        self.active = purchase['channel']['id']
        traffic = self.stream(64, 64, drain_seconds=10)
        shape = {'stream_id': traffic['sender']['stream_id'], 'packet_count': 64, 'payload_bytes': 1000}
        submitted(traffic['sender'], shape)
        received(traffic['receiver'], shape, self.nodes['n01'].npub, complete=True)
        final = self.caught_up()
        paid = final['payment_progress'][self.active]['authorized_sat']
        require(0 < paid < DUE_SAT and final['remaining_budget_sat']
                == self.buyer_budget - self.predecessor_paid - paid
                and self.journal()['next_funding'] == journal['next_funding'],
                'successor traffic changed lifetime authority or started another renewal')
        self.evidence['fragmented']['renewal'] = {
            'completed': True, 'previous': predecessor, 'successor': self.active,
            'funding_id': self.successor_authority['id'],
            'wallet_operation_id': self.intents[self.active]['funded']['wallet_operation_id'],
            'budget': final['funding_budget'], 'remaining_budget_sat': final['remaining_budget_sat'],
            'predecessor_report': report, 'successor_traffic': traffic}
        self.save()

    def close(self):
        if self.renewal_resumed:
            self.release_holds(self.held_nodes)
            self.ctl('n01', 'pause_renewals', operation_timeout=30)
        super().close()
