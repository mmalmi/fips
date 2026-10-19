"""Original receiver funding, measured paid traffic and financial closure."""

import json
import time
from types import SimpleNamespace

from . import wifi_probes as probes
from .cadence_workloads import stream
from . import wifi_receiver_custody as custody
from .paid_relay import eventually
from .paid_settlement import require, validate_report, verified_refund
from .wifi_priority_checks import received, submitted
from .wifi_retirement_live import maintenance_idle
from .wifi_receiver_window import exposure, measure

SETUP_LIFETIME = 1200


def caught_up(progress):
    return (not progress['in_flight'] and progress['acknowledged_msat'] is not None
            and progress['acknowledged_msat'] >= max(progress['authorized_sat'] * 1000,
                                                    progress['evidence_msat']))


class ReceiverWorkload:
    def journal(self, name='n02'):
        return self.state_json(name, 'controller/controller.json')

    def mutate(self, name, kind, channel=None, **fields):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            before = self.journal(name)
            if channel and channel in before['buyer_settlements']:
                settlement = before['buyer_settlements'][channel]
                if settlement['released'] and settlement['refunded']:
                    return {'settlements': [settlement['report']]}
                time.sleep(.1)
                continue
            if not maintenance_idle(before):
                time.sleep(.1)
                continue
            require(all(row['funded'] is not None for row in before['funding'].values()),
                    'never replay unresolved original funding')
            profile = self.participants()[name]
            errors = getattr(profile, 'owner', profile).output / 'last-error.txt'
            previous = errors.stat().st_mtime_ns if errors.exists() else None
            try:
                return self.ctl(name, kind, **fields)
            except RuntimeError:
                require(errors.exists() and errors.stat().st_mtime_ns != previous
                        and errors.read_bytes().strip() == b'fips-relay: controller history maintenance pending',
                        'control result uncertain; preserve original funding rather than replay')
                after = self.journal(name)
                require(all(before[key] == after[key] for key in ('local', 'epoch', 'policy', 'next_funding'))
                        and all(before['funding'].get(key) == row for key, row in after['funding'].items()),
                        'refused command changed original financial authority')
                self.evidence['receiver_history'].setdefault('backpressure', []).append({'node': name, 'kind': kind})
                self.save()
                time.sleep(.1)
        raise RuntimeError('original maintenance did not permit or finish the bounded command')

    def buy_route(self, owner, destination, provider, capacity):
        self.mutate(owner, 'buy', destination=self.participants()[destination].npub)
        purchase, = self.ctl(owner, 'status')['purchases']
        channel = purchase['channel']['id']
        intent, = [row for row in self.journal(owner)['funding'].values()
                   if row['funded'] and row['funded']['terms']['id'] == channel]
        lifetime = SETUP_LIFETIME if owner == 'n01' else 120
        require(channel not in self.intents and intent['funded']['terms'] == purchase['channel']
                and intent['capacity_sat'] == capacity
                and intent['max_wallet_debit_sat'] == capacity
                and intent['refund_after_unix'] == intent['created_unix'] + lifetime
                and intent['expires_unix'] == intent['created_unix'] + lifetime // 2
                and intent['funded']['wallet_cost']['wallet_debit_sat'] == capacity
                and intent['funded']['wallet_cost']['swap_fee_sat'] == 0,
                'original fixed-capacity funding changed')
        self.intents[channel], self.owners[channel], self.providers[channel] = intent, owner, provider
        self.evidence['receiver_history'].setdefault('channels', {})[channel] = {
            'owner': owner, 'provider': provider, 'capacity_sat': capacity,
            'created_unix': intent['created_unix'], 'refund_after_unix': intent['refund_after_unix'],
            'route_expires_unix': purchase['contract']['expires_unix']}
        self.save()
        return channel

    def payment(self, owner, channel):
        def ready():
            status = self.ctl(owner, 'status')
            return status if caught_up(status['payment_progress'][channel]) else None
        return eventually('original ordinary payment credited', ready, 30)

    def credit(self, provider, channel):
        ledger = self.state_json(provider, 'seller/ledger.json')['ledger']
        row, = [row for row in ledger['channels'] if row['terms']['id'] == channel]
        return row['usage']['paid_msat']

    def send(self, source, destination, count, size, rate):
        shape = probes.arm(self, source, destination, count, size, lifetime_secs=90)
        record = dict(source=source, destination=destination, shape=shape, rate_pps=rate)
        self.evidence['receiver_history'].setdefault('traffic', []).append(record)
        self.save()

        def complete():
            report = self.ctl(destination, 'status')['probe']
            record['receiver'] = report
            received(report, shape, self.participants()[source].npub, complete=True)
            return report

        try:
            record['sender'] = probes.send(self, source, destination, shape, rate,
                                          max_duration_secs=60, operation_timeout=75)
            submitted(record['sender'], shape)
            eventually('all original paid payloads delivered', complete, 10)
            return record
        except Exception as error:
            record['failure'] = str(error)
            self.record_probe_failure('receiver paid traffic', error, record)
            raise
        finally:
            self.save()

    def warmup_payment(self, owner, destination, channel):
        view = SimpleNamespace(ctl=self.ctl, nodes=self.participants())
        for _ in range(6):
            before = self.ctl(owner, 'status')['payment_progress'][channel]['evidence_msat']
            probe = stream(view, 1, 1, source=owner, destination=destination, drain_seconds=10)
            shape = dict(stream_id=probe['sender']['stream_id'], packet_count=1, payload_bytes=1000)
            submitted(probe['sender'], shape)
            received(probe['receiver'], shape, view.nodes[owner].npub)
            self.evidence['receiver_history'].setdefault('warmup', []).append(
                dict(source=owner, destination=destination, channel=channel, **probe))
            self.save()
            if probe['receiver']['unique_packets'] == 1:
                current = self.payment(owner, channel)
                unit = current['payment_progress'][channel]['evidence_msat'] - before
                require(unit > 0, 'ordinary warmup did not accrue paid evidence')
                return current, unit
        raise RuntimeError('native session warmup failed; preserve all separately billable attempts')

    def earn(self, owner, destination, channel, target, rate_pps=128):
        def evidence(state):
            return state['payment_progress'][channel]['evidence_msat']
        current, unit = self.warmup_payment(owner, destination, channel)
        for _ in range(100):
            signed = current['payment_progress'][channel]['authorized_sat']
            require(signed <= target and evidence(current) <= target * 1000, 'target payment overshot')
            if signed == target:
                return
            count = min(1024, ((target - 1) * 1000 + 1 - evidence(current)) // unit)
            self.send(owner, destination, max(1, count), 1000 if count else 40, rate_pps)
            current = self.payment(owner, channel)
        raise RuntimeError('ordinary paid traffic did not reach its exact target')

    def settle_channel(self, channel, paid=None):
        owner, provider = self.owners[channel], self.providers[channel]
        self.mutate(owner, 'settle', channel=channel)
        terms = self.intents[channel]['funded']['terms']
        report = eventually('original refund committed', lambda:
                            verified_refund(self.journal(owner), channel, terms), 120)
        checked = validate_report(report, capacity_sat=terms['capacity_sat'])
        def released():
            seller = self.journal(provider)['seller_settlements'].get(channel)
            return seller if seller and seller['released'] else None
        seller = eventually('original provider settlement released', released, 120)
        require(validate_report(seller['report'], capacity_sat=terms['capacity_sat']) == checked
                and seller['report']['signed_sat'] == checked['paid_sat']
                and (paid is None or checked['paid_sat'] == paid)
                and (channel not in self.reports or self.reports[channel] == checked),
                'original settled payment or provider payout differs')
        self.reports[channel] = checked
        self.evidence['receiver_history']['settlements'] = self.reports.copy()
        self.save()

    def retired_prefix(self):
        def done():
            journal = self.journal()
            return maintenance_idle(journal) and all(row['funded']['terms']['id'] not in self.old
                                                     for row in journal['funding'].values())
        eventually('ordinary original sender prefix retired', done, 180)

    def capture_inputs(self, channel, label):
        archive = self.stop_snapshot('n02', label)
        found, operation = custody.inputs(archive, self.intents[channel], self.originals)
        custody.unchanged(archive, self.retained_history)
        self.restart('n02')
        return found, operation

    def receiver_case(self):
        self.incoming = self.buy_route('n01', 'n03', 'n02', 960)
        deadline = self.intents[self.incoming]['refund_after_unix']
        self.earn('n01', 'n03', self.incoming, 959, rate_pps=32)
        self.settle_channel(self.incoming, 959)
        archive = self.stop_snapshot('n02', 'original-payout')
        custody.unchanged(archive, self.retained_history)
        self.originals = custody.payout(archive, self.incoming, self.retained_history)
        self.restart('n02')
        for _ in range(2):
            for _ in range(14):
                channel = self.buy_route('n02', 'destination', 'n03', 32)
                inputs, operation = self.capture_inputs(channel, 'original-outgoing')
                require(not inputs & self.old_inputs and operation not in self.operations,
                        'outgoing spend reused an original payout coin')
                self.old_inputs.update(inputs)
                self.operations.add(operation)
                self.earn('n02', 'destination', channel, 32)
                self.settle_channel(channel, 32)
                self.old.add(channel)
                require(len(self.journal()['funding']) <= 16, 'retained controller channel limit exceeded')
            self.retired_prefix()
            archive = self.stop_snapshot('n02', 'retired-outgoing-prefix')
            custody.released_sends(archive, self.operations)
            require(len(custody.original_states(archive, self.originals)) == 959,
                    'sender retirement released still receiver-owned originals')
            custody.unchanged(archive, self.retained_history)
            self.restart('n02')
        require(len(self.old) == 28 and len(self.old_inputs) == 896 and time.time() < deadline - 40,
                'preparation did not preserve original receiver owner and deadline')
        # Funding lasts 120 seconds, but forwarding lasts only 60. Preserve
        # enough service time after the incoming deadline for the live window.
        self.until(deadline - 10)
        self.guard = self.buy_route('n02', 'destination', 'n03', 32)
        archive = self.stop_snapshot('n02', 'before-transit')
        self.guard_inputs, guard_operation = custody.inputs(archive, self.intents[self.guard], self.originals)
        require(not self.guard_inputs & self.old_inputs, 'guard reused an earlier payout coin')
        self.operations.add(guard_operation)
        before = custody.original_states(archive, self.originals)
        self.unspent = {key for key, state in before.items() if state == 'UNSPENT'}
        require(len(before) == 959 and len(self.unspent) == 31
                and all(before[key] == 'SPENT' for key in self.old_inputs | self.guard_inputs),
                'original spent896/guard32/unspent31 partition differs')
        custody.mint_states(self.mint_url, before)
        custody.unchanged(archive, self.retained_history)
        self.evidence['receiver_history']['history_size_before_transit'] = custody.counts(archive)
        self.evidence['receiver_history']['proof_slots_before_transit'] = custody.slots(archive)
        self.restart('n02')
        self.transit = self.buy_route('source', 'destination', 'n02', 64)
        self.check_transit_opening()
        self.evidence['receiver_history']['prepared'] = {
            'originals': 959, 'release_batches': 8, 'released_spent': 896, 'guard_spent': 32,
            'retained_unspent': 31, 'wallet_debited_sat': self.ctl('n02', 'status')['funding_budget']['wallet_debited_sat']}
        require(self.evidence['receiver_history']['prepared']['wallet_debited_sat'] == 928,
                'original receiver funding budget changed')
        before_warm = [self.ctl('source', 'status'), self.ctl('n02', 'status')]
        self.send('source', 'destination', 1, 1000, 1)
        warm = [self.payment('source', self.transit), self.payment('n02', self.guard)]
        self.evidence['receiver_history']['exposure'] = exposure(before_warm, warm, warm,
                                                               [self.transit, self.guard], 92)
        original_sale = self.journal()['seller_settlements'][self.incoming]
        require(original_sale['released']
                and validate_report(original_sale['report'], capacity_sat=960) == self.reports[self.incoming]
                and original_sale['report']['signed_sat'] == self.reports[self.incoming]['paid_sat'],
                'original receiver settlement is not durably released')
        self.held_nodes.append('n02')
        self.nodes['n02'].hold_wallet(self.args.sqlite_hold, seconds=150)
        require(time.time() < deadline, 'writer hold began after original retirement deadline')
        self.until(deadline + 3)
        eligible = self.journal()
        require(eligible['seller_settlements'].get(self.incoming) == original_sale
                and all(row['channel']['id'] != self.incoming for row in eligible['incoming'].values())
                and custody.live(self.nodes['n02'], self.originals) == before,
                'held wallet lost its original eligible owner or payout')
        credits = [self.credit('n02', self.transit), self.credit('n03', self.guard)]
        self.evidence['receiver_history']['held_probe'] = self.send('source', 'destination', 8, 1000, 3)
        held = [self.payment('source', self.transit), self.payment('n02', self.guard)]
        held_credits = [self.credit('n02', self.transit), self.credit('n03', self.guard)]
        require(self.nodes['n02'].held() and self.journal()['seller_settlements'].get(self.incoming) == original_sale
                and custody.live(self.nodes['n02'], self.originals) == before,
                'held traffic changed original pending custody')
        for index, channel in enumerate((self.transit, self.guard)):
            require(held[index]['payment_progress'][channel]['authorized_sat']
                    > warm[index]['payment_progress'][channel]['authorized_sat']
                    and held_credits[index] > credits[index], 'held paid progress is not whole-sat credited')
        self.evidence['receiver_history']['live_exposure'] = exposure(before_warm, warm, held,
                                                                    [self.transit, self.guard], 84)
        require(all(time.time() + 37 < self.intents[channel]['expires_unix']
                    for channel in (self.guard, self.transit)),
                'the full 35-second observation must fit the original forwarding terms')
        result = measure(self, held, held_credits)
        self.evidence['receiver_history']['live'] = result
        self.save()
        # Recover all original obligations even when a progress gate fails.
        self.settle_channel(self.transit)
        self.settle_channel(self.guard)
        self.until(self.intents[self.guard]['refund_after_unix'] + 1)
        self.old.add(self.guard)
        self.retired_prefix()
        archive = self.stop_snapshot('n02', 'final-original-custody')
        custody.released_sends(archive, self.operations)
        require(custody.original_states(archive, self.originals)
                == dict.fromkeys(self.unspent, 'UNSPENT'), 'guard cleanup changed original unspent custody')
        custody.unchanged(archive, self.retained_history)
        self.restart('n02')
        for field in ('all_counters_advanced', 'within_limit', 'traffic_covers_cleanup'):
            require(result['progress'][field], 'receiver progress acceptance failed: ' + field)

    def check_transit_opening(self):
        intent = self.intents[self.transit]
        route, = [row for row in self.journal('source')['outgoing'].values()
                  if row['purchase']['channel']['id'] == self.transit]
        payment = intent['funded']['opening']
        proofs = payment['funding_proofs']
        require(len(proofs) == 64 and all(proof['amount'] == 1 for proof in proofs),
                'independent transit opening must use64 original one-sat proofs')
        request = dict(type='accept', offer_id=route['offer']['id'], channel=intent['funded']['terms'],
                       payment=payment, replaces=None)
        size = len(json.dumps(request, separators=(',', ':')).encode())
        require(size <= 64 * 1024, 'original transit opening exceeds the64KiB wire bound')
        self.evidence['receiver_history']['transit_opening_bytes'] = size

    def close_originals(self):
        # Resume only the known profiles after a stopped observation; never
        # create a replacement account or a new purchase during recovery.
        for name in list(self.stopped_names):
            self.participants()[name].start()
            self.stopped_names.remove(name)
            eventually('original profile available for financial recovery', lambda: self.ctl(name, 'status'), 60)
        for name in self.participants():
            journal = self.journal(name)
            for row in journal['funding'].values():
                require(row['funded'] and self.intents.get(row['funded']['terms']['id']) == row
                        and self.owners[row['funded']['terms']['id']] == name,
                        'unknown original funding requires deliberate recovery; preserve evidence')
        for channel in self.intents:
            if channel not in self.reports:
                self.settle_channel(channel)
        require(set(self.reports) == set(self.intents), 'original receiver channels remain unsettled')
        self.until(max((row['refund_after_unix'] for row in self.intents.values()), default=0) + 1)
        eventually('all original channel owners retired before collection', lambda:
            all(maintenance_idle(j := self.journal(name)) and not j['funding']
                and not j['buyer_settlements'] and not j['seller_settlements']
                for name in self.participants()), 240)
        for name in self.participants():
            intents = [row for channel, row in self.intents.items() if self.owners[channel] == name]
            paid = sum(row['paid_sat'] for channel, row in self.reports.items() if self.owners[channel] == name)
            debit = sum(row['capacity_sat'] for row in intents)
            status = self.ctl(name, 'status')
            budget = status['funding_budget']
            require(budget['wallet_debited_sat'] == debit and budget['wallet_refunded_sat'] == debit - paid
                    and budget['pending_reserved_sat'] == budget['locked_sat'] == 0
                    and budget['exposure_sat'] == paid and status['remaining_budget_sat'] == self.budget(name) - paid,
                    'receiver cleanup reset original lifetime funding or spending')
