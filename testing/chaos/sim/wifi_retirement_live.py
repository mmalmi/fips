"""Paid forwarding during retirement of real, fragmented channel refunds."""

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import signal
import time

from . import wifi_probes as probes
from .paid_relay import eventually
from .paid_settlement import (SettlementFixture, collect_settled_wallets, require,
                              validate_report, verified_refund)
from .wifi_priority_checks import received, submitted
from .wifi_remote import digest
from .wifi_retirement import RetirementRun


OLD_CHANNELS = 15
CAPACITY = 32
LIFETIME = 1320
MAX_SPREAD = 300
ACTIVE_LEAD = 60
HOLD_LEAD = 15
HOLD_SECONDS = MAX_SPREAD + 120
QUOTE_UNITS = 6 * 1024 * 1024
WALLET_LIMIT = 128
RELEASE_WINDOW = 240
RELEASE_MARGIN = 60
RUN_WINDOW = 2400


def pending(journal):
    return ((journal.get('history') or {}).get('channels') or {}).get('pending')


def maintenance_idle(journal):
    history = journal.get('history') or {}
    return not (history.get('pending') or pending(journal)
                or (history.get('seller') or {}).get('pending'))


def overlap(samples):
    """Signing and credit may advance on separate samples of one pending plan."""
    first = None
    for sample in samples:
        if not sample['plan']:
            first = None
        elif first is None or first['plan'] != sample['plan']:
            first = sample
        elif all(sample[key] > first[key]
                 for key in ('authorized_sat', 'credited_msat', 'delivered')):
            return True
    return False


def deadlines(intents, now):
    values = [row['refund_after_unix'] for row in intents.values()]
    first, last = min(values), max(values)
    require(last - first <= MAX_SPREAD,
            'device setup exceeded the bounded old-channel deadline spread')
    require(now < first - 100, 'fragmented setup consumed the active-channel preparation window')
    return first, last


def refund_count(client, channels):
    refunds = client['settled_refunds']
    require(set(refunds) == set(channels), 'refund store differs from the original channels')
    count = 0
    for row in refunds.values():
        coins = json.loads(row['proofs_json'])
        require(len(coins) == CAPACITY and all(coin['amount'] == 1 for coin in coins),
                'fragmentation requires original one-sat refund coins')
        count += len(coins)
    return count


class LiveRetirementRun(RetirementRun):
    quote_max_units = QUOTE_UNITS
    completion_phase = 'new paid delivery overlapped the original pending cleanup before and after release'

    @property
    def buyer_budget(self):
        return 256

    def create_mint(self, args):
        require(getattr(args, 'mint_host', None), 'fragmented retirement requires --mint-host')
        mint = super().create_mint(args)
        mint.settings['fragmented_channel_keyset'] = True
        return mint

    def profile_config(self, node):
        config = super().profile_config(node)
        config['terms'].update(billing='forwarding_data', fee_msat_per_kib=4,
                               max_rate_msat_per_kib=4, quote_max_units=QUOTE_UNITS,
                               quote_lifetime_secs=LIFETIME // 2,
                               wallet_capacity_bytes=64 * 1024 * 1024)
        config['terms']['controller'].update(channel_lifetime_secs=LIFETIME,
                                             channel_capacity_sat=CAPACITY,
                                             max_wallet_spend_sat=WALLET_LIMIT,
                                             max_funding_overhead_sat=0)
        # This disposable mint is owned by the fixture, unlike a public mint.
        config['funding_request_budget'] = {'burst': 128, 'requests_per_minute': 60_000}
        return config

    def journal(self, name='n01'):
        return self.state_json(name, 'controller/controller.json')

    def until(self, unix):
        while time.time() < unix:
            self.monitor.check()
            time.sleep(max(0, min(1, unix - time.time())))

    def buy(self):
        self.ctl('n01', 'buy', destination=self.nodes['n03'].npub)
        purchase, = self.ctl('n01', 'status')['purchases']
        return self.record_purchase(purchase)

    def record_purchase(self, purchase):
        channel = purchase['channel']['id']
        require(channel not in self.intents, 'purchase reused an original channel')
        journal = self.journal()
        intent, = [row for row in journal['funding'].values()
                   if row['funded'] and row['funded']['terms']['id'] == channel]
        require(intent['funded']['terms'] == purchase['channel']
                and intent['capacity_sat'] == CAPACITY
                and intent['funded']['wallet_cost']['wallet_debit_sat'] == CAPACITY
                and intent['funded']['wallet_cost']['swap_fee_sat'] == 0,
                'ordinary funding changed the fixed zero-fee capacity')
        self.intents[channel] = intent
        self.evidence['fragmented']['funded_channels'] = len(self.intents)
        self.save()
        return purchase

    def settle_old(self, purchase):
        channel = purchase['channel']['id']
        self.ctl('n01', 'settle')
        report = verified_refund(self.journal(), channel, purchase['channel'])
        require(report and report['paid_sat'] == 0 and report['refunded_sat'] == CAPACITY,
                'unused predecessor did not return its original capacity')
        seller = self.journal('n02')['seller_settlements'][channel]
        require(seller['released'] and validate_report(seller['report']) == report,
                'predecessor provider has not acknowledged the original settlement')
        self.reports[channel] = report
        self.evidence['fragmented']['old_reports'] = self.reports.copy()
        self.save()
        self.until(self.intents[channel]['created_unix'] + 1)

    def caught_up(self):
        def ready():
            status = self.ctl('n01', 'status', operation_timeout=8)
            progress = status['payment_progress'][self.active]
            ack = progress['acknowledged_msat']
            return status if (not progress['in_flight'] and ack is not None
                              and ack >= max(progress['authorized_sat'] * 1000,
                                             progress['evidence_msat'])) else None
        return eventually('active ordinary payment acknowledged', ready, 30)

    def active_ready(self):
        return self.caught_up()

    def sample(self, shape, held):
        if held:
            require(self.nodes['n01'].held(), 'external writer ended before the sample')
        first = self.journal()
        before = pending(first)
        status = self.ctl('n01', 'status', operation_timeout=8)
        progress = status['payment_progress'][self.active]
        ledger = self.state_json('n02', 'seller/ledger.json')['ledger']
        sale, = [row for row in ledger['channels'] if row['terms']['id'] == self.active]
        receiver = probes.receive(self, 'n01', 'n03', shape)
        last = self.journal()
        after = pending(last)
        if held:
            require(self.nodes['n01'].held(), 'external writer ended during the sample')
        for journal in (first, last):
            require(journal['policy']['max_wallet_spend_sat'] == WALLET_LIMIT
                    and any(row == self.intents[self.active] for row in journal['funding'].values()),
                    'traffic replaced the original active channel or spending policy')
        require(status['funding_budget'] == {
                    'wallet_debited_sat': (OLD_CHANNELS + 1) * CAPACITY,
                    'wallet_refunded_sat': OLD_CHANNELS * CAPACITY,
                    'locked_sat': CAPACITY, 'exposure_sat': CAPACITY, 'pending_reserved_sat': 0}
                and progress['authorized_sat'] <= CAPACITY
                and sale['usage']['paid_msat'] <= CAPACITY * 1000,
                'traffic changed original funding or exceeded the active payment capacity')
        return {'plan': digest(json.dumps(before, sort_keys=True).encode())
                if before and before == after else None,
                'through': before['after']['through'] if before else None,
                'authorized_sat': progress['authorized_sat'],
                'credited_msat': sale['usage']['paid_msat'],
                'delivered': receiver['unique_packets'], 'payment': progress}

    def traffic(self, label, count, rate, *, held=False, release=False):
        shape = probes.arm(self, 'n01', 'n03', count, 1000, lifetime_secs=90)
        row = {'shape': shape, 'samples': [], 'passed': False}
        self.evidence['fragmented'][label] = row
        if release:
            row['pre_release_payment'] = self.caught_up()['payment_progress'][self.active]
            self.release_holds(self.held_nodes)
        row['started'] = time.monotonic()
        row['samples'].append(self.sample(shape, held))
        if release:
            authorized = row['pre_release_payment']['authorized_sat']
            require(row['samples'][0]['authorized_sat'] == authorized
                    and row['samples'][0]['credited_msat'] >= authorized * 1000,
                    'post-release baseline still has uncredited held-window payment')
        with ThreadPoolExecutor(max_workers=1) as pool:
            sending = pool.submit(probes.send, self, 'n01', 'n03', shape, rate,
                                  max_duration_secs=60, operation_timeout=75)
            try:
                while not sending.done():
                    row['samples'].append(self.sample(shape, held))
                    self.save()
                    time.sleep(.1)
            finally:
                # Drain this exact finite send even after a failed observation;
                # replaying payloads would hide a delivery failure.
                try:
                    row['sender'] = sending.result(timeout=75)
                    row['receiver'] = eventually('all original payloads delivered', lambda:
                        probes.receive(self, 'n01', 'n03', shape, complete=True), 10)
                finally:
                    self.save()
        submitted(row['sender'], shape)
        self.caught_up()
        row['samples'].append(self.sample(shape, held))
        row['passed'] = overlap(row['samples'])
        row['elapsed_seconds'] = time.monotonic() - row['started']
        self.save()
        require(row['passed'], 'fresh payment and delivery did not overlap one pending retirement plan')

    def old_retired(self):
        source, seller = self.journal(), self.journal('n02')
        if not maintenance_idle(source) or not maintenance_idle(seller):
            return None
        retained = {row['funded']['terms']['id'] for row in source['funding'].values()
                    if row['funded']}
        history = seller.get('history') or {}
        if (retained & self.old or set(seller['seller_settlements']) & self.old
                or set(history.get('sellers', {})) & self.old):
            return None
        require(source['history']['channels']['totals']['channels'] == OLD_CHANNELS,
                'sender retirement lost the original channel count')
        totals = history['seller']['totals']
        require(totals['accounting']['channels'] == OLD_CHANNELS
                and sum(row['channels'] for row in totals['receiver']['totals']) == OLD_CHANNELS,
                'provider retirement did not finish the original receiver handoff')
        return source

    def close(self):
        self.release_holds(self.held_nodes)
        if self.retirement_started:
            eventually('original sender and seller retirement finished', self.old_retired, 240)
        else:
            eventually('pending maintenance finished before settlement', lambda:
                       all(maintenance_idle(self.journal(name)) for name in self.nodes), 240)
        # Reject an unknown or unfinished opening rather than issuing a replacement.
        for name in self.nodes:
            journal = self.journal(name)
            for intent in journal['funding'].values():
                require(name == 'n01' and intent['funded'] is not None
                        and self.intents.get(intent['funded']['terms']['id']) == intent,
                        'collection encountered unresolved or unknown original funding')
            for report in self.ctl(name, 'settle')['settlements']:
                channel = report['channel_id']
                require(name == 'n01' and channel in self.intents,
                        'settlement changed original channel ownership')
                checked = validate_report(report)
                require(channel not in self.reports or self.reports[channel] == checked,
                        'settlement changed an already verified refund')
                self.reports[channel] = checked
        require(set(self.reports) == set(self.intents), 'an original channel remains unsettled')
        source = self.journal()
        for channel, intent in self.intents.items():
            if channel not in source['buyer_settlements']:
                require(channel in self.old and self.retirement_started,
                        'missing original settlement has no retirement evidence')
                continue
            require(verified_refund(source, channel, intent['funded']['terms']) == self.reports[channel],
                    'original refund lacks durable wallet confirmation')
            seller = self.journal('n02')['seller_settlements'][channel]
            require(seller['released'] and validate_report(seller['report']) == self.reports[channel],
                    'provider settlement differs from the verified buyer refund')
        status = self.ctl('n01', 'status')
        paid = sum(report['paid_sat'] for report in self.reports.values())
        budget = status['funding_budget']
        require(budget['wallet_debited_sat'] == len(self.intents) * CAPACITY
                and budget['wallet_refunded_sat'] == len(self.intents) * CAPACITY - paid
                and budget['locked_sat'] == budget['pending_reserved_sat'] == 0
                and budget['exposure_sat'] == paid
                and status['remaining_budget_sat'] == self.buyer_budget - paid,
                'settlement or retirement changed lifetime capital/spending bounds')
        owners = dict.fromkeys(self.intents, 'n01')
        fixture = SettlementFixture(dict.fromkeys(self.nodes, 128),
                                    dict.fromkeys(self.nodes, self.buyer_budget), CAPACITY,
                                    owners, dict.fromkeys(self.intents, 'n02'))
        collect_settled_wallets(self, self.finances(), self.reports, owners, self.mint_url,
            execute=self.account_execute, stop=lambda name: self.nodes[name].stop(),
            export_path=lambda name, relative: self.nodes[name].state + '/' + relative,
            fixture=fixture, max_export_sat=CAPACITY)
        self.phase('all 384 original test sats collected after fragmented-history cleanup')

    def exercise(self):
        self.intents, self.reports, self.old, self.held_nodes = {}, {}, set(), []
        self.retirement_started = False
        self.evidence['harness_sha256']['wifi_retirement_live.py'] = digest(Path(__file__).read_bytes())
        self.evidence.update(sqlite_hold_sha256=digest(self.args.sqlite_hold.read_bytes()),
                             physical_power_loss=False, fragmented={})
        try:
            self.form_line()
            for _ in range(OLD_CHANNELS):
                purchase = self.buy()
                self.old.add(purchase['channel']['id'])
                self.settle_old(purchase)
            first, last = deadlines(self.intents, time.time())
            raw = self.nodes['n01'].remote(['cat', self.nodes['n01'].state + '/wallet/spilman-client.json'])
            coins = refund_count(json.loads(raw), self.old)
            require(coins == 480 and 1024 * 1024 < len(raw) <= 32 * 1024 * 1024,
                    'original fragmented history does not meet the bounded workload')
            self.evidence['fragmented']['prepared'] = {
                'refund_coins': coins, 'client_bytes': len(raw), 'client_sha256': digest(raw),
                'first_refund_deadline': first, 'last_refund_deadline': last}
            self.phase('480 real refunded coins retained before device expiry')
            self.until(first - ACTIVE_LEAD)
            purchase = self.buy()
            self.active = purchase['channel']['id']
            contract = purchase['contract']
            require(contract['expires_unix'] >= last + RELEASE_WINDOW + RELEASE_MARGIN
                    and contract['max_units'] == QUOTE_UNITS
                    and contract['price'] == {'msat': 4, 'per_bytes': 1024},
                    'active quote lacks the required lifetime or paid traffic capacity')
            warmup = self.stream(1, 1, drain_seconds=10)
            shape = {'stream_id': warmup['sender']['stream_id'], 'packet_count': 1, 'payload_bytes': 1000}
            submitted(warmup['sender'], shape)
            received(warmup['receiver'], shape, self.nodes['n01'].npub, complete=True)
            self.active_ready()
            self.evidence['fragmented']['warmup'] = warmup
            require(time.time() < first - HOLD_LEAD, 'active session establishment consumed the hold margin')
            self.until(first - HOLD_LEAD)
            self.held_nodes.append('n01')
            self.nodes['n01'].hold_wallet(self.args.sqlite_hold, HOLD_SECONDS)
            eventually('sender retirement durably pending behind its writer', self.pending_sender, 35)
            self.retirement_started = True
            self.traffic('held', 512, 64, held=True)
            self.until(last + 1)
            require(self.nodes['n01'].held(), 'writer deadline ended before the controlled release')
            deadline = time.monotonic() + RELEASE_WINDOW
            self.traffic('released', 4096, 128, release=True)
            remaining = deadline - time.monotonic()
            require(remaining > 0, 'post-release traffic exceeded the active cleanup window')
            after = eventually('old sender and provider history retired', self.old_retired, remaining)
            require(time.monotonic() < deadline, 'post-release cleanup exceeded its bounded window')
            require(any(row == self.intents[self.active] for row in after['funding'].values()),
                    'cleanup replaced or changed the active funded channel')
            self.verify_shortcuts()
            self.phase(self.completion_phase)
        except Exception as error:
            self.evidence['fragmented']['failure'] = str(error)
            self.save()
            raise
        finally:
            signal.alarm(0)
            try:
                self.close()
            except Exception as error:
                self.evidence['collection_failure'] = str(error)
                self.save()
                raise
