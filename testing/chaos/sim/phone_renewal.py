"""Automatic expiry renewal across an Android Wi-Fi reconnect and delayed close.

Uses the ordinary customer policy and existing four-account transit fixture. Only
the isolated mint's selected committed reply is delayed; no Buy or Start follows
renewal. This is a controlled LAN reconnect, not arbitrary mobile mesh coverage.
"""
import hashlib
import json
from pathlib import Path
import time

from . import phone_network
from .paid_finances import payments_credited
from .paid_phone_transit import PhoneTransitRun
from .paid_relay import eventually
from .paid_settlement import require
from .phone_customer import save
from .phone_diagnostics import control, resources
from .phone_outage import processes
from .stream_probe import duplex, validate_stream


def input_hashes(wallet, channel):
    proofs = json.loads(wallet['funding'][channel]['funding_proofs_json'])
    result = [hashlib.sha256(proof['secret'].encode()).hexdigest() for proof in proofs]
    require(1 <= len(result) <= 128 and len(set(result)) == len(result),
            'selected channel has invalid funding inputs')
    return result


def successor(state, original):
    purchases = state['purchases']
    if len(purchases) != 1 or purchases[0]['channel']['id'] == original['channel']['id']:
        return None
    replacement = purchases[0]
    require(replacement['provider'] == original['provider']
            and replacement['channel']['capacity_sat'] == 32
            and replacement['contract']['expires_unix'] > original['contract']['expires_unix']
            and all(replacement['contract'][key] == original['contract'][key]
                    for key in ('destination', 'next_hop', 'price', 'max_units', 'billing')),
            'successor changed paid-route authority')
    return replacement


class PhoneRenewalRun(PhoneTransitRun):
    def __init__(self, args):
        require(not any(getattr(args, flag, False) for flag in
                        ('screen_off', 'sustained_transit', 'forced_idle', 'phone_outage', 'phone_restart')),
                'renewal is a separate transit workload')
        super().__init__(args)
        self.settlement_channel_counts = {'n01': 1, 'phone': 2, 'n02': 1, 'n03': 2}
        self.evidence['phone_renewal'] = {'passed': False, 'physical_wifi_reconnect': True}
        for name in ('phone_renewal.py', 'phone_network.py', 'phone_diagnostics.py'):
            self.evidence['harness_sha256'][name] = hashlib.sha256(
                Path(__file__).with_name(name).read_bytes()).hexdigest()
        self.fault_generation = None

    def profile_config(self, node):
        config = super().profile_config(node)
        if node is self.nodes['n02']:
            config['terms']['quote_lifetime_secs'] = 180
        if node is self.nodes['n03']:
            config['terms']['controller']['renewal'] = {
                'at_capacity_percent': 80, 'before_expiry_secs': 30,
            }
        return config

    def before_funding(self):
        # Verify the diagnostic path before issuing any of this trial's money.
        self.phone.account_file('wallet/spilman-client.json')

    def fault(self, action, **fields):
        return self.mint.request({'type': 'fault', 'command': {'action': action, **fields}})

    def held(self, original):
        observed = self.fault('status')
        require(observed['generation'] == self.fault_generation and observed['phase'] == 'held',
                'selected committed mint reply is not held')
        buyer = self.accounts.state_json('phone', 'controller/controller.json')
        seller = self.accounts.state_json('n02', 'controller/controller.json')
        require(not buyer['buyer_settlements'][original]['refunded']
                and not buyer['renewals'][original]['completed']
                and seller['seller_settlements'][original]['report'] is None,
                'original channel closed before the overlap observation')
        return observed

    def release(self):
        if self.fault_generation is None:
            return
        state = self.fault('status')
        require(state['generation'] == self.fault_generation, 'mint barrier ownership changed')
        if state['phase'] == 'held':
            state = self.fault('release', generation=self.fault_generation)
        require(state['phase'] == 'released', 'retain unresolved armed mint for recovery')
        self.evidence['phone_renewal']['released'] = state
        self.fault_generation = None
        self.save()

    def fresh_stream(self, row):
        row['before'] = resources(self.phone)
        self.evidence['windows'].append(row)
        def observe():
            require(self.topology() is not None, 'transit topology changed during transfer')
            return {'line_verified': True, **self.screen('background')}
        duplex(self, row, label='renewal-reconnect', count=1024 * 1024,
               duration=12, rate=256 * 1024, observe=observe)
        row['after'] = resources(self.phone)
        require(row['before']['process'] == row['after']['process'], 'phone process changed')
        for name, result in row['results'].items():
            validate_stream(result, row['shapes'][name])
        row['passed'] = True
        self.save()

    def overlap(self, original, before):
        row = self.evidence['phone_renewal']
        old = original['phone']['channel']['id']
        selected = input_hashes(self.phone.account_file('wallet/spilman-client.json'), old)
        armed = self.once('arm-selected-close', lambda: self.fault('arm_swap_reply', input_hashes=selected))
        require(armed['phase'] == 'armed', 'mint did not arm selected channel close')
        self.fault_generation = armed['generation']
        row.update(armed=armed, original_channel=old, before_processes=processes(self))
        self.save()
        def committed():
            self.monitor.check()
            state = self.fault('status')
            require(state['generation'] == self.fault_generation, 'mint barrier ownership changed')
            return state if state['phase'] == 'held' else None
        row['committed'] = eventually('automatic phone close commits', committed, 150)
        row['held_at'] = time.time()
        require(original['phone']['contract']['expires_unix'] - 30 <= time.time()
                < original['phone']['contract']['expires_unix'], 'renewal was not near expiry')
        replacements = {}
        for name in ('phone', 'n03'):
            def ready(name=name):
                state = self.accounts.ctl(name, 'status')
                replacement = successor(state, original[name])
                if replacement:
                    replacements[name] = replacement
                    return state
                return None
            state = eventually('automatic funded successor at ' + name, ready, 10)
            if name == 'phone':
                row['successor_status'] = state
                require(state['funding_budget'] == {
                    'locked_sat': 64, 'pending_reserved_sat': 0,
                    'wallet_debited_sat': 64, 'wallet_refunded_sat': 0,
                    'exposure_sat': 64,
                }, 'phone renewed outside its original capital bound')
        row['successors'] = replacements
        self.held(old)
        phone_network.reconnect(self, row)
        eventually('original adjacency after Android reconnect', self.topology, 15)
        self.fresh_stream({'mode': 'background-renewal-reconnect', 'unpaid': False})
        after = control(self.phone, 'status')
        next_id = replacements['phone']['channel']['id']
        prior = row['successor_status']['payment_progress'].get(next_id, {})
        progress = after['payment_progress'][next_id]
        require(after['purchases'] == [replacements['phone']]
                and after['funding_budget'] == row['successor_status']['funding_budget'],
                'reconnect changed the successor or capital reservations')
        for key in ('evidence_msat', 'authorized_sat', 'acknowledged_msat'):
            require(progress[key] > prior.get(key, 0), 'successor payment failed to advance')
        sales = self.accounts.state_json('n02', 'seller/ledger.json')['ledger']['channels']
        sale = next(s for s in sales if s['terms']['id'] == next_id)
        require(sale['usage']['submitted_msat'] > 0
                and sale['usage']['paid_msat'] == progress['acknowledged_msat'],
                'successor provider credit differs')
        row['after_payment_progress'] = progress
        row['after_held'] = self.held(old)
        row['after_processes'] = processes(self)
        require(row['after_processes'] == row['before_processes'], 'a paid participant restarted')
        current = self.journals('after-overlap')
        for name, account in current.items():
            prior = before[name]
            require(account['controller']['policy'] == prior['controller']['policy']
                    and account['buyer']['total_budget_sat'] == prior['buyer']['total_budget_sat']
                    and account['buyer']['local'] == prior['buyer']['local'],
                    'renewal changed identity or lifetime authority')
            funding = account['controller']['funding']
            require(len(funding) == self.settlement_channel_counts[name]
                    and all(funding[key] == value for key, value in prior['controller']['funding'].items()),
                    'renewal duplicated funding or changed its predecessor')
        self.release()
        self.phase('Android reconnected and successor paid while original committed reply remained held')

    def exercise(self):
        eventually('exact four-node phone transit line', self.topology, 90)
        self.stream('foreground', unpaid=True)
        require(all(not self.accounts.ctl(name, 'status')['purchases'] for name in self.accounts.nodes),
                'unpaid check created a purchase')
        for name, other in (('n01', 'n03'), ('n03', 'n01')):
            self.once('buy-' + name, lambda name=name, other=other:
                      self.ctl(name, 'buy', destination=self.nodes[other].npub))
        self.stream('foreground')
        self.background = True
        self.phone.shell('input', 'keyevent', 'KEYCODE_HOME')
        self.stream('background')
        before = self.journals('before-renewal')
        original = {}
        for name in ('phone', 'n03'):
            purchases = self.accounts.ctl(name, 'status')['purchases']
            require(len(purchases) == 1, 'expected one original purchase before renewal')
            original[name] = purchases[0]
        try:
            self.overlap(original, before)
        finally:
            self.release()
        # Orderly pause drains renewal work, so it must follow the mint release.
        self.restore_foreground()
        self.once('pause-n03-renewal', lambda: self.ctl('n03', 'pause_renewals'))
        control(self.phone, 'pause_renewals')
        def refunded():
            for name in ('phone', 'n03'):
                state = self.accounts.state_json(name, 'controller/controller.json')
                closed = state['buyer_settlements'].get(original[name]['channel']['id'], {})
                if not closed.get('refunded') or not closed.get('released'):
                    return None
            return True
        eventually('both original refunds finish once', refunded, 30)
        phone_network.finish_guard(self, self.evidence['phone_renewal'])
        final = eventually('provider credit on every paying direction',
                           lambda: (state if payments_credited(state := self.finances()) else None), 30)
        require(control(self.phone, 'status')['received']['packets'] == 0,
                'phone became an application endpoint instead of transit')
        save(self.root / 'paid-finances.json', final)
        self.journals('paid')
        self.evidence['phone_renewal']['passed'] = True
        self.settle()

    def finish(self):
        try:
            self.release()
        finally:
            try:
                row = self.evidence['phone_renewal']
                if 'guard_pid' in row and not row.get('guard_finished_and_removed'):
                    phone_network.finish_guard(self, row)
            finally:
                super().finish()
