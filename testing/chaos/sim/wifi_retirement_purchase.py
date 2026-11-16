"""A new provider purchase beside paid radio traffic and fragmented cleanup.

Two zero-funded profiles share the guarded routers and use explicit LAN UDP
links. The original route remains native radio; this is not a performance test.
"""

import json
from pathlib import Path
import time

from . import wifi_probes as probes
from .paid_relay import eventually
from .paid_settlement import require
from .wifi_diamond_checks import listener, management_address
from .wifi_discovery import validate_unfunded
from .wifi_priority_checks import submitted
from .wifi_profiles import configure_stopped
from .wifi_remote import digest
from .wifi_retirement_live import CAPACITY, LIFETIME, LiveRetirementRun, funding_budget, pending


def unchanged_purchase(original, current):
    require(pending(original) and pending(current) == pending(original)
            and all(current[key] == original[key] for key in
                    ('local', 'epoch', 'policy', 'funding', 'next_funding', 'requested',
                     'outgoing', 'renewals', 'renewals_paused', 'watched_routes', 'route_changes')),
            'rejected purchase changed funding, route authority or its pending cleanup')


def completed_purchase(original, current, state, active, provider, requested):
    active_id, = [key for key, row in original['funding'].items()
                  if row['funded'] and row['funded']['terms']['id'] == active]
    require(not pending(current) and current['funding'].get(active_id) == original['funding'][active_id]
            and all(current[key] == original[key] for key in ('local', 'epoch', 'policy'))
            and current['buyer_settlements'].get(active) is None,
            'new purchase replaced the original channel or lifetime policy')
    added = {key: row for key, row in current['funding'].items() if key not in original['funding']}
    require(len(added) == 1 and len(current['funding']) == 2
            and current['next_funding'] == original['next_funding'] + 1
            and current['policy'] == original['policy']
            and state['funding_budget'] == funding_budget(CAPACITY), 'new purchase allocated extra authority')
    key, intent = next(iter(added.items()))
    purchases = state['purchases']
    require(len(purchases) == 2, 'new purchase replaced the existing route')
    old, = [p for p in purchases if p['channel']['id'] == active]
    new, = [p for p in purchases if p['channel']['id'] != active]
    require(intent['id'] == key and intent['capacity_sat'] == intent['max_wallet_debit_sat'] == CAPACITY
            and intent['created_unix'] >= requested
            and intent['expires_unix'] == intent['created_unix'] + LIFETIME // 2
            and intent['refund_after_unix'] == intent['created_unix'] + LIFETIME
            and intent['provider'] == new['provider'] == list(bytes.fromhex(provider))
            and old['provider'] != new['provider'] and new['channel'] == intent['funded']['terms']
            and old['channel'] == original['funding'][active_id]['funded']['terms'],
            'new funding changed its provider, original channel or terms')
    return key, intent, new


class PurchaseRetirementRun(LiveRetirementRun):
    completion_phase = 'new provider purchase rejected during cleanup, then funded once and both routes delivered'
    auxiliary_hosts = {'provider': 'n02', 'destination': 'n03'}
    expected_links = {'n01': {'n02': 'ethernet', 'provider': 'udp'},
                      'n02': {'n01': 'ethernet', 'n03': 'ethernet'}, 'n03': {'n02': 'ethernet'},
                      'provider': {'n01': 'udp', 'destination': 'udp'}, 'destination': {'provider': 'udp'}}

    def __init__(self, args):
        super().__init__(args)
        self.extra = {name: self.nodes[host].add_profile('purchase-' + name)
                      for name, host in self.auxiliary_hosts.items()}
        self.addresses, self.listeners = {}, {}
        self.evidence.update(new_route_transport='management_lan_udp', performance_test=False)
        for name in ('wifi_retirement_purchase.py', 'wifi_diamond_checks.py'):
            self.evidence['harness_sha256'][name] = digest(Path(__file__).with_name(name).read_bytes())

    def participants(self):
        return {**self.nodes, **self.extra}

    def initial_balances(self):
        return {**super().initial_balances(), **dict.fromkeys(self.extra, 0)}

    def ctl(self, node, kind, **fields):
        self.check_forwards()
        self.monitor.check()
        return self.participants()[node].control(kind, **fields)

    def state_json(self, name, relative):
        self.check_forwards()
        node = self.participants()[name]
        return json.loads(node.remote(['cat', node.state + '/' + relative]))

    def account_execute(self, name, binary, action, body, *, operation_timeout=45):
        if name not in self.extra:
            return super().account_execute(name, binary, action, body,
                                           operation_timeout=operation_timeout)
        require(binary == 'fips-relay' and action == 'wallet', 'unexpected auxiliary account operation')
        fields = dict(body)
        return self.ctl(name, fields.pop('type'), action=action,
                        operation_timeout=operation_timeout, **fields)

    def udp_config(self, name):
        node = self.nodes[name]
        address = management_address(node.remote([
            'ip', '-o', '-4', 'addr', 'show', 'dev', node.management, 'scope', 'global']), node.management)
        require(self.addresses.get(name, address) == address, 'management IPv4 changed')
        self.addresses[name] = address
        return {'bind_addr': address + ':0', 'bind_interface': node.management, 'advertise_on_nostr': False}

    def profile_config(self, node):
        config = super().profile_config(node)
        if node is self.nodes['n01']:
            config['transports']['udp'] = self.udp_config('n01')
        return config

    def before_launch(self):
        balances = {}
        for name, host in (('provider', 'n02'), ('destination', 'n03')):
            profile = self.extra[name]
            config = super().profile_config(self.nodes[host])
            config.update(state_directory=profile.state, transports={'udp': self.udp_config(host)})
            profile.prepare(config)
            balance = profile.control('balance', action='wallet')
            require(balance['mint_url'] == self.mint_url and balance['unit'] == 'sat'
                    and balance['balance_sat'] == 0, 'auxiliary profile has initial funds')
            balances[name] = 0
        self.evidence['auxiliary_identities'] = {name: p.npub for name, p in self.extra.items()}
        self.evidence['auxiliary_initial_balances'] = balances
        super().before_launch()

    def discovery_adapter(self, name, adapters):
        if name == 'n01':
            udp, = [item for item in adapters if item['type'] == 'udp']
            self.listeners[name] = listener(udp['local_addr'], self.addresses[name])
            adapters = [item for item in adapters if item['type'] != 'udp']
        return super().discovery_adapter(name, adapters)

    def form_line(self):
        super().form_line()
        for name, host, peer in (('provider', 'n02', 'n01'), ('destination', 'n03', 'provider')):
            profile = self.extra[name]
            configure_stopped(profile, neighbors=[{'npub': self.participants()[peer].npub,
                'addresses': [{'transport': 'udp', 'addr': self.listeners[peer]}]}])
            profile.start()
            state = eventually('new unfunded profile ready', lambda: self.ctl(name, 'status'), 30)
            validate_unfunded(state, buyer_budget_sat=self.buyer_budget)
            adapters = profile.native({'command': 'show_transports'})['data']['transports']
            require(len(adapters) == 1 and adapters[0]['type'] == 'udp', 'auxiliary transport shortcut')
            self.listeners[name] = listener(adapters[0]['local_addr'], self.addresses[host])
        topology = eventually('exact radio and new-provider UDP fork', self.fork_ready, 90)
        self.phase('two unfunded auxiliary profiles formed a separate provider route', topology=topology)

    def fork_ready(self):
        expected = self.expected_links
        profiles = self.participants()
        require(len({p.npub for p in profiles.values()}) == 5, 'fork identities are not distinct')
        states = {name: self.ctl(name, 'status') for name in profiles}
        for name, neighbors in expected.items():
            require(states[name]['npub'] == profiles[name].npub, 'fork profile identity changed')
            peers = states[name]['peers']
            wanted = {profiles[other].npub: (other, transport) for other, transport in neighbors.items()}
            if len(peers) != len(wanted) or {p['npub'] for p in peers} != set(wanted):
                return None
            for peer in peers:
                other, transport = wanted[peer['npub']]
                if not peer['connected']:
                    return None
                require(peer['transport'] == transport and (transport != 'udp'
                        or peer['address'] == self.listeners[other]), 'fork transport or listener changed')
        return states

    def traffic(self, label, count, rate, *, held=False, release=False):
        if held:
            self.purchase_before = self.journal()
            self.evidence['fragmented']['purchase'] = {'original': self.purchase_before, 'rejected': []}
            self.reject_purchase()
        super().traffic(label, count, rate, held=held, release=release)
        if held:
            self.reject_purchase()

    def reject_purchase(self):
        require(self.nodes['n01'].held(), 'purchase refusal is outside the held cleanup')
        unchanged_purchase(self.purchase_before, self.journal())
        error_path = self.nodes['n01'].output / 'last-error.txt'
        prior = error_path.stat().st_mtime_ns if error_path.exists() else None
        started = time.monotonic()
        try:
            self.ctl('n01', 'buy', destination=self.extra['destination'].npub, operation_timeout=8)
        except RuntimeError:
            require(error_path.exists() and error_path.stat().st_mtime_ns != prior
                    and error_path.read_bytes().strip() == b'fips-relay: controller journal suspended',
                    'new purchase failed outside the expected maintenance refusal')
        else:
            raise RuntimeError('new purchase funded during held cleanup')
        elapsed = time.monotonic() - started
        current, state = self.journal(), self.ctl('n01', 'status', operation_timeout=8)
        unchanged_purchase(self.purchase_before, current)
        require(elapsed < 8 and self.nodes['n01'].held() and state['funding_budget'] == funding_budget()
                and len(state['purchases']) == 1 and state['purchases'][0]['channel']['id'] == self.active
                and current['buyer_settlements'].get(self.active) is None
                and state['remaining_budget_sat'] == self.buyer_budget
                    - state['payment_progress'][self.active]['authorized_sat'],
                'rejected purchase changed the selected route or spending')
        self.evidence['fragmented']['purchase']['rejected'].append({
            'seconds': elapsed, 'error': 'controller journal suspended', 'journal': current,
            'budget': state['funding_budget'], 'payment': state['payment_progress'][self.active]})
        self.save()

    def after_retirement(self, journal):
        super().after_retirement(journal)
        original = self.purchase_before
        require(not pending(journal) and len(journal['funding']) == 1
                and journal['next_funding'] == original['next_funding']
                and self.ctl('n01', 'status')['funding_budget'] == funding_budget(),
                'cleanup created new funding before the requested purchase')
        requested = int(time.time())
        self.ctl('n01', 'buy', destination=self.extra['destination'].npub, operation_timeout=30)
        current, state = self.journal(), self.ctl('n01', 'status')
        super().after_retirement(current)
        provider = self.extra['provider'].native({'command': 'show_status'})['data']['node_addr']
        key, intent, new = completed_purchase(original, current, state, self.active, provider, requested)
        self.record_purchase(new, provider='provider')
        traffic = {}
        for destination, channel, seller in (('destination', new['channel']['id'], 'provider'),
                                              ('n03', self.active, 'n02')):
            before = self.credit(seller, channel)
            shape = probes.arm(self, 'n01', destination, 512, 1000, lifetime_secs=90)
            sent = probes.send(self, 'n01', destination, shape, 128)
            submitted(sent, shape)
            received = eventually('all original route payloads delivered', lambda:
                probes.receive(self, 'n01', destination, shape, complete=True), 10)
            state = self.caught_up(channel)
            eventually('fresh provider credit', lambda: self.credit(seller, channel) > before, 30)
            require(state['payment_progress'][channel]['authorized_sat'] > 0
                    and self.credit(seller, channel) >= state['payment_progress'][channel]['authorized_sat'] * 1000,
                    'fresh route lacks its signed and credited payment')
            traffic[destination] = {'shape': shape, 'sender': sent, 'receiver': received,
                                    'credit_before': before, 'credit_after': self.credit(seller, channel)}
        final = self.ctl('n01', 'status')
        paid = sum(final['payment_progress'][channel]['authorized_sat'] for channel in (self.active, new['channel']['id']))
        completed = self.journal()
        super().after_retirement(completed)
        require(final['funding_budget'] == funding_budget(CAPACITY)
                and final['remaining_budget_sat'] == self.buyer_budget - paid
                and completed['next_funding'] == current['next_funding']
                and completed['buyer_settlements'].get(self.active) is None,
                'two-route delivery changed lifetime spending or allocated another channel')
        require(self.fork_ready(), 'two routes lost their exact topology')
        self.evidence['fragmented']['purchase'].update(completed=True, funding_id=key,
            wallet_operation_id=intent['funded']['wallet_operation_id'], new_channel=new['channel']['id'],
            budget=final['funding_budget'], remaining_budget_sat=final['remaining_budget_sat'], traffic=traffic)
        self.save()

    def credit(self, name, channel):
        ledger = self.state_json(name, 'seller/ledger.json')['ledger']
        sale, = [row for row in ledger['channels'] if row['terms']['id'] == channel]
        return sale['usage']['paid_msat']
