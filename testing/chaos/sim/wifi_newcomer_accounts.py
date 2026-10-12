"""Observe live and stopped test accounts without reopening a stopped wallet."""

import copy
import json
from types import SimpleNamespace

from .paid_diamond import Accounts
from .paid_finances import financial_observation
from .paid_phone_finances import _address
from .paid_settlement import SettlementFixture, amount, original_channels, require


def frozen_status(before, status, after):
    """Retain a real funding-budget sample only across unchanged durable authority."""
    for field in ('local', 'policy', 'funding', 'buyer_settlements', 'history'):
        require(before['controller'].get(field) == after['controller'].get(field),
                'stopping changed the sampled funding authority')
    buyer = after['buyer']
    require(status['remaining_budget_sat'] + sum(
        amount(row['authorized_sat']) for row in buyer['channels'].values())
        == buyer['total_budget_sat'], 'stopping changed the sampled signed liability')
    return copy.deepcopy({key: status[key] for key in ('funding_budget', 'remaining_budget_sat')})


class NewcomerAccounts(Accounts):
    def __init__(self, run):
        super().__init__(run)
        self.frozen = {}
        self.purchases = {}

    def freeze(self, name):
        profile = self.nodes[name]
        before = profile.monetary_journals()
        status = profile.control('status')
        owner = getattr(profile, 'owner', profile)
        owner.stop(profile)
        after = profile.monetary_journals()
        self.frozen[name] = (frozen_status(before, status, after), after)
        self.run.phase('stopped account financial observation retained', account=name)

    def resume(self, name):
        self.unchanged(name)
        self.nodes[name].start()
        del self.frozen[name]

    def unchanged(self, name):
        _, journals = self.frozen[name]
        require(self.nodes[name].monetary_journals() == journals,
                'stopped account financial records changed')

    def observation(self):
        def status(name, kind):
            require(kind == 'status', 'offline observation cannot execute a control operation')
            if name not in self.frozen:
                return self.ctl(name, kind)
            self.unchanged(name)
            return self.frozen[name][0]

        view = SimpleNamespace(nodes=self.nodes, ctl=status, state_json=self.state_json)
        return financial_observation(view, wallet=None)

    def finances(self):
        return self.observation()[1]

    def buy(self, name, destination):
        purchase = self.ctl(name, 'buy', destination=self.nodes[destination].npub)['purchase']
        previous = self.purchases.get(name)
        require(previous is None or previous['channel'] == purchase['channel'],
                'new destination replaced the incumbent channel')
        self.purchases[name] = purchase
        return purchase

    def fixture(self):
        raw, summary = self.observation()
        channels = {p['channel']['id']: name for name, p in self.purchases.items()}
        require(len(channels) == len(self.purchases), 'different buyers share a channel')
        provider = _address(raw['n02']['controller']['local'])
        operations = set()
        for name, state in raw.items():
            controller, buyer = state['controller'], state['buyer']
            policy = controller['policy']
            require(policy['mint_url'] == self.run.mint_url and policy['renewal'] is None
                    and policy['channel_capacity_sat'] == 32 and policy['max_locked_sat'] == 64
                    and policy['max_wallet_spend_sat'] == 128 and policy['max_funding_overhead_sat'] == 0
                    and buyer['total_budget_sat'] == 64, 'newcomer changed financial limits')
            funding = controller['funding']
            require(len(funding) == int(name in self.purchases), 'unacknowledged funding exists')
            expected = {}
            for key, intent in funding.items():
                funded = intent['funded']
                require(funded is not None, 'unresolved newcomer funding')
                terms, operation = funded['terms'], funded['wallet_operation_id']
                require(terms == self.purchases[name]['channel'] and intent['id'] == key
                        and _address(terms['buyer']) == _address(buyer['local']) == _address(controller['local'])
                        and _address(intent['provider']) == provider
                        and terms['mint_url'] == self.run.mint_url and terms['capacity_sat'] == 32
                        and intent['capacity_sat'] == intent['max_wallet_debit_sat'] == 32
                        and funded['wallet_cost'] == dict(token_amount_sat=32, wallet_debit_sat=32, swap_fee_sat=0)
                        and funded['opening']['channel_id'] == terms['id']
                        and funded['opening']['balance'] == 0
                        and operation and operation not in operations,
                        'newcomer funding differs from the acknowledged account')
                operations.add(operation)
                expected[key] = (terms['id'], operation)
            require(summary[name]['funding'] == expected, 'funding summary differs from raw records')
            require(set(buyer['channels']) == {key for key, owner in channels.items() if owner == name},
                    'buyer journal gained another account')
            for key, row in buyer['channels'].items():
                require(row['terms'] == self.purchases[name]['channel']
                        and _address(row['provider']) == provider and 0 <= amount(row['authorized_sat']) <= 32,
                        'buyer authorization changed its owner or capacity')
            rows = state['seller']['ledger']['channels']
            require(len(rows) == (len(channels) if name == 'n02' else 0), 'unexpected seller account')
            for row in rows:
                key, usage = row['terms']['id'], row['usage']
                require(key in channels and row['terms'] == self.purchases[channels[key]]['channel']
                        and amount(usage['lost_msat']) == 0
                        and amount(usage['submitted_msat']) <= amount(usage['reserved_msat'])
                        <= min(32_000, amount(usage['paid_msat']) + row['terms']['grace_msat'])
                        and amount(usage['paid_msat']) <= summary[channels[key]]['signed_after'][key] * 1000,
                        'seller accounting exceeds original authorization')
        fixture = SettlementFixture(dict.fromkeys(self.nodes, 128), dict.fromkeys(self.nodes, 64), 32,
                                    channels, dict.fromkeys(channels, 'n02'))
        original_channels(self.nodes, summary, fixture=fixture)
        return summary, fixture

    def snapshot_hashes(self, name):
        # Raw journals include signed material and stay in memory.
        from .wifi_remote import digest
        return {key: digest(json.dumps(value, sort_keys=True).encode())
                for key, value in self.nodes[name].monetary_journals().items()}
