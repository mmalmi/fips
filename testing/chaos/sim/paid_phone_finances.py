"""Read-only checks for the fresh four-account, zero-fee phone fixture.

validate_settled(journals, before, balances, mint, expected_edges):
  journals/before: participant -> {controller, buyer, seller} raw saved JSON;
    seller may include the outer {ledger: ...} journal wrapper.
  balances: participant -> actual stopped-wallet integer balance; the caller
    verifies mint/unit on CLI replies and the immutable phone profile/UI action.
  mint: actual pre-collection report; expected_edges: four (buyer, provider) pairs.

This fixture intentionally requires 128 issued sats per account and 32 per
original channel. It does not reconstruct status or validate proof signatures.
It returns monetary summaries only, never signed payments or bearer proofs.
"""
from .paid_settlement import amount, require, validate_report


def _mapping(value, label):
    require(type(value) is dict, label + ' is not an object')
    return value


def _text(value, label):
    require(isinstance(value, str) and bool(value), label + ' is missing')
    return value


def _address(value):
    # ledger::node_addr persists NodeAddr as exactly sixteen unsigned bytes.
    require(type(value) is list and len(value) == 16
            and all(type(byte) is int and 0 <= byte <= 255 for byte in value),
            'invalid persisted participant address')
    return tuple(value)


def _zero(value):
    if value is None:
        return True
    if type(value) is dict:
        return all(_zero(item) for item in value.values())
    if type(value) is list:
        return not value
    return type(value) is int and value == 0


def _ledger(journal):
    seller = _mapping(journal['seller'], 'seller journal')
    return seller['ledger'] if 'ledger' in seller else seller


def check_mint(report, collected):
    """Require actual fresh test-mint evidence; conserved alone is insufficient."""
    require(report['test_only'] is True and report['conserved'] is True,
            'mint is not the conserved isolated test mint')
    _text(report['url'], 'mint URL')
    for key in ('issued_sat', 'external_funding_sat', 'total_accounted_sat'):
        require(amount(report[key]) == 512, 'mint funding changed from 512 sats')
    require(amount(report['collected_sat']) == collected, 'collector balance differs')


def _snapshot(journals, mint, edges):
    participants = set(journals)
    require(len(participants) == 4 and len(edges) == len(set(edges)) == 4,
            'expected exactly four participants and four unique edges')
    require({buyer for buyer, _ in edges} == participants
            and all(provider in participants and buyer != provider for buyer, provider in edges),
            'expected one original purchase per participant')
    identities, owner_by_addr = {}, {}
    for name, state in journals.items():
        controller, buyer = state['controller'], state['buyer']
        address = _address(controller['local'])
        require(address not in owner_by_addr and _address(buyer['local']) == address,
                'duplicate or inconsistent participant identity')
        identities[name], owner_by_addr[address] = address, name
        require(_zero(buyer.get('history')) and _zero(_ledger(state).get('history')),
                'fixture has retired buyer or seller accounting')
        history = controller.get('history') or {}
        require(_zero(history.get('channels')) and _zero(history.get('seller'))
                and history.get('pending') is None,
                'fixture has retired financial history or pending retirement')
    channels, operations, outgoing = {}, set(), {}
    for name, state in journals.items():
        controller, buyer = state['controller'], state['buyer']
        funds = _mapping(controller['funding'], 'funding')
        require(len(funds) == 1, 'fixture changed original per-account channel count')
        for key, intent in funds.items():
            require(intent['id'] == key and intent['funded'] is not None,
                    'funding is unresolved or has changed identity')
            funded = intent['funded']
            terms, cost = funded['terms'], funded['wallet_cost']
            channel = _text(terms['id'], 'funded channel')
            operation = _text(funded['wallet_operation_id'], 'funding operation')
            require(channel not in channels and operation not in operations,
                    'duplicate channel or wallet operation')
            provider = owner_by_addr.get(_address(intent['provider']))
            require((name, provider) in edges and _address(terms['buyer']) == identities[name]
                    and terms['mint_url'] == mint, 'funding owner/provider/mint differs')
            require(amount(terms['capacity_sat']) == amount(intent['capacity_sat']) == 32
                    and amount(intent['max_wallet_debit_sat']) == 32
                    and amount(cost['token_amount_sat']) == amount(cost['wallet_debit_sat']) == 32
                    and amount(cost['swap_fee_sat']) == 0,
                    'original zero-fee funding terms changed')
            require(terms['expires_unix'] == intent['expires_unix']
                    and terms['grace_msat'] == intent['grace_msat']
                    and funded['opening']['channel_id'] == channel
                    and amount(funded['opening']['balance']) == 0,
                    'funding intent/opening terms differ')
            channels[channel] = (name, provider, terms)
            operations.add(operation)
            outgoing[name] = channel
        require(set(buyer['channels']) == {outgoing[name]},
                'buyer authority does not match original funding')
        own = buyer['channels'][outgoing[name]]
        require(own['terms'] == channels[outgoing[name]][2]
                and _address(own['provider']) == identities[channels[outgoing[name]][1]],
                'buyer account changed funding terms')
        authorized = amount(own['authorized_sat'])
        budget = amount(buyer['total_budget_sat'])
        require(authorized <= 32 and authorized <= budget, 'buyer authorization exceeds budget')
    require({(owner, provider) for owner, provider, _ in channels.values()} == set(edges),
            'actual channel graph differs from expected graph')
    sellers = {}
    for name, state in journals.items():
        expected = {channel for channel, (_, provider, _) in channels.items() if provider == name}
        rows = _ledger(state)['channels']
        require(type(rows) is list, 'seller channels are not an array')
        actual = {}
        for row in rows:
            channel = row['terms']['id']
            require(channel not in actual, 'duplicate seller channel')
            actual[channel] = row
        require(set(actual) == expected, 'seller account set differs from funded graph')
        for channel, row in actual.items():
            require(row['terms'] == channels[channel][2], 'seller channel terms differ')
            amount(row['usage']['paid_msat'])
        sellers[name] = actual
    return identities, channels, outgoing, sellers


def validate_settled(journals, before, balances, mint, expected_edges):
    """Validate four terminal cooperative settlements and all 512 stopped sats."""
    try:
        return _validate_settled(journals, before, balances, mint, list(map(tuple, expected_edges)))
    except (KeyError, TypeError, IndexError) as error:
        raise RuntimeError('missing or malformed four-account financial evidence') from error


def _validate_settled(journals, before, balances, mint, edges):
    require(set(journals) == set(before) == set(balances), 'account set changed')
    check_mint(mint, 0)
    old_identity, old_channels, old_outgoing, old_sellers = _snapshot(before, mint['url'], edges)
    identity, channels, outgoing, sellers = _snapshot(journals, mint['url'], edges)
    require(identity == old_identity and channels == old_channels and outgoing == old_outgoing,
            'settlement changed channel ownership or terms')
    reports, summaries = {}, {}
    for name, state in journals.items():
        prior = before[name]
        controller, old_controller = state['controller'], prior['controller']
        buyer, old_buyer = state['buyer'], prior['buyer']
        require(controller['funding'] == old_controller['funding']
                and controller['policy'] == old_controller['policy'],
                'settlement changed funding evidence or authority policy')
        require(not old_controller['buyer_settlements'] and not old_controller['seller_settlements'],
                'pre-settlement fixture already has settlement work')
        require(set(controller['buyer_settlements']) == {outgoing[name]},
                'missing or extra buyer settlement')
        expected_sales = {channel for channel, (_, provider, _) in channels.items() if provider == name}
        require(set(controller['seller_settlements']) == expected_sales,
                'missing or extra seller settlement')
        channel = outgoing[name]
        settlement = controller['buyer_settlements'][channel]
        provider = channels[channel][1]
        sale = journals[provider]['controller']['seller_settlements'][channel]
        require(settlement.get('kind', 'cooperative') == 'cooperative'
                and settlement['released'] is True and settlement['refunded'] is True
                and sale['released'] is True,
                'settlement is incomplete, unacknowledged, or not cooperative')
        require(_address(settlement['provider']) == identity[provider]
                and settlement['channel'] == sale['channel'] == channels[channel][2],
                'settlement terms/parties changed')
        report = validate_report(settlement['report'])
        require(report['channel_id'] == channel and sale['report'] == settlement['report'],
                'buyer and seller reports differ')
        require(amount(settlement['wallet_refund_sat']) == report['refunded_sat'],
                'wallet refund differs from settlement report')
        require(isinstance(settlement['usage'], dict) and isinstance(sale['usage'], dict),
                'settlement omitted sealed usage evidence')
        for saved in (settlement, sale):
            require(saved['payment']['channel_id'] == channel
                    and amount(saved['payment']['balance']) == report['paid_sat'],
                    'final signed payment differs from report')
        authorized = amount(buyer['channels'][channel]['authorized_sat'])
        previous = amount(old_buyer['channels'][channel]['authorized_sat'])
        total = amount(buyer['total_budget_sat'])
        require(total == amount(old_buyer['total_budget_sat']) and previous <= authorized
                and authorized == report['paid_sat'], 'lifetime buyer budget or signed amount changed')
        require(amount(sellers[provider][channel]['usage']['paid_msat']) == authorized * 1000
                and amount(old_sellers[provider][channel]['usage']['paid_msat']) <= authorized * 1000,
                'provider credit differs from retained final signature')
        reports[channel] = report
        summaries[name] = {
            'buyer_budget_sat': total, 'authorized_sat': authorized, 'remaining_budget_sat': total-authorized,
            'funding_budget': {'pending_reserved_sat': 0, 'wallet_debited_sat': 32,
                               'wallet_refunded_sat': report['refunded_sat'], 'locked_sat': 0,
                               'exposure_sat': 32-report['refunded_sat']},
        }
    for name in journals:
        refund = reports[outgoing[name]]['refunded_sat']
        earned = sum(reports[channel]['paid_sat'] for channel in sellers[name])
        expected = 128 - 32 + refund + earned
        actual = amount(balances[name])
        require(actual == expected, 'stopped wallet balance differs from verified debit/refund/earnings')
        summaries[name].update(wallet_balance_sat=actual, seller_received_sat=earned)
    require(sum(amount(value) for value in balances.values()) == 512,
            'four stopped wallets do not conserve all 512 issued sats')
    return {'accounts': summaries, 'channel_owners': {
        channel: {'buyer': buyer, 'provider': provider} for channel, (buyer, provider, _) in channels.items()},
        'settlements': reports, 'total_wallet_sat': 512, 'issued_sat': 512}
