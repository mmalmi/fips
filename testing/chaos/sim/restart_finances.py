"""Shared accounting checks for the fixed three-node restart fixtures."""

from .paid_finances import payments_credited
from .paid_settlement import amount, original_channels, require


QUOTE_UNITS = 32 * 1024 * 1024


def recovered_exposure(journal):
    """Derive exact unbilled exposure from the stopped provider's durable ceiling."""
    require(journal['version'] == 2 and journal['window_msat'] == 4000,
            'unexpected durable-window policy')
    channels = journal['ledger']['channels']
    require(len(channels) == 2 and len(journal['ceilings']) == 2,
            'restart requires exactly two original provider channels')
    result = {}
    for channel in channels:
        terms, usage = channel['terms'], channel['usage']
        key = terms['id']
        require(key not in result and channel['active'] and terms['capacity_sat'] == 32
                and terms['grace_msat'] == 8000, 'provider channel terms changed')
        ceiling = amount(journal['ceilings'][key])
        reserved, lost = amount(usage['reserved_msat']), amount(usage['lost_msat'])
        require(lost == 0 and 0 <= ceiling - reserved <= 4000
                and ceiling <= min(32000, amount(usage['paid_msat']) + 8000),
                'stopped allowance exceeds the original exposure bound')
        result[key] = lost + ceiling - reserved
    require(set(result) == set(journal['ceilings']), 'durable ceiling membership differs')
    return result


def retained_finances(anchor, current, expected_lost):
    require(original_channels(anchor, anchor) == original_channels(current, current),
            'load or restart replaced an original channel')
    credited = current['n02']['credited']
    require(set(credited) == set(expected_lost), 'provider channel membership changed')
    for name, state in current.items():
        old = anchor[name]
        require(state['funding'] == old['funding'] and state['budget'] == old['budget'],
                'load or restart changed funding or capital')
        for channel, signed in state['signed'].items():
            require(old['signed'][channel] <= amount(signed) <= 32
                    and credited[channel] <= state['signed_after'][channel] * 1000,
                    'authorization decreased or provider credit exceeds signed liability')
        for kind in ('buyer_units', 'seller_units'):
            require(set(state[kind]) == set(old[kind])
                    and all(old[kind][key] <= amount(value) <= QUOTE_UNITS
                            for key, value in state[kind].items()),
                    'route agreement changed or usage decreased/exceeded its grant')
    require(set(current['n02']['seller_channels']) == set(credited),
            'provider usage membership changed')
    for channel, usage in current['n02']['seller_channels'].items():
        require(usage['paid_msat'] == credited[channel]
                and 0 <= usage['submitted_msat'] <= usage['reserved_msat']
                <= min(32000, credited[channel] + 8000)
                and usage['submitted_msat'] + usage['lost_msat'] <= usage['reserved_msat']
                and usage['lost_msat'] == expected_lost[channel],
                'provider recovery changed the exact unbilled exposure or credit bound')
    return current if payments_credited(current) else None
