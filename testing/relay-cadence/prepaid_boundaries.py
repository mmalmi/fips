"""Explicit schema-2 prepaid usage accounting; historical reports stay strict.

Intervals partition cumulative observations, not atomic wall-clock snapshots.
All counters use exact integers. Evidence is usage, not another payment or a
physical-byte measurement; journal totals and operation details overlap.
Observed trial totals include the workload summaries and must not be added to
them. Setup before the first guard and settlement after the final guard remain
outside the observed trial, as in the existing experiment.
"""
import copy

from costs import node_costs, sum_counts
from service_carrier import difference, identity, intervals, snapshot
from validation import quiet_boundary, validate_gap

CONTRACT = 'prepaid-usage-v1'


def enabled(metadata):
    if 'boundary_accounting' not in metadata:
        return False
    value = metadata['boundary_accounting']
    if type(value) is not str or value != CONTRACT:
        raise ValueError('unsupported boundary accounting contract')
    if metadata['schema'] != 2:
        raise ValueError('prepaid boundary accounting requires schema 2')
    if metadata.get('payment_service_carrier') is not True:
        raise ValueError('prepaid boundary accounting requires declared carrier measurements')
    return True


def observe(data, previous, carrier_intervals):
    observed = {}
    for name, before, after in intervals(data, previous):
        if name != 'before_to_after':
            validate_gap(before, after, prepaid_usage=True)
        elif quiet_boundary(before) != quiet_boundary(after):
            raise ValueError('paying channels changed during measurement')
        nodes = {}
        for prior, current in zip(before, after):
            key = identity(prior)[0]
            costs = node_costs(prior, current, complete=True)
            costs['service_carrier'] = copy.deepcopy(carrier_intervals[name]['nodes'][key])
            nodes[key] = costs
        total = sum_counts(nodes.values())
        observed[name] = {
            'nodes': nodes, 'total': total,
            # Workload evidence can use newly paid credit. Only gap usage is
            # proven covered by an unchanged previous acknowledgment.
            'prepaid_usage_msat': (copy.deepcopy(total['evidence_msat'])
                                   if name != 'before_to_after' else {}),
        }
    return observed


def finish_trial(windows, first, last):
    measured = [value for row in windows for value in row['observed_intervals'].values()]
    nodes = {key: sum_counts(interval['nodes'][key] for interval in measured)
             for key in measured[0]['nodes']}
    expected = {}
    for before, after in zip(first, last):
        key = identity(before)[0]
        costs = node_costs(before, after, complete=True)
        costs['service_carrier'] = difference(snapshot(before, True), snapshot(after, True))
        expected[key] = costs
    # Exact integer reconciliation covers every nested operation, channel and
    # transport, including the last guard after the final measured workload.
    if nodes != expected:
        raise ValueError('observed intervals do not telescope to the full trial')
    windows[-1]['observed_trial_costs'] = {
        'from': 'idle.before_guard', 'to': 'high_rate.after_guard',
        'interval_count': len(measured), 'telescopes': True,
        'nodes': nodes, 'total': sum_counts(nodes.values()),
        'prepaid_usage_msat': sum_counts(value['prepaid_usage_msat'] for value in measured),
    }
