"""Validate the fixed forwarding diagnostic while retaining delivery failures."""
from copy import deepcopy

from analyze import summarize
from costs import delta, node_costs
from native_counters import WAIT_DROPS, difference, groups
from service_carrier import intervals, record as record_carrier
from validation import WORKLOADS, probe_delivery_loss, unsigned, validate_gap


def require(condition, message):
    if not condition:
        raise ValueError(message)


def forwarding(data):
    before, after = data['forwarding']['before'], data['forwarding']['after']
    require(len(before) == len(after) == 5, 'forwarding observation shape changed')
    nodes = []
    for index, (prior, current) in enumerate(zip(before, after)):
        pid = prior['process_id']
        require(pid == current['process_id'] == data['before'][index]['measurements']['process_id']
                == data['after'][index]['measurements']['process_id'], 'forwarding process changed')
        a, b = prior['counters'], current['counters']
        require(WAIT_DROPS <= a.keys(), 'missing admission drop categories')
        counts = difference(groups({'forwarding': a}, ('forwarding',)),
                            groups({'forwarding': b}, ('forwarding',)))['forwarding']
        allowed = {f'{kind}_{unit}' for kind in ('drop_policy_denied', 'drop_policy_wait_full')
                   for unit in ('packets', 'bytes')}
        require(not any(value for key, value in counts.items()
                        if key.startswith(('drop_', 'decode_error_', 'ttl_exhausted_'))
                        and key not in allowed), 'unexpected native drop or error')
        causes = {}
        for unit in ('packets', 'bytes'):
            values = {reason: counts[f'drop_policy_wait_{reason}_{unit}']
                      for reason in ('full', 'expired', 'invalidated')}
            values['explicit_reject'] = counts[f'drop_policy_denied_{unit}'] - sum(values.values())
            require(values['explicit_reject'] == 0, 'unexpected explicit policy rejection')
            causes[unit] = values
        a = data['before_guard'][index]['measurements']['admission_denials']
        b = data['after_guard'][index]['measurements']['admission_denials']
        require(set(a) == set(b) == {'credit_limit', 'durable_window'}, 'admission layout changed')
        nodes.append({'node': index, 'process_id': pid, 'counters': counts,
                      'policy_drop_causes': causes,
                      'admission_denials': {key: delta(a, b, key) for key in a}})
    return nodes


def classify_row(row, previous):
    data = row['data']
    counts = WORKLOADS[data['workload']]
    require(len(data['probes']) == len(counts), 'workload probe count changed')
    missing = sum(probe_delivery_loss(p, count) for p, count in zip(data['probes'], counts))
    high_loss = data['workload'] == 'high_rate' and missing > 0
    require(not missing or high_loss, 'unexpected loss outside high-rate workload')

    # The raw record remains untouched. Only the already-classified evidence
    # deficit is projected out of the strict validator's view. Original guard
    # equality and every interval are checked first, so this cannot hide work.
    view = deepcopy(row)
    deficits = []
    for boundary in ('before_guard', 'before', 'after', 'after_guard'):
        require(len(data[boundary]) == 5, 'service boundary shape changed')
        for index, node in enumerate(data[boundary]):
            for channel, state in node['payment_progress'].items():
                require(set(state) == {'evidence_msat', 'authorized_sat', 'acknowledged_msat',
                                       'in_flight', 'pending', 'last_failure_stage'},
                        'payment state layout changed')
                require(state['in_flight'] is False and state['pending'] is None
                        and state['last_failure_stage'] is None, 'unfinished or failed payment')
                evidence = unsigned(state['evidence_msat'])
                ack = unsigned(state['acknowledged_msat'])
                require(ack >= unsigned(state['authorized_sat']) * 1000,
                        'unacknowledged signed liability')
                if evidence > ack:
                    require(high_loss and boundary in ('after', 'after_guard'),
                            'unexpected unreconciled evidence')
                    deficits.append({'boundary': boundary, 'node': index,
                                     'channel': channel, 'state': deepcopy(state)})
                    view['data'][boundary][index]['payment_progress'][channel]['evidence_msat'] = ack
    for name, before, after in intervals(data, previous):
        require(len(before) == len(after) == 5, 'interval shape changed')
        for a, b in zip(before, after):
            node_costs(a, b, complete=True)
            for channel, state in a['payment_progress'].items():
                for key in ('acknowledged_msat', 'authorized_sat'):
                    delta(state, b['payment_progress'][channel], key)
            if name != 'before_to_after':
                require(a['payment_progress'] == b['payment_progress'],
                        'payment evidence changed outside measurement windows')
    if previous is not None:
        validate_gap(previous, data['before_guard'])
    delivery_rejections = []
    measured = summarize(view, delivery_rejections=delivery_rejections)
    record_carrier(data, measured, previous, True)
    require(measured['payment_service_carrier']['total']['discarded_outputs'] == 0
            and all(v['total']['discarded_outputs'] == 0 for v in
                    measured['payment_service_carrier']['outside_workload'].values()),
            'payment carrier discarded output')
    nodes = forwarding(data)
    full = sum(n['policy_drop_causes']['packets']['full'] for n in nodes)
    full_bytes = sum(n['policy_drop_causes']['bytes']['full'] for n in nodes)
    require(not full or data['workload'] == 'high_rate',
            'unexpected native queue congestion outside high-rate workload')
    # Native counters include opaque session controls and cover a wider sampling
    # interval. Neither equality nor a difference attributes individual probe loss.
    classification = ('high-rate-loss' if missing else
                      'native-queue-congestion' if full else 'clean')
    return {'trial': row['trial'], 'max_delay_ms': row['max_delay_ms'],
            'workload': data['workload'], 'submitted_packets': sum(counts),
            'received_packets': sum(counts) - missing, 'missing_packets': missing,
            'queue_full_packets': full, 'queue_full_bytes': full_bytes,
            'probe_loss_from_queue_full': None,
            'classification': classification,
            'clean_link_accepted': classification == 'clean', 'sequence_may_continue': True,
            'delivery_rejections': delivery_rejections, 'evidence_deficits': deficits,
            'nodes': nodes, 'measurements': measured}


def classify(raw):
    require(len(raw) == 13, 'incomplete diagnostic sequence')
    meta = raw[0]
    require(meta['diagnostic'] == 'native-forwarding-drops'
            and meta['comparison_complete'] is False and type(meta['max_delay_ms']) is int
            and meta['max_delay_ms'] == 500 and type(meta['repeats']) is int
            and meta['repeats'] == 2, 'diagnostic metadata changed')
    summaries = []
    for trial in (0, 1):
        warmup, *rows, money = raw[1 + trial * 6:7 + trial * 6]
        for row in (warmup, *rows, money):
            require(type(row['trial']) is int and row['trial'] == trial
                    and type(row['max_delay_ms']) is int and row['max_delay_ms'] == 500,
                    'trial or policy sequence changed')
        require(set(warmup) == {'trial', 'max_delay_ms', 'warmup'}
                and len(warmup['warmup']) == 1, 'warmup changed')
        require(probe_delivery_loss(warmup['warmup'][0], 1) == 0, 'warmup lost packet')
        require([r['data']['workload'] for r in rows] == list(WORKLOADS), 'workload sequence changed')
        previous = None
        for row in rows:
            require(set(row) == {'trial', 'max_delay_ms', 'data'}, 'unexpected workload record')
            summaries.append(classify_row(row, previous))
            previous = row['data']['after_guard']
        require(set(money) == {'trial', 'max_delay_ms', 'conserved', 'issued_sat',
                               'collected_sat', 'settled_channels'}, 'accounting record changed')
        require(money['conserved'] is True and unsigned(money['issued_sat']) == 5120
                and unsigned(money['collected_sat']) == 5120
                and unsigned(money['settled_channels']) == 6, 'trial conservation failed')
    return {'sequence_may_continue': True, 'comparison_complete': False,
            'clean_link_accepted': all(r['clean_link_accepted'] for r in summaries),
            'scope': 'fixed 500 ms diagnostic; native drop totals cannot attribute probe loss',
            'workloads': summaries}


if __name__ == '__main__':
    import argparse
    import json
    from pathlib import Path

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.report.read_text().splitlines() if line.strip()]
    print(json.dumps(classify(rows), indent=2))
