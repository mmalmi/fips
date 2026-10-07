"""Attribute native cadence packets by observed counter ranges, not wall clocks."""
from bisect import bisect_left
from collections import Counter, defaultdict

from analyze import analyze_rows
from service_carrier import boundaries, counter, difference, identity, snapshot
from validation import PAYMENT_PORT
from wire_capture import match_packets


def analyze_wire(rows, packets, traces):
    metadata, windows, _ = analyze_rows(rows)
    if metadata['schema'] != 2 or metadata.get('payment_service_carrier') is not True:
        raise ValueError('requires the instrumented native cadence report')
    ranges = defaultdict(list)
    expected = {}
    final = {}
    owners = {}
    costs = defaultdict(Counter)
    previous = None
    trial = None
    for row in rows:
        if 'data' not in row:
            continue
        if row['trial'] != trial:
            trial = row['trial']
            previous = None
        samples = boundaries(row['data'], previous)
        for index, (name, nodes) in enumerate(samples):
            for node_index, node in enumerate(nodes):
                key, pid = identity(node)
                if key != str(pid):
                    raise ValueError('capture namespace differs from native process identities')
                owner = (trial, node_index)
                if pid in owners and owners[pid] != owner:
                    raise ValueError('process identity reused across captured trials')
                owners[pid] = owner
                value = snapshot(node, True)
                if index == 0:
                    if previous is not None:
                        continue
                    before = {**value, 'transports': {
                        transport: {field: 0 for field in counters}
                        for transport, counters in value['transports'].items()}}
                    label = (trial, 'setup', 'before_first_guard', node_index)
                else:
                    before = snapshot(samples[index - 1][1][node_index], True)
                    label = (trial, row['data']['workload'], samples[index - 1][0] + '_to_' + name, node_index)
                delta = difference(before, value)
                expected[label] = Counter(packets=sum(v['submitted_packets'] for v in delta['transports'].values()),
                    fips_payload_bytes=sum(v['fips_payload_bytes'] for v in delta['transports'].values()))
                for transport, counters in value['transports'].items():
                    if transport != 'udp' and counters['submitted_packets']:
                        raise ValueError('native UDP capture has another active carrier')
                    ranges[(pid, transport)].append((counters['submitted_packets'], label))
                final[pid] = {'process_id': pid, 'service_port': PAYMENT_PORT,
                    'ambiguous_port_datagrams': 0, 'discarded_outputs': value['discarded_outputs'],
                    'transports': [dict(transport=t, **c) for t, c in value['transports'].items()]}
        previous = row['data']['after_guard']

    # Validate the complete trace first, including events after the final guard.
    # Those settlement/shutdown events stay outside the measured prefix.
    selected = []
    counter_ids = {}
    for trace in traces:
        pid = trace['process_id']
        if pid not in final:
            raise ValueError('unexpected process in cadence traces')
        if trace['service_port'] != PAYMENT_PORT:
            continue
        if pid in counter_ids and counter_ids[pid] != trace['counter_id']:
            raise ValueError('multiple endpoint counters in one native daemon')
        counter_ids[pid] = trace['counter_id']
        key = (pid, trace['transport'])
        if key not in ranges:
            raise ValueError('unobserved carrier in cadence traces')
        if counter(trace['packet_number']) <= ranges[key][-1][0]:
            selected.append(trace)

    ends = {key: [end for end, _ in values] for key, values in ranges.items()}

    def matched(trace, framing):
        key = (trace['process_id'], trace['transport'])
        index = bisect_left(ends[key], trace['packet_number'])
        label = ranges[key][index][1]
        if framing['ip_bytes'] is None:
            raise ValueError('UDP submission has no captured IP framing')
        costs[label].update(packets=1, fips_payload_bytes=trace['payload_bytes'],
                            captured_link_bytes=framing['captured_link_bytes'], ip_bytes=framing['ip_bytes'])

    capture = match_packets(packets, selected, list(final.values()), on_match=matched)
    for label, wanted in expected.items():
        if any(costs[label][field] != amount for field, amount in wanted.items()):
            raise ValueError('captured interval disagrees with observed carrier counters')
    intervals = [{'trial': t, 'workload': w, 'interval': i, 'node': n, **costs[label]}
                 for label in sorted(expected) for t, w, i, n in [label]]
    measured = []
    for window in windows:
        total = Counter()
        for node_index in range(metadata['nodes']):
            total.update(costs[(window['trial'], window['workload'], 'before_to_after', node_index)])
        delivered = window['delivered_bytes']
        measured.append({'trial': window['trial'], 'max_delay_ms': window['max_delay_ms'],
            'workload': window['workload'], 'delivered_bytes': delivered, 'wire': dict(total),
            'captured_link_bytes_per_delivered_byte': total['captured_link_bytes'] / delivered if delivered else None,
            'ip_bytes_per_delivered_byte': total['ip_bytes'] / delivered if delivered else None})
    return {'metadata': metadata, 'capture': capture, 'windows': measured,
            'intervals': intervals, 'physical_wire_bytes': None, 'radio_airtime': None}
