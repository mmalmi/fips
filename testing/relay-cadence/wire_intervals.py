"""Attribute cadence packets by observed counter ranges, not wall clocks."""
from bisect import bisect_left
from collections import Counter, defaultdict
import argparse
import json
from pathlib import Path
import re

from analyze import analyze_rows
from service_carrier import boundaries, counter, difference, identity, snapshot
from validation import PAYMENT_PORT
from wire_capture import match_packets, read_pcap, read_traces


def analyze_wire(rows, packets, traces, *, host=None, trial=None, pilot=False):
    metadata, windows, _ = analyze_rows(rows, pilot=pilot)
    hardware = metadata['schema'] == 3
    if metadata.get('payment_service_carrier') is not True:
        raise ValueError('requires the instrumented cadence report')
    if (hardware and host not in ('n01', 'n02', 'n03')) or (not hardware and host is not None):
        raise ValueError('hardware captures require one explicit originating host')
    if trial is not None and (type(trial) is not int or not any(w['trial'] == trial for w in windows)):
        raise ValueError('capture trial must identify an observed trial')
    carrier = 'ethernet' if hardware else 'udp'
    ranges = defaultdict(list)
    expected = {}
    final = {}
    owners = {}
    costs = defaultdict(Counter)
    previous = None
    current_trial = None
    for row in rows:
        if 'data' not in row or (trial is not None and row['trial'] != trial):
            continue
        if row['trial'] != current_trial:
            current_trial = row['trial']
            previous = None
        samples = boundaries(row['data'], previous)
        for index, (name, nodes) in enumerate(samples):
            for node_index, node in enumerate(nodes):
                if hardware and node['host_process']['host'] != host:
                    continue
                scope = identity(node)
                pid = node['measurements']['process_id']
                if not hardware and scope != (str(pid), pid):
                    raise ValueError('capture namespace differs from native process identities')
                owner = (current_trial, node_index, scope)
                if pid in owners and owners[pid] != owner:
                    raise ValueError('process identity reused across captured trials')
                owners[pid] = owner
                value = snapshot(node, True, native_ethernet=hardware)
                if index == 0:
                    if previous is not None:
                        continue
                    before = {**value, 'transports': {
                        transport: {field: 0 for field in counters}
                        for transport, counters in value['transports'].items()}}
                    label = (current_trial, 'setup', 'before_first_guard', node_index)
                else:
                    before = snapshot(samples[index - 1][1][node_index], True, native_ethernet=hardware)
                    label = (current_trial, row['data']['workload'], samples[index - 1][0] + '_to_' + name, node_index)
                delta = difference(before, value)
                expected[label] = Counter(packets=sum(v['submitted_packets'] for v in delta['transports'].values()),
                    fips_payload_bytes=sum(v['fips_payload_bytes'] for v in delta['transports'].values()))
                for transport, counters in value['transports'].items():
                    if transport != carrier and counters['submitted_packets']:
                        raise ValueError('capture has another active carrier')
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
        if carrier == 'udp' and framing['ip_bytes'] is None:
            raise ValueError('UDP submission has no captured IP framing')
        costs[label].update(packets=1, fips_payload_bytes=trace['payload_bytes'],
                            captured_link_bytes=framing['captured_link_bytes'])
        if framing['ip_bytes'] is not None:
            costs[label]['ip_bytes'] += framing['ip_bytes']

    capture = match_packets(packets, selected, list(final.values()), on_match=matched)
    for label, wanted in expected.items():
        if any(costs[label][field] != amount for field, amount in wanted.items()):
            raise ValueError('captured interval disagrees with observed carrier counters')
    intervals = [{'trial': t, 'workload': w, 'interval': i, 'node': n, **costs[label]}
                 for label in sorted(expected) for t, w, i, n in [label]]
    measured = []
    for window in windows:
        if trial is not None and window['trial'] != trial:
            continue
        total = Counter()
        for node_index in range(metadata['nodes']):
            total.update(costs[(window['trial'], window['workload'], 'before_to_after', node_index)])
        delivered = window['delivered_bytes']
        measured.append({'trial': window['trial'], 'max_delay_ms': window['max_delay_ms'],
            'workload': window['workload'], 'delivered_bytes': delivered, 'wire': dict(total),
            'captured_link_bytes_per_delivered_byte': total['captured_link_bytes'] / delivered if delivered else None,
            'ip_bytes_per_delivered_byte': total['ip_bytes'] / delivered if delivered and carrier == 'udp' else None})
    return {'metadata': metadata, 'capture': capture, 'windows': measured,
            'intervals': intervals, 'originating_host': host, 'originating_trial': trial,
            'physical_wire_bytes': None, 'radio_airtime': None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('capture', type=Path)
    parser.add_argument('traces', nargs='+', type=Path)
    parser.add_argument('--capture-stats', type=Path, required=True)
    parser.add_argument('--host', choices=('n01', 'n02', 'n03'))
    parser.add_argument('--trial', type=int)
    parser.add_argument('--pilot', action='store_true')
    args = parser.parse_args()
    stats = args.capture_stats.read_text()
    captured = re.findall(r'^(\d+) packets? captured$', stats, re.MULTILINE)
    dropped = re.findall(r'^(\d+) packets? dropped by kernel$', stats, re.MULTILINE)
    if len(captured) != 1 or dropped != ['0']:
        raise ValueError('requires one complete zero-drop capture report')
    rows = [json.loads(line) for line in args.report.read_text().splitlines()]

    def lines():
        for path in args.traces:
            with path.open() as stream:
                yield from stream

    with args.capture.open('rb') as stream:
        result = analyze_wire(rows, read_pcap(stream), read_traces(lines()),
                              host=args.host, trial=args.trial, pilot=args.pilot)
    if result['capture']['capture']['packets'] != int(captured[0]):
        raise ValueError('capture report packet count differs from PCAP')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
