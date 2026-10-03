"""Read opt-in admission traces; these observations never accept financial cost."""

import json
import re
from pathlib import Path

LIMIT = 4 * 1024 * 1024
EVENT = re.compile(r'^\s*(\d+)\.(\d{9})s\s+TRACE fips_admission: (.*)$')
FIELD = re.compile(r'\b([a-z_]+)=("[a-z_]+"|true|false|\d+)(?=\s|$)')
FIELDS = {
    'clock': {'epoch_unix_us', 'uncertainty_us'},
    'published': {'persist_us', 'increased'},
    'queued': {'packets', 'bytes'},
    'wake': {'packets'},
    'readmitted': {'wait_us', 'bytes'},
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read_log(path):
    require(path.stat().st_size <= LIMIT + 128, 'trace exceeds retained-log cap')
    header, separator, body = path.read_bytes().partition(b'\n')
    match = re.fullmatch(rb'# original_bytes=(\d+) omitted_prefix_bytes=(\d+)', header)
    require(separator and match is not None, 'missing trace retention evidence')
    original, omitted = map(int, match.groups())
    require(omitted == 0 and original == len(body), 'incomplete admission trace')
    events = []
    for line in body.decode('utf-8').splitlines():
        if 'fips_admission:' not in line:
            continue
        match = EVENT.fullmatch(line)
        require(match is not None, 'admission trace requires monotonic log timestamps')
        seconds, nanos, message = match.groups()
        pairs = FIELD.findall(message)
        fields = dict(pairs)
        require(len(fields) == len(pairs), 'duplicate trace field')
        kind = fields.pop('event', '').strip('"')
        require(kind in FIELDS and set(fields) == FIELDS[kind], 'unsupported admission event')
        for key, value in fields.items():
            if key == 'increased':
                require(value in ('true', 'false'), 'invalid publication flag')
                fields[key] = value == 'true'
            else:
                require(value.isdecimal(), 'invalid trace counter')
                fields[key] = int(value)
        events.append({'at_ns': int(seconds) * 1_000_000_000 + int(nanos),
                       'event': kind, **fields})
    require(events, 'no admission timing evidence')
    # Concurrent writers may acquire the log sink in a different order.
    events.sort(key=lambda row: row['at_ns'])
    anchors = [e for e in events if e['event'] == 'clock']
    require(len(anchors) == 1 and events[0] == anchors[0], 'missing or repeated process clock')
    require(anchors[0]['epoch_unix_us'] > 0, 'invalid process clock')
    return anchors[0], events


def distribution(values):
    if not values:
        return {'samples': 0, 'mean_us': None, 'max_us': None, 'p50_us': None, 'p95_us': None}
    values = sorted(values)
    return {'samples': len(values), 'mean_us': sum(values) / len(values), 'max_us': values[-1],
            **{f'p{p}_us': values[(len(values) * p + 99) // 100 - 1] for p in (50, 95)}}


def summarize(report, log_directory):
    metadata = report[0]
    require(metadata.get('admission_timing') is True
            and metadata['log_filter'] == 'warn,fips_admission=trace'
            and metadata['retained_log_tail_bytes_per_node'] == LIMIT,
            'not an admission-timing capture')
    rows = [r for r in report if 'data' in r]
    require([(r['trial'], r['data']['workload']) for r in rows]
            == [(trial, name) for trial in (0, 1)
                for name in ('idle', 'bursty', 'steady', 'high_rate')], 'incomplete workload sequence')
    logs = {}
    expected = {f'trial-{trial}/node-{node}.log' for trial in (0, 1) for node in range(5)}
    require({str(p.relative_to(log_directory)) for p in log_directory.rglob('*.log')} == expected,
            'missing or unexpected node log')
    for trial in (0, 1):
        for node in range(5):
            logs[trial, node] = read_log(log_directory / f'trial-{trial}/node-{node}.log')
    result = []
    for row in rows:
        data, trial = row['data'], row['trial']
        start, end = data['started_unix_us'], data['finished_unix_us']
        require(type(start) is int and type(end) is int and end > start, 'invalid workload clock')
        require(abs(end - start - data['clock_span_us']) <= 5_000, 'workload wall clock changed')
        for node in range(5):
            anchor, events = logs[trial, node]
            # Wall-clock alignment is approximate; reported event durations use
            # monotonic clocks. Exclude observations near each workload boundary.
            margin = anchor['uncertainty_us'] + 5_000
            require(end - start > 2 * margin, 'clock uncertainty covers the workload')
            active = [e for e in events if start + margin
                      < anchor['epoch_unix_us'] + e['at_ns'] // 1_000 < end - margin]
            result.append({
                'trial': trial, 'workload': data['workload'], 'node': node,
                'alignment_margin_us': margin,
                'queued_events': sum(e['event'] == 'queued' for e in active),
                'wake_events': sum(e['event'] == 'wake' for e in active),
                'publication': distribution([e['persist_us'] for e in active
                                              if e['event'] == 'published']),
                'readmission_wait': distribution([e['wait_us'] for e in active
                                                  if e['event'] == 'readmitted']),
            })
    return {'performance_accepted': False, 'workloads': result,
            'scope': 'Trace-enabled diagnostic. Publication includes serialization, disk I/O and '
                     'ceiling publication. Wait ends at readmission, before transport submission. '
                     'Durations use monotonic clocks; workload alignment uses local wall clocks. '
                     'Wake notifications coalesce, so counts do not identify a causal refill. '
                     'This report does not accept delivery, money conservation or cost boundaries.'}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    parser.add_argument('logs', type=Path)
    args = parser.parse_args()
    rows = [json.loads(line) for line in args.report.read_text().splitlines()]
    print(json.dumps(summarize(rows, args.logs), indent=2))
