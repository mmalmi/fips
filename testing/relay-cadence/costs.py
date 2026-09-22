"""Integer counter deltas shared by workload summaries and complete intervals."""
from collections import defaultdict

from validation import PAYMENT_OPERATIONS, payment_counters, unsigned, validate_measurements

JOURNALS = ('journal_writes', 'journal_bytes_written', 'journal_syncs', 'journal_commits')
LINKS = ('sent_bytes', 'received_bytes', 'sent_packets', 'received_packets')


def delta(before, after, key):
    a, b = unsigned(before[key]), unsigned(after[key])
    if b < a:
        raise ValueError(f'missing or reset counter: {key}')
    return b - a


def counters(before, after):
    if before.keys() != after.keys():
        raise ValueError('counter layout changed')
    return {key: delta(before, after, key) for key in before}


def add_counts(total, value):
    """Sum only integer counter trees; metadata and ratios never enter totals."""
    for key, item in value.items():
        if isinstance(item, dict):
            add_counts(total.setdefault(key, {}), item)
        else:
            total[key] = total.get(key, 0) + unsigned(item)


def sum_counts(values):
    total = {}
    for value in values:
        add_counts(total, value)
    return total


def node_costs(before, after, *, complete=False):
    a, b = before['measurements'], after['measurements']
    validate_measurements(a, b)
    operations = {name: counters(prior, b['operations'][name])
                  for name, prior in a['operations'].items()}
    if any(c['cpu_samples'] != c['spans'] for c in operations.values()):
        raise ValueError('missing thread CPU samples')
    peers = []
    for node in (before, after):
        active = [p for p in node['peers'] if p['connected']]
        indexed = {p['npub']: p for p in active}
        if complete and (len(indexed) != len(active)
                         or any(type(p['connected']) is not bool for p in node['peers'])):
            raise ValueError('duplicate or invalid connected peer')
        peers.append(indexed)
    prior, current = peers
    if prior.keys() != current.keys():
        raise ValueError('connected topology changed during a matched run')
    link_fields = LINKS if complete else ('sent_bytes',)
    links = {key: 0 for key in link_fields}
    for identity, peer in current.items():
        if prior[identity]['link_id'] != peer['link_id']:
            raise ValueError('link counters changed epoch')
        for key in link_fields:
            links[key] += delta(prior[identity], peer, key)
    result = {
        'process_cpu_ns': delta(a, b, 'process_cpu_ns'),
        'operations': operations,
        'journals': {key: sum(c[key] for c in operations.values()) for key in JOURNALS},
        'payment_records': counters(payment_counters(before), payment_counters(after)),
        'links': links,
    }
    if complete:
        if before['payment_progress'].keys() != after['payment_progress'].keys():
            raise ValueError('paying channels changed during observation')
        result['evidence_msat'] = {
            channel: delta(state, after['payment_progress'][channel], 'evidence_msat')
            for channel, state in before['payment_progress'].items()
        }
    return result


def summarize_costs(costs):
    """Keep the historical workload units/output; exact totals stay integers."""
    result = defaultdict(float)
    result['process_cpu_ms'] = costs['process_cpu_ns'] / 1e6
    for name, c in costs['operations'].items():
        for suffix, key in (('writes', 'journal_writes'), ('bytes', 'journal_bytes_written'),
                            ('syncs', 'journal_syncs'), ('commits', 'journal_commits')):
            result['journal_' + suffix] += c[key]
            if name in PAYMENT_OPERATIONS:
                result['payment_journal_' + suffix] += c[key]
        if name in PAYMENT_OPERATIONS:
            result['payment_cpu_ms'] += c['thread_cpu_ns'] / 1e6
            result['payment_spans'] += c['spans']
        if name == 'payment_sign':
            result['signs'] += c['spans']
        if name == 'payment_usage':
            result['usage_polls'] += c['spans']
        if name == 'payment_update':
            result['updates'] += c['spans']
    for name, key in (('payment_record_bytes', 'stream_bytes_sent'),
                      ('payment_requests', 'requests_started'),
                      ('payment_received_bytes', 'stream_bytes_received'),
                      ('payment_received_requests', 'requests_received')):
        result[name] = costs['payment_records'][key]
    result['aggregate_link_bytes'] = costs['links']['sent_bytes']
    return dict(result)
