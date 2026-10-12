"""Analyze the two equal-volume background phone-transit windows."""

import argparse
import json
from pathlib import Path
import sys

from costs import node_costs, summarize_costs

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'chaos'))
from sim.paid_settlement import require
from sim.stream_probe import validate_stream


NODES = ('n01', 'phone', 'n02', 'n03')
RATES = {'background': 32, 'background-high-rate': 256}
BYTES = 4 * 1024**2
SCOPE = (
    'One ordered pair, same processes, peers and payment channels, four MiB per direction '
    'and fixed 300-second windows. Streams keep pumping after completion for ACK recovery, '
    'so full-window CPU includes different idle tails and diagnostics. Completion throughput '
    'includes setup and final ACK. Logical journal bytes are not physical flash/SQLite '
    'attribution; payment record bytes are not complete wire attribution. Payment CPU '
    'excludes scheduler and TCP/FIPS/core transport work. USB powered with the app hidden; '
    'no natural deep-idle, battery-life, throughput ceiling or optimization claim.'
)


def window_costs(window, identities):
    mode = window['mode']
    require(window['passed'] and not window['unpaid'] and not window['errors'],
            'rate window did not finish successfully')
    require(set(window['results']) == set(window['shapes']) == {'n01', 'n03'},
            'rate window lacks both endpoints')
    require(window['before']['process'] == window['after']['process'], 'phone process changed')
    require(window['samples'] and all(s['line_verified'] and s['foreground_service']
            and s['wakefulness'] == 'Awake' for s in window['samples']), 'missing background observations')
    completion = {}
    for name, report in window['results'].items():
        shape = window['shapes'][name]
        require(shape['peer'] == identities['n03' if name == 'n01' else 'n01']
                and shape['bytes'] == BYTES and shape['duration_secs'] == 300
                and shape['bytes_per_second'] == RATES[mode] * 1024,
                'matched rate workload changed')
        validate_stream(report, shape)
        require(report['elapsed_us'] >= 300_000_000 and report['completed_us'] > 0,
                'rate window or completion time is incomplete')
        completion[name] = report['completed_us'] / 1e6
    before = dict(window['routers_before'], phone=window['payment_before'])
    after = dict(window['routers_after'], phone=window['payment_after'])
    require(set(before) == set(after) == set(NODES), 'missing forwarding-hop measurements')
    measured, summaries = {}, {}
    for name in NODES:
        a, b = before[name], after[name]
        require(a['npub'] == b['npub'] == identities[name], 'measured node identity changed')
        require(a['measurements']['version'] == 3, 'exclusive payment CPU counters required')
        require(a['funding_budget']['wallet_debited_sat'] == b['funding_budget']['wallet_debited_sat'] == 32,
                'rate window changed original channel funding')
        require(a['purchases'] and a['purchases'] == b['purchases'], 'rate window changed purchased terms')
        require(len(a['payment_progress']) == 1 and a['payment_progress'].keys() == b['payment_progress'].keys(),
                'rate window changed original paying channels')
        for channel, prior in a['payment_progress'].items():
            current = b['payment_progress'][channel]
            require(all(current[key] > prior[key] for key in ('evidence_msat', 'authorized_sat', 'acknowledged_msat'))
                    and current['authorized_sat'] <= 32 and current['in_flight'] is False
                    and current['acknowledged_msat'] >= current['authorized_sat'] * 1000,
                    'a paying hop did not advance and acknowledge payment within its channel')
        measured[name] = node_costs(a, b, complete=True)
        total = summarize_costs(measured[name])
        require(total['payment_cpu_ms'] > 0, 'payment CPU was not measured')
        summaries[name] = {
            **total, 'payment_cpu_ms_per_payload_mib': total['payment_cpu_ms'] / 8,
            'process_cpu_ms_per_payload_mib': total['process_cpu_ms'] / 8,
        }
    return {
        'offered_kib_per_second_per_direction': RATES[mode], 'payload_mib_per_direction': 4,
        'completion_seconds': completion,
        'completion_kib_per_second_per_direction': {n: 4096 / t for n, t in completion.items()},
        'phone_cpu_seconds': window['cpu_seconds'], 'phone_memory_after_kib': window['after']['memory_kib'],
        'nodes': summaries, 'counters': measured, 'samples': len(window['samples']),
    }


def analyze(result):
    require(result['passed'] and result['compare_transit_rates_requested']
            and not result['impaired_transit_requested'], 'report is not an accepted healthy rate comparison')
    identities = dict(result['test_identities'], phone=result['phone_npub'])
    require(set(identities) == set(NODES) and len(set(identities.values())) == len(NODES),
            'rate comparison needs four distinct identities')
    windows = [w for w in result['windows'] if w['mode'].startswith('background')]
    require([w['mode'] for w in windows] == list(RATES), 'rate comparison ordering or population changed')
    summaries = {w['mode']: window_costs(w, identities) for w in windows}
    first, last = windows
    require(first['after']['process'] == last['before']['process'], 'phone restarted between rates')
    a = dict(first['routers_after'], phone=first['payment_after'])
    b = dict(last['routers_before'], phone=last['payment_before'])
    for name in NODES:
        # Validate the unmeasured gap too; neither an epoch nor a counter reset
        # may make the second rate look cheaper.
        node_costs(a[name], b[name], complete=True)
        require(a[name]['purchases'] == b[name]['purchases'], 'purchased terms changed between rates')
    return {'comparison': summaries, 'scope': SCOPE}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('report', type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(json.loads(args.report.read_text())), indent=2))
