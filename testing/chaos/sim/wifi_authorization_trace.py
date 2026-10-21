"""Conservative durable-authorization timing on each original process clock.

The bounded diagnostic ring has no financial authority. Full sequence coverage,
quiescent boundaries and independent journal balances are required; signature
completion is never used to infer when an authorization was committed.
"""

from concurrent.futures import ThreadPoolExecutor
import re

from .paid_settlement import require
from . import wifi_measurements

CAPACITY = 1024
LIMIT_NS = 2_000_000_000
U64_MAX = (1 << 64) - 1


def number(value):
    require(type(value) is int and 0 <= value <= U64_MAX, 'invalid authorization trace counter')
    return value


def capture(run, started):
    """Two read-only status calls, with the existing exact process-epoch checks."""
    run.check_forwards()
    run.monitor.check()
    profiles = run.participants()

    def read(name, host, channel):
        status = wifi_measurements.snapshot(profiles[name], host)
        measurements = status['measurements']
        timing = status['sample_timing']
        origin = int(started * 1_000_000_000)
        return dict(channel_id=channel, npub=status['npub'],
                    host_process={key: status['host_process'][key] for key in ('host', 'pid', 'start_ticks')},
                    process_id=measurements['process_id'],
                    process_cpu_ns=measurements['process_cpu_ns'],
                    operations=measurements['operations'],
                    trace=measurements.get('authorization_commits'),
                    payment_progress=status['payment_progress'][channel],
                    started_us=(timing['started_monotonic_ns'] - origin) // 1000,
                    finished_us=(timing['finished_monotonic_ns'] - origin + 999) // 1000)

    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = {name: pool.submit(read, name, host, channel)
                   for name, host, channel in (('source', 'n01', run.transit), ('n02', 'n02', run.guard))}
        result = {name: future.result() for name, future in pending.items()}
    run.check_forwards()
    run.monitor.check()
    return result


def checked(snapshot, channel, balance):
    require(isinstance(snapshot, dict) and snapshot['channel_id'] == channel
            and isinstance(channel, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,128}', channel),
            'authorization trace channel changed')
    identity = snapshot['host_process']
    require(isinstance(snapshot['npub'], str) and snapshot['npub']
            and identity['host'] in ('n01', 'n02')
            and number(identity['pid']) == number(snapshot['process_id']) > 0
            and number(identity['start_ticks']) > 0,
            'authorization trace process identity missing')
    require(0 <= snapshot['started_us'] <= snapshot['finished_us'] <= 35_000_000,
            'authorization trace read exceeds window')
    payment = snapshot['payment_progress']
    require(number(payment['authorized_sat']) == balance and payment['in_flight'] is False
            and number(payment['acknowledged_msat']) >= max(balance * 1000, number(payment['evidence_msat'])),
            'authorization trace boundary is not reconciled')
    trace = snapshot['trace']
    require(isinstance(trace, dict) and trace['version'] == 1
            and trace['clock'] == 'CLOCK_MONOTONIC' and trace['capacity'] == CAPACITY,
            'bounded authorization commit trace required')
    require(trace['sequence_exhausted'] is False and trace['lock_poisoned'] is False
            and number(trace['pending']) == 0, 'authorization trace boundary is incomplete')
    for key in ('completed_sequence', 'overwritten', 'missing_intervals', 'clock_failures', 'aborted'):
        number(trace[key])
    measured = number(trace['measured_at_ns'])
    events = trace['events']
    require(isinstance(events, list) and len(events) <= CAPACITY, 'authorization trace capacity exceeded')
    previous = 0
    for event in events:
        sequence = number(event['sequence'])
        require(previous < sequence <= trace['completed_sequence'], 'authorization trace sequence is invalid')
        require(isinstance(event['channel_id'], str) and 0 < len(event['channel_id'].encode()) <= 128
                and number(event['old_sat']) < number(event['new_sat'])
                and number(event['started_ns']) <= number(event['finished_ns']) <= measured,
                'authorization commit interval is invalid')
        previous = sequence
    retained = [event for event in events if event['channel_id'] == channel]
    require(retained and retained[-1]['new_sat'] == balance, 'authorization trace differs from journal baseline')
    return trace


def channel_progress(before, after, channel, initial, final):
    first, last = checked(before, channel, initial), checked(after, channel, final)
    require(before['npub'] == after['npub'] and before['host_process'] == after['host_process']
            and before['process_id'] == after['process_id'], 'authorization trace process epoch changed')
    require(first['measured_at_ns'] < last['measured_at_ns'], 'authorization trace clock did not advance')
    for key in ('missing_intervals', 'clock_failures', 'aborted'):
        require(first[key] == last[key], 'authorization trace lost interval coverage')
    start, end = first['completed_sequence'], last['completed_sequence']
    require(start < end <= start + CAPACITY and last['overwritten'] >= first['overwritten'],
            'authorization trace cannot cover the complete window')
    events = [event for event in last['events'] if event['sequence'] > start]
    require([event['sequence'] for event in events] == list(range(start + 1, end + 1)),
            'authorization trace required events are missing')
    previous_low = previous_high = first['measured_at_ns']
    upper = lower = count = 0
    balance = initial
    for event in events:
        if event['channel_id'] != channel:
            continue
        require(event['old_sat'] == balance and previous_high <= event['started_ns'],
                'authorization trace balance or interval chain changed')
        upper = max(upper, event['finished_ns'] - previous_low)
        lower = max(lower, event['started_ns'] - previous_high)
        previous_low, previous_high = event['started_ns'], event['finished_ns']
        balance, count = event['new_sat'], count + 1
    require(balance == final and final > initial and count >= 2,
            'authorization trace did not cover original paid progress')
    upper = max(upper, last['measured_at_ns'] - previous_low)
    lower = max(lower, last['measured_at_ns'] - previous_high)
    verdict = 'failed' if lower > LIMIT_NS else 'passed' if upper <= LIMIT_NS else 'unqualified'
    return dict(timing_verdict=verdict, maximum_gap_ns=upper, minimum_gap_ns=lower,
                commits=count, first_sequence=start, final_sequence=end,
                observation_ns=last['measured_at_ns'] - first['measured_at_ns'])


def qualify(polled, row):
    """Replace only the two authorization bounds; retain independent raw reads."""
    boundaries = row['authorization_commit_observation']
    require(set(boundaries) == {'baseline', 'terminal'}, 'authorization trace boundaries missing')
    baseline, terminal = row['baseline'], row['samples'][-1]
    results = []
    for index, name in enumerate(('source', 'n02')):
        before, after = boundaries['baseline'][name], boundaries['terminal'][name]
        require(before['finished_us'] <= row['stream_started_us']
                and after['started_us'] >= max(read['finished_us'] for read in terminal['counter_reads'])
                and after['finished_us'] <= row['terminal_progress_us'],
                'authorization trace does not bracket the complete original stream')
        results.append(channel_progress(before, after, row['payment_channels'][index],
                       baseline['payments'][index]['authorized_sat'], terminal['payments'][index]['authorized_sat']))
    result = dict(polled, timing_verdict=list(polled['timing_verdict']),
                  max_observed_gap_us=list(polled['max_observed_gap_us']),
                  minimum_gap_us=list(polled['minimum_gap_us']),
                  authorization_commits=results,
                  authorization_timing_source='complete process-local durable commit intervals')
    for index, trace in enumerate(results, 1):
        result['timing_verdict'][index] = trace['timing_verdict']
        result['max_observed_gap_us'][index] = (trace['maximum_gap_ns'] + 999) // 1000
        result['minimum_gap_us'][index] = trace['minimum_gap_ns'] // 1000
    result['within_limit'] = all(verdict == 'passed' for verdict in result['timing_verdict'])
    result['timing_resolution_sufficient'] = 'unqualified' not in result['timing_verdict']
    return result
