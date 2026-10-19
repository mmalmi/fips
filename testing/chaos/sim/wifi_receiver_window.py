"""Bounded exposure and all-hop progress through complete original proof cleanup."""

from concurrent.futures import ThreadPoolExecutor
import time

from . import wifi_probes as probes
from .paid_settlement import require
from .wifi_priority_checks import submitted
from .wifi_receiver_observer import ReceiverObserver


def exposure(before, warm, current, channels, packets):
    hops = []
    for index, channel in enumerate(channels):
        delta = warm[index]['payment_progress'][channel]['evidence_msat'] - before[index]['payment_progress'][channel]['evidence_msat']
        purchase, = [p for p in current[index]['purchases'] if p['channel']['id'] == channel]
        price, capacity = purchase['contract']['price'], purchase['channel']['capacity_sat']
        lower = 1000 * price['msat'] // price['per_bytes']
        needed = current[index]['payment_progress'][channel]['evidence_msat'] + (delta + 1) * packets
        require(delta > 0 and lower > 0 and (needed + 999) // 1000 < capacity,
                f'hop{index}: warmup={delta}msat, bound={needed}msat for{packets} packets, capacity={capacity}sat')
        quantization = (1_000_000_000 + lower * 3 - 1) // (lower * 3)
        require(quantization + 500_000 < 2_000_000, 'payload price/rate cannot ensure two-second whole-sat cadence')
        hops.append(dict(capacity_sat=capacity, maximum_evidence_msat=needed,
                         calibrated_warmup_msat=delta, price=price, minimum_payload_msat=lower,
                         maximum_quantization_us=quantization))
    return dict(remaining_packets=packets, hops=hops)


def values(sample):
    return [sample['delivered'], *[p['authorized_sat'] for p in sample['payments']], *sample['credits']]


def progress(baseline, samples, custody_samples=()):
    require(len(samples) >= 2, 'whole-window progress requires multiple observations')
    first, previous = values(baseline), values(baseline)
    previous_time = baseline['elapsed_us']
    result = dict(counter_order=['delivered', 'source_authorized_sat', 'relay_authorized_sat',
                                 'first_provider_credit_msat', 'second_provider_credit_msat'],
                  limit_us=2_000_000, all_counters_advanced=False, within_limit=False,
                  progress_between_unfinished_cleanup_samples=False,
                  timing_resolution_sufficient=False, timing_verdict=['unqualified'] * 5)
    if any('counter_reads' not in sample for sample in [baseline, *samples]):
        return dict(result, timing_refusal='per-counter read intervals missing')
    previous_reads = baseline['counter_reads']
    lower, upper = [previous_time] * 5, [previous_time] * 5
    gaps, minimum, read_gaps, durations = [[0] * 5 for _ in range(4)]
    for sample in samples:
        now, current = sample['elapsed_us'], values(sample)
        require(now > previous_time, 'progress observation time did not advance')
        require(len(sample['counter_reads']) == len(previous_reads) == 5, 'progress timing count changed')
        for index, value in enumerate(current):
            require(value >= previous[index], 'paid progress counter reset')
            reading, prior = sample['counter_reads'][index], previous_reads[index]
            start, end = reading['started_us'], reading['finished_us']
            require(prior['finished_us'] <= start <= end <= now, 'progress read intervals overlap or run backwards')
            durations[index] = max(durations[index], end - start)
            read_gaps[index] = max(read_gaps[index], end - prior['started_us'])
            # An advance occurred after the previous read began, not at this
            # batch's completion. Keep both event-time bounds conservatively.
            gaps[index] = max(gaps[index], end - lower[index])
            if value > previous[index]:
                lower[index], upper[index] = prior['started_us'], end
            else:
                minimum[index] = max(minimum[index], start - upper[index])
        previous, previous_time, previous_reads = current, now, sample['counter_reads']
    verdict = ['passed' if gap <= 2_000_000 else 'failed' if least > 2_000_000 else 'unqualified'
               for gap, least in zip(gaps, minimum)]
    pending = [sample for sample in custody_samples if sample['cleanup_pending']]
    between = [sample for sample in samples if len(pending) >= 2
               and all(pending[0]['elapsed_us'] <= read['started_us']
                       and read['finished_us'] <= pending[-1]['started_us'] for read in sample['counter_reads'])]
    interior = len(between) >= 2 and all(y > x for x, y in zip(values(between[0]), values(between[-1])))
    return dict(result, max_observed_gap_us=gaps, minimum_gap_us=minimum,
                max_read_interval_us=read_gaps, max_read_duration_us=durations,
                all_counters_advanced=all(last > start for last, start in zip(previous, first)),
                within_limit=all(value == 'passed' for value in verdict),
                timing_verdict=verdict, timing_resolution_sufficient='unqualified' not in verdict,
                progress_between_unfinished_cleanup_samples=interior,
                observation_us=previous_time - baseline['elapsed_us'])


def measure(run, held, held_credits):
    shape = probes.arm(run, 'source', 'destination', 84, 1000, lifetime_secs=90)
    started = time.monotonic()
    held_values = [0, held[0]['payment_progress'][run.transit]['authorized_sat'],
                   held[1]['payment_progress'][run.guard]['authorized_sat'], *held_credits]
    row = dict(shape=shape, baseline=None, samples=[], custody_samples=[],
               observer='independent timed progress and bounded read-only original-Y queries',
               observer_busy_timeout_ms=250, observer_query_timeout_ms=1000,
               cleanup_finished_us=None, traffic_finished_us=None, passed=False)
    run.evidence['receiver_history']['live'] = row
    run.save()
    with ThreadPoolExecutor(max_workers=1) as sender, ReceiverObserver(run, shape, started) as observer:
        observer.start_custody()
        baseline = observer.progress()
        require(baseline['delivered'] == 0 and all(current >= old for current, old in zip(values(baseline), held_values)),
                'original stream or payment baseline changed before its one send')
        row['baseline'] = baseline
        row['stream_started_us'] = int((time.monotonic() - started) * 1_000_000)
        sending = sender.submit(probes.send, run, 'source', 'destination', shape, 3,
                                max_duration_secs=60, operation_timeout=75)
        released, final_custody, terminal_progress = False, False, None
        try:
            while time.monotonic() - started < 35:
                if terminal_progress is None:
                    current = observer.progress()
                    row['samples'].append(current)
                    if current['delivered'] == 84:
                        if row['traffic_finished_us'] is None:
                            row['traffic_finished_us'] = current['counter_reads'][0]['finished_us']
                        if all(read['started_us'] >= row['traffic_finished_us'] for read in current['counter_reads'][1:]) \
                                and all(credit >= payment['authorized_sat'] * 1000
                                        for credit, payment in zip(current['credits'], current['payments'])) \
                                and all(not p['in_flight'] and p['acknowledged_msat'] is not None
                               and p['acknowledged_msat'] >= max(p['authorized_sat'] * 1000, p['evidence_msat'])
                               for p in current['payments']):
                            terminal_progress = current['elapsed_us']
                            row['terminal_progress_us'] = terminal_progress
                checked = observer.poll_custody()
                if checked is not None:
                    row['custody_samples'].append(checked)
                    if not released:
                        require(run.nodes['n02'].held() and checked['cleanup_pending'],
                                'receiver cleanup escaped the original held writer')
                        require(time.monotonic() - started < 2 and not sending.done(),
                                'original live stream did not begin before release')
                        if current['delivered'] > 0:
                            run.release_holds(run.held_nodes)
                            released = True
                            row['released_us'] = int((time.monotonic() - started) * 1_000_000)
                    elif not checked['cleanup_pending'] and row['cleanup_finished_us'] is None:
                        row['cleanup_finished_us'] = checked['elapsed_us']
                    if row['cleanup_finished_us'] is not None:
                        require(not checked['cleanup_pending'], 'completed original cleanup reappeared')
                    if terminal_progress is not None and checked['started_us'] >= terminal_progress \
                            and not checked['cleanup_pending'] and checked['elapsed_us'] <= 35_000_000:
                        final_custody = True
                        break
                    observer.start_custody()
                run.save()
                time.sleep(.05)
            require(released and final_custody and row['cleanup_finished_us'] is not None
                    and row['traffic_finished_us'] is not None,
                    'whole original receiver cleanup did not finish inside35 seconds')
        finally:
            # Keep this exact stream and any failed samples; never resend it.
            try:
                row['sender'] = sending.result(timeout=75)
            finally:
                run.save()
    submitted(row['sender'], shape)
    row['receiver'] = probes.receive(run, 'source', 'destination', shape, complete=True)
    row['progress'] = progress(baseline, row['samples'], row['custody_samples'])
    # Even if the last packet and cleanup appear in one polling sample, only
    # claim coverage when cleanup preceded the earliest possible final send.
    earliest_final = row['stream_started_us'] + int((shape['packet_count'] - 1) / 3 * 1_000_000)
    row['progress'].update(cleanup_finished_us=row['cleanup_finished_us'], traffic_finished_us=row['traffic_finished_us'],
                           earliest_final_send_us=earliest_final,
                           traffic_covers_cleanup=row['cleanup_finished_us'] < earliest_final)
    row['passed'] = all(row['progress'][key] for key in ('within_limit', 'all_counters_advanced', 'traffic_covers_cleanup'))
    return row
