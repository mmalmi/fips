"""Bounded exposure and all-hop progress through complete original proof cleanup."""

from concurrent.futures import ThreadPoolExecutor
import time

from . import wifi_probes as probes
from . import wifi_authorization_trace as authorization_trace
from .paid_settlement import require
from .wifi_priority_checks import submitted
from .wifi_receiver_observer import POLL_SECONDS, ReceiverObserver


def caught_up(progress):
    return (not progress['in_flight'] and progress['acknowledged_msat'] is not None
            and progress['acknowledged_msat'] >= max(progress['authorized_sat'] * 1000,
                                                    progress['evidence_msat']))


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
        # A rounded-up claim can prepay almost one sat. Further debt must
        # arrive in whole packets, rather than at a continuous byte rate.
        packets_to_next_sat = (1000 + lower - 1) // lower
        quantization = (packets_to_next_sat * 1_000_000 + 2) // 3
        require(quantization + 500_000 < 2_000_000, 'payload price/rate cannot ensure two-second whole-sat cadence')
        hops.append(dict(capacity_sat=capacity, maximum_evidence_msat=needed,
                         calibrated_warmup_msat=delta, price=price, minimum_payload_msat=lower,
                         maximum_quantization_us=quantization))
    return dict(remaining_packets=packets, hops=hops)


def values(sample, payment_field='authorized_sat'):
    return [sample['delivered'], *[p[payment_field] for p in sample['payments']], *sample['credits']]


def progress(baseline, samples, custody_samples=(), *, payment_field='authorized_sat', expected_packets=None):
    require(len(samples) >= 2, 'whole-window progress requires multiple observations')
    first, previous = values(baseline, payment_field), values(baseline, payment_field)
    previous_time = baseline['elapsed_us']
    result = dict(counter_order=['delivered', 'source_' + payment_field, 'relay_' + payment_field,
                                 'first_provider_credit_msat', 'second_provider_credit_msat'],
                  limit_us=2_000_000, all_counters_advanced=False, within_limit=False,
                  progress_between_unfinished_cleanup_samples=False,
                  timing_resolution_sufficient=False, timing_verdict=['unqualified'] * 5)
    if expected_packets is not None:
        require(type(expected_packets) is int and expected_packets > 0 and first[0] == 0,
                'delivery timing requires a fresh bounded stream')
        result.update(delivery_expected_packets=expected_packets, delivery_complete_us=None)
    if any('counter_reads' not in sample for sample in [baseline, *samples]):
        return dict(result, timing_refusal='per-counter read intervals missing')
    previous_reads = baseline['counter_reads']
    lower, upper = [previous_time] * 5, [previous_time] * 5
    gaps, minimum, read_gaps, durations = [[0] * 5 for _ in range(4)]
    observed = [0] * 5
    for sample in samples:
        now, current = sample['elapsed_us'], values(sample, payment_field)
        require(now > previous_time, 'progress observation time did not advance')
        require(expected_packets is None or current[0] <= expected_packets,
                'delivery count exceeds the original stream')
        require(len(sample['counter_reads']) == len(previous_reads) == 5, 'progress timing count changed')
        for index, value in enumerate(current):
            require(value >= previous[index], 'paid progress counter reset')
            reading, prior = sample['counter_reads'][index], previous_reads[index]
            if reading == prior:
                require(value == previous[index], 'cached progress changed without a fresh read')
                continue
            start, end = reading['started_us'], reading['finished_us']
            require(prior['finished_us'] <= start <= end <= now, 'progress read intervals overlap or run backwards')
            # Once every expected packet arrived, waiting for payment receipts
            # is no longer a delivery gap. Still validate all subsequent reads
            # and retain the full payment and provider-credit observation.
            if index == 0 and expected_packets is not None and previous[0] == expected_packets:
                continue
            observed[index] += 1
            durations[index] = max(durations[index], end - start)
            read_gaps[index] = max(read_gaps[index], end - prior['started_us'])
            # An advance occurred after the previous read began, not at this
            # batch's completion. Keep both event-time bounds conservatively.
            gaps[index] = max(gaps[index], end - lower[index])
            if value > previous[index]:
                lower[index], upper[index] = prior['started_us'], end
                if index == 0 and value == expected_packets:
                    result['delivery_complete_us'] = end
            else:
                minimum[index] = max(minimum[index], start - upper[index])
        previous, previous_time, previous_reads = current, now, sample['counter_reads']
    if expected_packets is not None:
        require(previous[0] == expected_packets and result['delivery_complete_us'] is not None,
                'delivery timing requires every original packet')
    verdict = ['failed' if least > 2_000_000 else 'passed' if count >= 2 and gap <= 2_000_000 else 'unqualified'
               for gap, least, count in zip(gaps, minimum, observed)]
    pending = [sample for sample in custody_samples if sample.get('complete', True) and sample['cleanup_pending']]
    between = [sample for sample in samples if len(pending) >= 2
               and all(pending[0]['elapsed_us'] <= read['started_us']
                       and read['finished_us'] <= pending[-1]['started_us'] for read in sample['counter_reads'])]
    interior = len(between) >= 2 and all(y > x for x, y in zip(values(between[0], payment_field),
                                                            values(between[-1], payment_field)))
    return dict(result, max_observed_gap_us=gaps, minimum_gap_us=minimum,
                max_read_interval_us=read_gaps, max_read_duration_us=durations,
                observed_counter_reads=observed,
                all_counters_advanced=all(last > start for last, start in zip(previous, first)),
                within_limit=all(value == 'passed' for value in verdict),
                timing_verdict=verdict, timing_resolution_sufficient='unqualified' not in verdict,
                progress_between_unfinished_cleanup_samples=interior,
                observation_us=previous_time - baseline['elapsed_us'])


def payment_reconciled(sample, reading, index, after):
    if any(read['started_us'] < after for read in sample['counter_reads']):
        return False
    payment, state = sample['payments'][index], reading['value']
    return (reading['started_us'] >= after and caught_up(state) and state['pending'] is None
            and payment['authorized_sat'] == payment['signed_sat'] == state['authorized_sat']
            and sample['credits'][index] >= state['authorized_sat'] * 1000)


def reconciled(sample, statuses, after):
    return statuses is not None and all(payment_reconciled(sample, statuses[name], index, after)
                                       for index, name in enumerate(('source', 'n02')))


def measure(run, held, held_credits):
    shape = probes.arm(run, 'source', 'destination', 84, 1000, lifetime_secs=90)
    started = time.monotonic()
    held_values = [0, held[0]['payment_progress'][run.transit]['authorized_sat'],
                   held[1]['payment_progress'][run.guard]['authorized_sat'], *held_credits]
    row = dict(shape=shape, baseline=None, samples=[], custody_samples=[],
               observer='independently polled counters and bounded read-only original-Y queries',
               observer_busy_timeout_ms=250, observer_query_timeout_ms=1000,
               custody_minimum_start_interval_us=1_000_000, custody_remote_timeout_seconds=3,
               progress_poll_delay_us=int(POLL_SECONDS * 1_000_000), maximum_queued_progress_reads=2048,
               progress_payments='durable authorization and completed signature balances',
               payment_channels=[run.transit, run.guard], authorization_commit_observation={},
               cleanup_finished_us=None, traffic_finished_us=None, passed=False)
    run.evidence['receiver_history']['live'] = row
    run.save()
    saved_at = time.monotonic()

    def save_diagnostics():
        nonlocal saved_at
        now = time.monotonic()
        if now - saved_at >= 1:
            run.save()
            saved_at = now

    with ThreadPoolExecutor(max_workers=1) as sender, ReceiverObserver(run, shape, started, row) as observer:
        observer.start_custody()
        # Read both trace boundaries alongside the initial counter reads; an
        # additional serial status round trip would consume the release budget.
        authorization_baseline = sender.submit(authorization_trace.capture, run, started)
        baseline = observer.baseline()
        held_payments = [status['payment_progress'][channel] for status, channel in zip(held, (run.transit, run.guard))]
        row['baseline'], row['baseline_payment_status'] = baseline, held_payments
        require(baseline['delivered'] == 0 and all(current >= old for current, old in zip(values(baseline), held_values))
                and all(payment['authorized_sat'] == payment['signed_sat'] == earlier['authorized_sat']
                        and caught_up(earlier) and credit >= payment['signed_sat'] * 1000
                        for payment, earlier, credit in zip(baseline['payments'], held_payments, baseline['credits'])),
                'original stream or payment baseline changed before its one send')
        row['authorization_commit_observation']['baseline'] = authorization_baseline.result()
        row['stream_started_us'] = int((time.monotonic() - started) * 1_000_000)
        observer.start()
        sending = sender.submit(probes.send, run, 'source', 'destination', shape, 3,
                                max_duration_secs=60, operation_timeout=75)
        released, final_custody, terminal_progress = False, False, None
        authorization_terminal = {}
        try:
            while time.monotonic() - started < 35:
                observer.start_custody()
                if terminal_progress is None:
                    row['samples'].extend(observer.progress())
                    current = row['samples'][-1] if row['samples'] else None
                    if current is not None and current['delivered'] == 84:
                        if row['traffic_finished_us'] is None:
                            row['traffic_finished_us'] = current['counter_reads'][0]['finished_us']
                        statuses = observer.payment_status()
                        if statuses is not None:
                            candidates = {name: observer.authorization_status[name]
                                          for index, name in enumerate(('source', 'n02'))
                                          if payment_reconciled(current, statuses[name], index, row['traffic_finished_us'])}
                            authorization_terminal = authorization_trace.terminal_records(authorization_terminal, candidates)
                        if reconciled(current, statuses, row['traffic_finished_us']) and len(authorization_terminal) == 2:
                            row['samples'].extend(observer.stop_and_drain())
                            require(reconciled(row['samples'][-1], statuses, row['traffic_finished_us']),
                                    'final progress differs from fresh scheduler acknowledgment')
                            row['authorization_commit_observation']['terminal'] = authorization_terminal
                            run.check_forwards()
                            run.monitor.check()
                            terminal_progress = int((time.monotonic() - started) * 1_000_000)
                            row['terminal_progress_us'] = terminal_progress
                            row['terminal_payment_status'] = statuses
                checked = observer.poll_custody()
                if checked is not None:
                    row['custody_samples'].append(checked)
                    if not checked.get('complete', True):
                        save_diagnostics()
                        time.sleep(.05)
                        continue
                    if not released:
                        require(run.nodes['n02'].held() and checked['cleanup_pending'],
                                'receiver cleanup escaped the original held writer')
                        require(time.monotonic() - started < 2 and not sending.done(),
                                'original live stream did not begin before release')
                        if row['samples'] and row['samples'][-1]['delivered'] > 0:
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
                save_diagnostics()
                time.sleep(.05)
            require(released and final_custody and row['cleanup_finished_us'] is not None
                    and row['traffic_finished_us'] is not None,
                    'whole original receiver cleanup did not finish inside35 seconds')
        finally:
            # Keep this exact stream and any failed samples; never resend it.
            try:
                row['samples'].extend(observer.stop_and_drain())
            finally:
                try:
                    row['sender'] = sending.result(timeout=75)
                finally:
                    run.save()
    submitted(row['sender'], shape)
    row['receiver'] = probes.receive(run, 'source', 'destination', shape, complete=True)
    row['polled_progress'] = progress(baseline, row['samples'], row['custody_samples'],
                                      expected_packets=shape['packet_count'])
    row['progress'] = authorization_trace.qualify(row['polled_progress'], row)
    row['signed_progress'] = progress(baseline, row['samples'], row['custody_samples'],
                                      payment_field='signed_sat', expected_packets=shape['packet_count'])
    # Even if the last packet and cleanup appear in one polling sample, only
    # claim coverage when cleanup preceded the earliest possible final send.
    earliest_final = row['stream_started_us'] + int((shape['packet_count'] - 1) / 3 * 1_000_000)
    row['progress'].update(cleanup_finished_us=row['cleanup_finished_us'], traffic_finished_us=row['traffic_finished_us'],
                           earliest_final_send_us=earliest_final,
                           traffic_covers_cleanup=row['cleanup_finished_us'] < earliest_final)
    row['passed'] = (all(row['progress'][key] for key in ('within_limit', 'all_counters_advanced', 'traffic_covers_cleanup'))
                     and row['signed_progress']['within_limit'] and row['signed_progress']['all_counters_advanced'])
    run.save()
    return row
