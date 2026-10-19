"""Bounded exposure and all-hop progress through complete original proof cleanup."""

from concurrent.futures import ThreadPoolExecutor
import time

from . import wifi_probes as probes
from . import wifi_receiver_custody as custody
from .paid_settlement import require
from .wifi_priority_checks import submitted


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


def progress(baseline, samples):
    require(len(samples) >= 2, 'whole-window progress requires multiple observations')
    first, previous = values(baseline), values(baseline)
    previous_time = baseline['elapsed_us']
    advanced_at, gaps = [previous_time] * 5, [0] * 5
    for sample in samples:
        now, current = sample['elapsed_us'], values(sample)
        require(now > previous_time, 'progress observation time did not advance')
        for index, value in enumerate(current):
            require(value >= previous[index], 'paid progress counter reset')
            gaps[index] = max(gaps[index], now - advanced_at[index])
            if value > previous[index]:
                advanced_at[index] = now
        previous, previous_time = current, now
    interior = any(a['cleanup_pending'] and b['cleanup_pending']
                   and all(y > x for x, y in zip(values(a), values(b)))
                   for i, a in enumerate(samples) for b in samples[i + 1:])
    return dict(counter_order=['delivered', 'source_authorized_sat', 'relay_authorized_sat',
                               'first_provider_credit_msat', 'second_provider_credit_msat'],
                max_observed_gap_us=gaps, limit_us=2_000_000,
                all_counters_advanced=all(last > start for last, start in zip(previous, first)),
                within_limit=all(gap <= 2_000_000 for gap in gaps),
                progress_between_unfinished_cleanup_samples=interior,
                observation_us=previous_time - baseline['elapsed_us'])


def sample(run, shape, started, pool):
    actions = {'source': lambda: run.ctl('source', 'status', operation_timeout=3),
               'relay': lambda: run.ctl('n02', 'status', operation_timeout=3),
               'received': lambda: probes.receive(run, 'source', 'destination', shape),
               'credit1': lambda: run.credit('n02', run.transit),
               'credit2': lambda: run.credit('n03', run.guard),
               'journal': run.journal,
               'proofs': lambda: custody.live(run.nodes['n02'], run.originals)}
    pending = {key: pool.submit(call) for key, call in actions.items()}
    state = {key: future.result(timeout=5) for key, future in pending.items()}
    require(any(row == run.intents[run.guard] for row in state['journal']['funding'].values()),
            'cleanup changed the original active guard funding')
    remaining = state['proofs']
    require(all(remaining.get(key) == 'SPENT' for key in run.guard_inputs)
            and all(remaining.get(key) == 'UNSPENT' for key in run.unspent),
            'cleanup changed the exact guard or spendable original identities')
    retained = run.incoming in state['journal']['seller_settlements']
    return dict(elapsed_us=int((time.monotonic() - started) * 1_000_000),
                delivered=state['received']['unique_packets'],
                payments=[state['source']['payment_progress'][run.transit],
                          state['relay']['payment_progress'][run.guard]],
                credits=[state['credit1'], state['credit2']], receiver_retained=retained,
                remaining_originals=len(remaining), cleanup_pending=retained or len(remaining) != 63)


def measure(run, held, held_credits):
    shape = probes.arm(run, 'source', 'destination', 84, 1000, lifetime_secs=90)
    started = time.monotonic()
    baseline = dict(elapsed_us=0, delivered=0, credits=held_credits,
                    payments=[held[0]['payment_progress'][run.transit], held[1]['payment_progress'][run.guard]])
    row = dict(shape=shape, baseline=baseline, samples=[], observer='bounded read-only original-Y queries',
               observer_busy_timeout_ms=250, observer_query_timeout_ms=1000,
               cleanup_finished_us=None, traffic_finished_us=None, passed=False)
    run.evidence['receiver_history']['live'] = row
    run.save()
    with ThreadPoolExecutor(max_workers=1) as sender, ThreadPoolExecutor(max_workers=7) as readers:
        sending = sender.submit(probes.send, run, 'source', 'destination', shape, 3,
                                max_duration_secs=60, operation_timeout=75)
        released = False
        try:
            while time.monotonic() - started < 35:
                current = sample(run, shape, started, readers)
                row['samples'].append(current)
                if not released:
                    require(run.nodes['n02'].held() and current['cleanup_pending'],
                            'receiver cleanup escaped the original held writer')
                    if current['delivered'] > 0:
                        require(time.monotonic() - started < 2 and not sending.done(),
                                'original live stream did not begin before release')
                        run.release_holds(run.held_nodes)
                        released = True
                        row['released_us'] = int((time.monotonic() - started) * 1_000_000)
                elif not current['cleanup_pending'] and row['cleanup_finished_us'] is None:
                    row['cleanup_finished_us'] = current['elapsed_us']
                if current['delivered'] == 84:
                    if row['traffic_finished_us'] is None:
                        row['traffic_finished_us'] = current['elapsed_us']
                    if row['cleanup_finished_us'] is not None and all(
                        not p['in_flight'] and p['acknowledged_msat'] is not None
                        and p['acknowledged_msat'] >= max(p['authorized_sat'] * 1000, p['evidence_msat'])
                        for p in current['payments']):
                        break
                run.save()
                time.sleep(.05)
            require(released and row['cleanup_finished_us'] is not None and row['traffic_finished_us'] is not None,
                    'whole original receiver cleanup did not finish inside35 seconds')
        finally:
            # Keep this exact stream and any failed samples; never resend it.
            try:
                row['sender'] = sending.result(timeout=75)
            finally:
                run.save()
    submitted(row['sender'], shape)
    row['receiver'] = probes.receive(run, 'source', 'destination', shape, complete=True)
    row['progress'] = progress(baseline, row['samples'])
    # Even if the last packet and cleanup appear in one polling sample, only
    # claim coverage when cleanup preceded the earliest possible final send.
    earliest_final = int((shape['packet_count'] - 1) / 3 * 1_000_000)
    row['progress'].update(cleanup_finished_us=row['cleanup_finished_us'], traffic_finished_us=row['traffic_finished_us'],
                           earliest_final_send_us=earliest_final,
                           traffic_covers_cleanup=row['cleanup_finished_us'] < earliest_final)
    row['passed'] = all(row['progress'][key] for key in ('within_limit', 'all_counters_advanced', 'traffic_covers_cleanup'))
    return row
