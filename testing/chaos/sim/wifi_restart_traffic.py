"""Keep one finite paid sender active across an ownership-checked relay crash."""

from concurrent.futures import ThreadPoolExecutor
import time

from . import wifi_probes as probes
from .paid_relay import eventually
from .paid_settlement import require
from .wifi_priority_checks import received, submitted


def validate_overlap(evidence, shape, source, rate):
    before = received(evidence['before_crash'], shape, source)
    resumed_before = received(evidence['recovery_before'], shape, source)
    resumed_after = received(evidence['recovery_after'], shape, source)
    require(0 < before <= resumed_before < resumed_after < shape['packet_count'],
            'restart lacks fresh partial delivery before the sender finishes')
    require(evidence['dispatch_started'] < evidence['crash_started']
            < evidence['restarted_at'] <= evidence['recovery_sampled_at']
            < evidence['recovery_observed_at']
            < evidence['dispatch_started'] + (shape['packet_count'] - 1) / rate,
            'restart recovery did not overlap the minimum paced-send window')


def active_restart_stream(run, round_id, count, rate):
    source, destination = 'n01', 'n03'
    before = run.middle_sample()
    shape = probes.arm(run, source, destination, count, 1000)
    evidence = run.evidence['active_restart'] = {'shape': shape, 'passed': False}
    sender = None
    with ThreadPoolExecutor(max_workers=1) as pool:
        evidence['dispatch_started'] = time.monotonic()
        future = pool.submit(probes.send, run, source, destination, shape, rate)

        def still_sending():
            if future.done():
                future.result()  # Preserve the sender's actual failure.
                raise RuntimeError('sender finished before active restart recovery')
            require(time.monotonic() < evidence['dispatch_started'] + (count - 1) / rate,
                    'active restart exceeded the minimum paced-send window')

        try:
            def partial():
                still_sending()
                report = probes.receive(run, source, destination, shape)
                return report if 0 < report['unique_packets'] < count else None

            evidence['before_crash'] = eventually('partial delivery before process crash', partial, 10)
            still_sending()
            evidence['crash_started'] = time.monotonic()
            run.save()
            run.restart_middle(wait_for_recovery=False)
            evidence['restarted_at'] = time.monotonic()
            still_sending()
            evidence['recovery_before'] = probes.receive(run, source, destination, shape)
            evidence['recovery_sampled_at'] = time.monotonic()

            def resumed():
                report = partial()
                if report and report['unique_packets'] > evidence['recovery_before']['unique_packets']:
                    still_sending()
                    return report
                return None

            evidence['recovery_after'] = eventually('same paid stream resumes after restart', resumed, 20)
            evidence['recovery_observed_at'] = time.monotonic()
            validate_overlap(evidence, shape, run.nodes[source].npub, rate)
            evidence['passed'] = True
        finally:
            # Only this thread writes evidence. Drain this exact send before any
            # restoration or settlement, including an ambiguous control reply.
            try:
                sender = future.result(timeout=35)
                evidence['sender'] = sender
            except Exception as error:
                evidence['sender_error'] = type(error).__name__
                raise
            finally:
                if future.done():
                    time.sleep(2)
                    try:
                        evidence['receiver'] = probes.receive(run, source, destination, shape)
                    except Exception as error:
                        evidence['receiver_error'] = type(error).__name__
                run.save()
    submitted(sender, shape)
    require('receiver' in evidence, 'terminal interrupted-stream receiver observation failed')
    return {'round': round_id, 'source': source, 'destination': destination,
            'seconds': time.monotonic() - evidence['dispatch_started'],
            'before': before, 'after': run.middle_sample(), 'sender': sender,
            'receiver': evidence['receiver'], 'frame_loss': None, 'active_restart': evidence}
