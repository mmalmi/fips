"""Finite, concurrent TCP/FIPS checks using the existing private relay controls."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import secrets
import time

from .paid_settlement import require
from .phone_customer import save
from .wifi_remote import checked_name


def validate_stream(report, shape):
    require(report['shape'] == shape and report['ready'] and report['connected']
            and report['finished'] and report['stopped_reason'] is None
            and report['completed_us'] is not None
            and 0 <= report['completed_us'] <= report['elapsed_us']
            <= (shape['duration_secs'] + 5) * 1_000_000,
            'stream shape or completion differs')
    require(all(report[key] == shape['bytes'] for key in
                ('accepted_bytes', 'received_bytes', 'acknowledged_bytes')),
            'stream did not deliver and acknowledge every byte')
    identifier = bytes.fromhex(shape['stream_id'])
    block = bytes((pos % 251) ^ identifier[pos % 16] for pos in range(251 * 16))
    complete, tail = divmod(shape['bytes'], len(block))
    expected = hashlib.sha256(block * complete + block[:tail]).hexdigest()
    require(report['received_sha256'] == expected, 'stream payload digest differs')


def denied(report, shape):
    require(report['shape'] == shape and report['ready'] and report['finished']
            and report['completed_us'] is None
            and report['stopped_reason'] == 'stream probe deadline reached before exact delivery and ACK'
            and report['received_bytes'] == report['acknowledged_bytes'] == 0
            and report['received_sha256'] == hashlib.sha256(b'').hexdigest(),
            'unpaid deadline lacks fresh completed zero-delivery evidence')


def duplex(run, record, *, label, count, duration, rate, observe, expect_denial=False):
    """Dispatch each endpoint once; retain both outcomes even if observation fails."""
    operations = run.root / ('stream-' + checked_name(label))
    operations.mkdir(mode=0o700)
    identifier = secrets.token_hex(16)
    shapes = {name: {'peer': run.nodes[other].npub, 'stream_id': identifier,
                     'bytes': count, 'bytes_per_second': rate,
                     'duration_secs': duration, 'connect': name == 'n01'}
              for name, other in (('n01', 'n03'), ('n03', 'n01'))}
    record.update(shapes=shapes, samples=[])
    run.save()

    def probe(name):
        save(operations / (name + '-intent.json'), shapes[name])
        try:
            result = run.ctl(name, 'stream_probe', probe=shapes[name], operation_timeout=duration + 20)
        except Exception as error:
            save(operations / (name + '-error.json'), {'type': type(error).__name__, 'reason': str(error)[:240]})
            # The native diagnostic returns an error for incomplete delivery.
            # Reconcile that exact stream from live status; never resend it.
            observed = run.ctl(name, 'status').get('stream_probe')
            save(operations / (name + '-observed.json'), observed)
            if not expect_denial:
                raise
            require(isinstance(observed, dict), 'unpaid stream status is unavailable')
            result = {'probe': observed, 'observed_after_error': True}
        if expect_denial:
            denied(result['probe'], shapes[name])
        save(operations / (name + '-result.json'), result)
        return result['probe']

    jobs = {}
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            jobs = {name: pool.submit(probe, name) for name in shapes}
            while not all(job.done() for job in jobs.values()):
                run.monitor.check()
                record['samples'].append({'at': time.monotonic(), **observe()})
                run.save()
                time.sleep(3)
    finally:
        results, errors = {}, {}
        for name, job in jobs.items():
            try:
                results[name] = job.result()
            except Exception as error:
                errors[name] = {'type': type(error).__name__, 'reason': str(error)[:240]}
        record.update(results=results, errors=errors)
        run.save()
    require(not errors and set(results) == set(shapes), 'stream endpoint operation failed')
    return results
