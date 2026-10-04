"""Existing bounded relay diagnostics inside the explicitly selected debug app.

No intents, wallet operations or new phone API. Each mutation has a durable local
intent and is dispatched once; an uncertain reply is never retried here.
"""

import hashlib
import json
import struct
import uuid

from .paid_settlement import require
from .phone_customer import save
from .phone_restart import process
from .wifi_measurements import process_identity, resource_fields


def decode_record(data):
    require(4 <= len(data) <= 1024 * 1024 + 4, 'invalid phone control response size')
    require(struct.unpack('!I', data[:4])[0] == len(data) - 4,
            'incomplete or trailing phone control record')
    value = json.loads(data[4:])
    require(isinstance(value, dict) and set(value) in ({'ok'}, {'error'}),
            'invalid phone control envelope')
    require('error' not in value, 'phone diagnostic rejected: ' + str(value.get('error')))
    return value['ok']


def control(phone, kind, *, probe=None, operation_timeout=20):
    require(kind in ('status', 'receive_probe', 'send_probe'),
            'phone diagnostic command is not allowed')
    require((probe is None) == (kind == 'status')
            and type(operation_timeout) is int and 10 <= operation_timeout <= 330,
            'invalid phone diagnostic arguments')
    phone.ensure_ready()
    phone.check()
    request = {'type': kind}
    if probe is not None:
        request['probe'] = probe
    data = json.dumps(request, separators=(',', ':')).encode()
    require(len(data) <= 4096, 'phone diagnostic request exceeds bound')
    identifier = 'diagnostic-' + uuid.uuid4().hex
    save(phone.root / (identifier + '-intent.json'), {
        'request': request, 'sha256': hashlib.sha256(data).hexdigest(),
        'timeout_seconds': operation_timeout,
    })
    try:
        # exec-out only copies output: the service receives no request bytes.
        # A non-PTY shell carries both directions without terminal conversion.
        reply = phone.adb(
            'shell', '-T', 'run-as', phone.package, 'toybox', 'nc', '-U', '-w', '3',
            '-W', str(operation_timeout - 5), 'files/client/state/control.sock',
            data=struct.pack('!I', len(data)) + data, timeout=operation_timeout,
        )
        result = decode_record(reply)
    except Exception as error:
        save(phone.root / (identifier + '-failure.json'),
             {'error': type(error).__name__, 'reason': str(error)[:240]})
        raise
    save(phone.root / (identifier + '-result.json'), result)
    return result


def resources(phone):
    identity = process(phone)
    require(identity is not None, 'phone candidate process is absent')
    base = '/proc/' + str(identity['pid'])
    stat = phone.shell('run-as', phone.package, 'cat', base + '/stat').decode()
    require(process_identity(stat) == (identity['pid'], identity['start_ticks']),
            'phone process changed before resource read')
    fields = stat.rsplit(') ', 1)[1].split()
    memory = phone.shell('run-as', phone.package, 'cat', base + '/status').decode()
    ticks = int(phone.shell('run-as', phone.package, 'getconf', 'CLK_TCK').strip())
    require(ticks > 0 and process(phone) == identity,
            'phone clock or process changed during resource read')
    return {'process': identity, 'cpu_ticks': int(fields[11]) + int(fields[12]),
            'ticks_per_second': ticks,
            'memory_kib': resource_fields(memory, ('VmRSS', 'VmHWM'), 'kB')}
