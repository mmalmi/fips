"""Local payment-service submissions, including separately retained guard gaps."""

from validation import PAYMENT_PORT, host_identity, payment_counters, unsigned

TRANSPORTS = {'udp', 'ethernet', 'tcp', 'tor', 'websocket', 'webrtc', 'ble', 'sim', 'other'}
FIELDS = {'submitted_packets', 'fips_payload_bytes', 'ethernet_framing_bytes'}
MAX_COUNTER = 2**64 - 1


def counter(value):
    if unsigned(value) >= MAX_COUNTER:
        raise ValueError('carrier counter saturated or exceeds its integer range')
    return value


def snapshot(node, enabled, *, native_ethernet=False):
    services = [s for s in node['control_traffic'] if s['service_port'] == PAYMENT_PORT]
    if len(services) != 1:
        raise ValueError('missing or duplicate payment carrier service')
    value = services[0].get('service_carrier')
    if not enabled:
        if value is not None:
            raise ValueError('payment carrier instrumentation differs from report metadata')
        return None
    fields = {'service_port', 'ambiguous_port_datagrams', 'discarded_outputs', 'transports'}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError('missing or changed payment carrier snapshot')
    if type(value['service_port']) is not int or value['service_port'] != PAYMENT_PORT:
        raise ValueError('carrier snapshot belongs to a different service')
    if counter(value['ambiguous_port_datagrams']) != 0:
        raise ValueError('ambiguous service-port attribution')
    transports = {}
    for transport in value['transports']:
        if not isinstance(transport, dict) or set(transport) != FIELDS | {'transport'}:
            raise ValueError('missing or changed carrier transport counters')
        name = transport['transport']
        if name not in TRANSPORTS or name in transports:
            raise ValueError('unknown or duplicate carrier transport')
        transports[name] = {key: counter(transport[key]) for key in FIELDS}
        if name != 'ethernet' and transport['ethernet_framing_bytes']:
            raise ValueError('Ethernet framing attributed to a different transport')
    if set(transports) != TRANSPORTS:
        raise ValueError('carrier transport observations are incomplete')
    # The hardware contract names Ethernet. Prior application sends need
    # cumulative carrier evidence, even when the current idle delta is zero.
    if native_ethernet and unsigned(payment_counters(node)['stream_bytes_sent']):
        ethernet = transports['ethernet']
        if not ethernet['submitted_packets'] or not ethernet['fips_payload_bytes']:
            raise ValueError('missing Ethernet carrier activity after application sends')
    return {'discarded_outputs': counter(value['discarded_outputs']), 'transports': transports}


def difference(before, after):
    def subtract(a, b):
        if b < a:
            raise ValueError('carrier counter reset within the process epoch')
        return b - a
    return {'discarded_outputs': subtract(before['discarded_outputs'], after['discarded_outputs']),
            'transports': {name: {key: subtract(values[key], after['transports'][name][key])
                                  for key in FIELDS}
                           for name, values in before['transports'].items()}}


def identity(node):
    if 'host_process' in node:
        return host_identity(node)
    pid = unsigned(node['measurements']['process_id'])
    if not pid:
        raise ValueError('missing carrier process identity')
    return str(pid), pid


def aggregate(nodes):
    total = {key: sum(values[key] for node in nodes.values()
                     for values in node['transports'].values()) for key in FIELDS}
    total['discarded_outputs'] = sum(node['discarded_outputs'] for node in nodes.values())
    return {'nodes': nodes, 'total': total}


def record(data, result, previous, enabled, *, native_ethernet=False):
    if type(enabled) is not bool:
        raise ValueError('payment carrier measurement must be explicit')
    boundaries = [(name, data[name]) for name in ('before_guard', 'before', 'after', 'after_guard')]
    if previous is not None:
        boundaries.insert(0, ('previous_after_guard', previous))
    samples = []
    expected = None
    for name, nodes in boundaries:
        identified = {identity(node): snapshot(node, enabled, native_ethernet=native_ethernet)
                      for node in nodes}
        if len(identified) != len(nodes) or (expected is not None and set(identified) != expected):
            raise ValueError('carrier node or process identities changed')
        expected = set(identified)
        samples.append((name, identified))
    result['payment_service_carrier'] = None
    if not enabled:
        return
    measured = {'service_port': PAYMENT_PORT, 'physical_wire_bytes': None, 'outside_workload': {}}
    for (a_name, before), (b_name, after) in zip(samples, samples[1:]):
        value = aggregate({key[0]: difference(before[key], after[key]) for key in before})
        if (a_name, b_name) == ('before', 'after'):
            measured.update(value)
        else:
            measured['outside_workload'][f'{a_name}_to_{b_name}'] = value
    size = measured['total']['fips_payload_bytes'] + measured['total']['ethernet_framing_bytes']
    delivered = result['delivered_bytes']
    measured['bytes_per_delivered_byte'] = size / delivered if delivered else None
    result['payment_service_carrier'] = measured
