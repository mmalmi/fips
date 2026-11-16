"""Match encrypted service submissions to complete outgoing Ethernet PCAP records.

These are captured link bytes, not radio airtime or uncaptured PHY framing.
Opaque transit and shared traffic remain explicitly unattributed. Never subtract
them as a baseline or infer that a successful submission reached its recipient.
"""

from collections import Counter, defaultdict
import hashlib
import re
import struct

from service_carrier import counter, FIELDS as COUNTER_FIELDS, TRANSPORTS

MAX_PACKETS = 2_000_000
MAX_PACKET_BYTES = 1 << 20
TRACE_TARGET = 'fips_core::service_wire'
TRACE_MESSAGE = 'FIPS service packet submitted'
FIELDS = {'process_id', 'counter_id', 'service_port', 'packet_number', 'transport', 'payload_bytes', 'fingerprint'}
ANSI = re.compile(r'\x1b\[[0-9;]*m')
FIELD = re.compile(r'\b([a-z_]+)=(?:"([^"]*)"|([^\s]+))')


def exact(stream, size):
    data = stream.read(size)
    if len(data) != size:
        raise ValueError('incomplete PCAP record')
    return data


def frame_payload(frame, ether_type):
    """Return the FIPS transport payload and IP length, if directly observable."""
    if len(frame) < 14:
        raise ValueError('incomplete Ethernet header')
    protocol, offset = struct.unpack('!H', frame[12:14])[0], 14
    while protocol in (0x8100, 0x88a8):
        if offset > 22 or len(frame) < offset + 4:
            raise ValueError('unsupported or truncated VLAN stack')
        protocol = struct.unpack('!H', frame[offset + 2:offset + 4])[0]
        offset += 4
    body = frame[offset:]
    if protocol == ether_type:
        if not body or body[0] != 0:
            return None
        if len(body) < 3:
            raise ValueError('incomplete FIPS Ethernet prefix')
        size = int.from_bytes(body[1:3], 'little')
        if size > len(body) - 3:
            raise ValueError('incomplete FIPS Ethernet payload')
        return 'ethernet', body[3:3 + size], None
    if protocol == 0x0800:
        if len(body) < 20 or body[0] >> 4 != 4:
            raise ValueError('invalid IPv4 packet')
        header = (body[0] & 15) * 4
        total = struct.unpack('!H', body[2:4])[0]
        if header < 20 or total < header or total > len(body):
            raise ValueError('invalid IPv4 length')
        if body[9] != 17 or int.from_bytes(body[6:8], 'big') & 0x3fff:
            return None
    elif protocol == 0x86dd:
        if len(body) < 40 or body[0] >> 4 != 6:
            raise ValueError('invalid IPv6 packet')
        header, total = 40, 40 + int.from_bytes(body[4:6], 'big')
        if total > len(body):
            raise ValueError('invalid IPv6 length')
        next_header = body[6]
        for _ in range(8):
            if next_header not in (0, 43, 60):
                break
            if header + 2 > total:
                raise ValueError('incomplete IPv6 extension')
            size = (body[header + 1] + 1) * 8
            next_header = body[header]
            header += size
        if header > total:
            raise ValueError('invalid IPv6 extension length')
        if next_header != 17:
            return None
    else:
        return None
    if total - header < 8:
        raise ValueError('incomplete UDP header')
    udp = body[header:total]
    if int.from_bytes(udp[4:6], 'big') != len(udp):
        raise ValueError('invalid UDP length')
    return 'udp', udp[8:], total


def read_pcap(stream, *, ether_type=0x88b5):
    header = exact(stream, 24)
    formats = {b'\xd4\xc3\xb2\xa1': ('<', 1_000_000), b'\xa1\xb2\xc3\xd4': ('>', 1_000_000),
               b'\x4d\x3c\xb2\xa1': ('<', 1_000_000_000), b'\xa1\xb2\x3c\x4d': ('>', 1_000_000_000)}
    if header[:4] not in formats:
        raise ValueError('requires classic PCAP, not PCAPNG')
    endian, precision = formats[header[:4]]
    major, minor, _zone, _accuracy, snaplen, linktype = struct.unpack(endian + 'HHIIII', header[4:])
    if (major, minor) != (2, 4) or linktype != 1 or not 0 < snaplen <= MAX_PACKET_BYTES:
        raise ValueError('requires complete Ethernet PCAP without FCS metadata')
    if type(ether_type) is not int or not 1536 <= ether_type <= 65535:
        raise ValueError('invalid test EtherType')
    count = 0
    while True:
        record = stream.read(16)
        if not record:
            return
        if len(record) != 16:
            raise ValueError('incomplete PCAP packet header')
        seconds, fraction, included, original = struct.unpack(endian + 'IIII', record)
        if fraction >= precision or not 0 < included == original <= snaplen:
            raise ValueError('truncated or invalid PCAP packet')
        count += 1
        if count > MAX_PACKETS:
            raise ValueError('PCAP packet limit exceeded; capture trials separately')
        frame = exact(stream, included)
        parsed = frame_payload(frame, ether_type)
        result = {'timestamp_ns': seconds * 1_000_000_000 + fraction * (1_000_000_000 // precision),
                  'captured_link_bytes': original, 'key': None, 'ip_bytes': None}
        if parsed is not None:
            transport, payload, ip_bytes = parsed
            result.update(key=(transport, len(payload), hashlib.sha256(payload).hexdigest()),
                          ip_bytes=ip_bytes)
        yield result


def read_traces(lines):
    seen = defaultdict(set)
    count = 0
    for line in lines:
        if len(line) > 16384:
            raise ValueError('oversized trace line')
        line = ANSI.sub('', line)
        if TRACE_TARGET not in line or TRACE_MESSAGE not in line:
            continue
        fields = FIELD.findall(line.split(TRACE_MESSAGE, 1)[1])
        values = {name: quoted or plain for name, quoted, plain in fields}
        if set(values) != FIELDS or len(fields) != len(FIELDS):
            raise ValueError('incomplete or changed service wire trace')
        for name in FIELDS - {'transport', 'fingerprint'}:
            if not values[name].isdigit():
                raise ValueError('invalid wire trace counter')
            values[name] = int(values[name])
        if (not 0 < values['process_id'] <= 2**32 - 1 or not 0 < values['counter_id'] < 2**64
                or not 0 <= values['service_port'] <= 65535
                or not 0 < values['packet_number'] < 2**64 - 1
                or not 0 < values['payload_bytes'] <= MAX_PACKET_BYTES
                or values['transport'] not in ('udp', 'ethernet')
                or not re.fullmatch('[0-9a-f]{64}', values['fingerprint'])):
            raise ValueError('unsupported or invalid wire trace')
        group = tuple(values[name] for name in ('process_id', 'counter_id', 'service_port', 'transport'))
        number = values['packet_number']
        if number in seen[group]:
            raise ValueError('duplicate service packet ordinal')
        seen[group].add(number)
        count += 1
        if count > MAX_PACKETS:
            raise ValueError('wire trace limit exceeded')
        yield values
    for numbers in seen.values():
        if min(numbers) != 1 or max(numbers) != len(numbers):
            raise ValueError('missing service packet ordinals')


def match_packets(packets, traces, snapshots, *, on_match=None):
    """Consume one captured outgoing packet per trace, including identical retries."""
    captures = defaultdict(Counter)
    total = Counter()
    for packet in packets:
        key = packet['key']
        captures[key][(packet['captured_link_bytes'], packet['ip_bytes'])] += 1
        total['packets'] += 1
        total['captured_link_bytes'] += packet['captured_link_bytes']
    groups = defaultdict(Counter)
    for trace in traces:
        key = (trace['transport'], trace['payload_bytes'], trace['fingerprint'])
        if not captures[key]:
            raise ValueError('service submission missing from independent capture')
        # Identical payloads with different encapsulation cannot be assigned to
        # an individual sender/window without more capture evidence.
        if len(captures[key]) != 1:
            raise ValueError('ambiguous captured packet framing')
        framing = next(iter(captures[key]))
        captures[key][framing] -= 1
        if not captures[key][framing]:
            del captures[key][framing]
        group = tuple(trace[name] for name in ('process_id', 'service_port', 'transport'))
        cost = groups[group]
        cost.update(packets=1, fips_payload_bytes=trace['payload_bytes'], captured_link_bytes=framing[0])
        if framing[1] is not None:
            cost['ip_bytes'] += framing[1]
        if on_match is not None:
            on_match(trace, {'captured_link_bytes': framing[0], 'ip_bytes': framing[1]})
    measured = Counter()
    for cost in groups.values():
        measured.update(cost)
    expected = defaultdict(Counter)
    for snapshot in snapshots:
        pid, port = counter(snapshot['process_id']), counter(snapshot['service_port'])
        if not 0 < pid < 2**32 or port > 65535 or counter(snapshot['ambiguous_port_datagrams']):
            raise ValueError('invalid or ambiguous final carrier identity')
        counter(snapshot['discarded_outputs'])
        seen = set()
        for counters in snapshot['transports']:
            transport = counters['transport']
            if set(counters) != COUNTER_FIELDS | {'transport'} or transport not in TRANSPORTS or transport in seen:
                raise ValueError('invalid or duplicate final carrier transport')
            seen.add(transport)
            for name in COUNTER_FIELDS:
                counter(counters[name])
            if bool(counters['submitted_packets']) != bool(counters['fips_payload_bytes']):
                raise ValueError('inconsistent final carrier counters')
            if transport not in ('udp', 'ethernet'):
                if any(counters[name] for name in COUNTER_FIELDS):
                    raise ValueError('unsupported nonzero carrier counters')
                continue
            framing = 3 * counters['submitted_packets'] if transport == 'ethernet' else 0
            if counters['ethernet_framing_bytes'] != framing:
                raise ValueError('inconsistent final carrier framing counters')
            if counters['submitted_packets']:
                key = (pid, port, transport)
                expected[key].update(packets=counters['submitted_packets'], fips_payload_bytes=counters['fips_payload_bytes'])
        if seen != TRANSPORTS:
            raise ValueError('incomplete final carrier counters')
    observed = {key: {name: cost[name] for name in ('packets', 'fips_payload_bytes')}
                for key, cost in groups.items()}
    if observed != dict(expected):
        raise ValueError('wire traces disagree with final carrier counters')
    return {'capture': dict(total), 'attributed': dict(measured),
            'groups': [{'process_id': group[0], 'service_port': group[1], 'transport': group[2], **cost}
                       for group, cost in sorted(groups.items())],
            'unattributed': {key: total[key] - measured[key] for key in ('packets', 'captured_link_bytes')},
            'physical_wire_bytes': None, 'radio_airtime': None}
