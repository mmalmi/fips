"""Impair one paid phone UDP adjacency under the existing router cleanup lease."""

import hashlib
import ipaddress
import json
from pathlib import Path
import re
import shlex
import time

from .paid_relay import eventually
from .paid_settlement import require
from .phone_diagnostics import native
from .phone_restart import process
from .stream_probe import duplex
from .wifi_measurements import snapshot
from .wifi_priority_checks import natural


def endpoint(value):
    address, port = value.rsplit(':', 1)
    ip = ipaddress.IPv4Address(address)
    if ip.is_unspecified or ip.is_multicast or not port.isdecimal() or not 0 < int(port) <= 65535:
        raise ValueError('outage requires an exact unicast IPv4 UDP endpoint')
    return str(ip), int(port)


class UdpFault:
    def __init__(self, node, phone, router, *, every=1, burst=1, mode="drop"):
        self.node = node
        self.phone, self.router = endpoint(phone), endpoint(router)
        require(self.phone[0] != self.router[0], 'phone and router addresses must differ')
        require(type(every) is int and 1 <= every <= 1000, 'invalid packet-loss interval')
        require(type(burst) is int and 1 <= burst <= every, 'invalid UDP fault burst')
        require(mode in ('drop', 'corrupt'), 'invalid UDP fault mode')
        self.every, self.burst, self.mode = every, burst, mode
        self.attempted = False

    def rules(self):
        n = self.node
        selected = '0' if self.burst == 1 else f'< {self.burst}'
        selection = f'counter numgen inc mod {self.every} {selected} ' if self.every > 1 else ''
        predicate, action = '', 'drop'
        if self.mode == 'corrupt':
            # Match established FMP only, flip a ciphertext bit, and leave the
            # IPv4 UDP checksum disabled so AEAD, not the kernel, rejects it.
            predicate = 'udp length >= 40 @th,64,8 0 '
            action = '@th,192,8 set @th,192,8 ^ 0x01 udp checksum set 0'

        rules = f'create table netdev {n.table} {{ comment "{n.table_owner}"; }}\n'
        for direction, source, target in (('ingress', self.phone, self.router),
                                          ('egress', self.router, self.phone)):
            rules += (f'add chain netdev {n.table} {direction} {{ type filter hook {direction} '
                      f'device "{n.management}" priority -500; policy accept; }}\n'
                      f'add rule netdev {n.table} {direction} ip saddr {source[0]} '
                      f'ip daddr {target[0]} udp sport {source[1]} udp dport {target[1]} '
                      f'{predicate}{selection}counter {action}\n')
        return rules

    def counters(self, table):
        rows = table['nftables']
        owners = [r['table'] for r in rows if 'table' in r]
        require(len(owners) == 1 and owners[0]['name'] == self.node.table
                and owners[0]['family'] == 'netdev' and owners[0]['comment'] == self.node.table_owner,
                'UDP outage table ownership changed')
        rules = [r['rule'] for r in rows if 'rule' in r]
        require(len(rules) == 2 and {r['chain'] for r in rules} == {'ingress', 'egress'},
                'UDP outage must contain exactly two directional rules')
        result = {}
        for rule in rules:
            counters = [e['counter'] for e in rule['expr'] if 'counter' in e]
            require(len(counters) == (2 if self.every > 1 else 1),
                    'UDP loss counter is missing or ambiguous')
            result[rule['chain']] = {k: natural(counters[-1][k]) for k in ('packets', 'bytes')}
            if self.every > 1:
                result[rule['chain']]['matched_packets'] = natural(counters[0]['packets'])
        return result

    def validate_effect(self, before, after):
        require(self.every > 1, 'periodic impairment requires a finite interval')
        start, end = (self.counters(value['table']) for value in (before, after))
        def handles(value):
            return {row['rule']['chain']: natural(row['rule']['handle'])
                    for row in value['table']['nftables'] if 'rule' in row}
        require(handles(before) == handles(after), 'packet-loss rules were replaced')
        delta = {}
        for direction, values in end.items():
            row = {key: value - start[direction][key] for key, value in values.items()}
            require(all(value > 0 for value in row.values())
                    and row['matched_packets'] >= 10 * self.every
                    # Counter snapshots can straddle an in-flight packet.
                    and abs(row['packets'] * self.every - row['matched_packets'] * self.burst)
                        <= 2 * self.every * self.burst,
                    'UDP fault interval lacks matching observed packet counts')
            delta[direction] = row
        return delta

    def observe(self):
        table = json.loads(self.node.remote(['nft', '-j', 'list', 'table', 'netdev', self.node.table]))
        return {'counters': self.counters(table), 'table': table}

    def enable(self):
        require(not self.attempted, 'never replay an uncertain UDP cut')
        self.attempted = True
        self.node.install_owned_table(self.node.table, 'table-created', self.rules())
        return self.observe()

    def clear(self):
        if not self.attempted:
            return None
        n = self.node
        # Reconcile an uncertain creation without deleting a different owner's
        # table. The independent router guard uses the same marker and token.
        script = f'''owner=$(nft -j list table netdev {n.table} 2>/dev/null | jsonfilter -e '@.nftables[*].table.comment' || :)
if [ -n "$owner" ]; then
  test "$owner" = "{n.table_owner}"
  nft delete table netdev {n.table}
fi
if nft list table netdev {n.table} >/dev/null 2>&1; then exit 1; fi
rm -f {n.temporary}/table-created
nft -j list tables
'''
        tables = json.loads(n.guarded(script))
        require(not any(r.get('table', {}).get('name') == n.table for r in tables['nftables']),
                'UDP outage remains after removal')
        return {'removed': True, 'tables': tables}


def isolated(states, identities):
    wanted = {'n01': ['phone'], 'phone': ['n01'], 'n02': ['n03'], 'n03': ['n02']}
    return all({p['npub'] for p in states[name]['peers'] if p['connected']}
               == {identities[other] for other in peers}
               and all(p['transport'] == 'udp' for p in states[name]['peers'] if p['connected'])
               for name, peers in wanted.items())


def processes(run):
    return {'phone': process(run.phone), **{
        name: {key: value for key, value in snapshot(node, name)['host_process'].items()
               if key in ('host', 'pid', 'start_ticks')} for name, node in run.nodes.items()}}


def peer_session(peers, npub):
    matches = [peer for peer in peers if peer['npub'] == npub]
    require(len(matches) == 1, 'missing or ambiguous impaired peer')
    peer = matches[0]
    require(peer['connectivity'] == 'connected' and peer['transport_type'] == 'udp'
            and re.fullmatch('[0-9a-fA-F]{8}', peer['our_session_index']),
            'impaired UDP session is disconnected or missing its receiver index')
    return {**{key: peer[key] for key in ('npub', 'link_id', 'authenticated_at_ms',
                                        'our_session_index', 'last_seen_ms')},
            'rekey_in_progress': bool(peer.get('rekey_in_progress'))}


def sessions(run):
    node = run.nodes['n02']
    return {'n02': peer_session(node.native({'command': 'show_peers'})['data']['peers'],
                                run.evidence['phone_npub']),
            'phone': peer_session(native(run.phone, 'show_peers')['data']['peers'], node.npub)}


def validate_sessions(before, after, *, allow_rotation=False):
    require(set(before) == set(after) == {'n02', 'phone'}, 'missing impaired session observation')
    for name, peer in before.items():
        require(peer['last_seen_ms'] - peer['authenticated_at_ms'] >= 30_000,
                'corruption must start beyond the original fresh-session grace')
        ignored = {'last_seen_ms', 'our_session_index', 'rekey_in_progress'} if allow_rotation else {'last_seen_ms'}
        require({k: v for k, v in peer.items() if k not in ignored}
                == {k: v for k, v in after[name].items() if k not in ignored}
                and (allow_rotation or not peer['rekey_in_progress'])
                and after[name]['last_seen_ms'] > peer['last_seen_ms'],
                'corruption replaced the original UDP session or stopped authenticated traffic')


def decrypt_failures(node):
    path = shlex.quote(node.temporary + '/process.log')
    raw = node.remote(f'test "$(wc -c < {path})" -le 8388608 && cat {path}')
    require(len(raw) <= 8 * 1024 * 1024, 'corruption diagnostic log exceeded its bound')
    text = re.sub(r'\x1b\[[0-9;]*m', '', raw.decode())
    require('FMP AEAD failures exceeded threshold' not in text,
            'corruption triggered native recovery instead of preserving live traffic')
    counters = []
    for line in text.splitlines():
        if 'dataplane FMP AEAD decryption failed' in line:
            counter = re.search(r'\bcounter=(\d+)\b', line)
            require(counter is not None, 'unrecognized native decryption-failure evidence')
            counters.append(int(counter[1]))
    return counters


def impaired_transit(run):
    corrupt = getattr(run.args, 'impaired_transit', None) == 'corrupt'
    loss = UdpFault(run.nodes['n02'], run.evidence['phone_udp_address'], run.endpoint('n02'),
                    every=100 if corrupt else 20, burst=8 if corrupt else 1,
                    mode='corrupt' if corrupt else 'drop')
    row = {'passed': False, 'every': loss.every, 'before_processes': processes(run),
           'physical_radio_change': False, 'mode': loss.mode, 'burst': loss.burst}
    require(row['before_processes']['phone'] is not None, 'phone process is absent')
    run.evidence['phone_impairment'] = row
    run.evidence['harness_sha256']['phone_outage.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    run.save()
    try:
        if corrupt:
            row['before_sessions'] = sessions(run)
            row['decrypt_failures_before'] = decrypt_failures(run.nodes['n02'])
        row['filter_before'] = loss.enable()
        run.save()
        def observe_corruption():
            if 'burst_sessions' not in row:
                observed = decrypt_failures(run.nodes['n02'])[len(row['decrypt_failures_before']):]
                if any(observed[i:i + 8] == list(range(value, value + 8))
                       for i, value in enumerate(observed)):
                    row['burst_sessions'] = sessions(run)
                    validate_sessions(row['before_sessions'], row['burst_sessions'])
                    row['burst_decrypt_failures'] = observed
            return {'corruption_burst_verified': 'burst_sessions' in row}
        run.stream('background', observe=observe_corruption if corrupt else None)
        row['filter_after'] = loss.observe()
        row['affected'] = loss.validate_effect(row['filter_before'], row['filter_after'])
        row['after_processes'] = processes(run)
        require(row['before_processes'] == row['after_processes'], 'impaired transit restarted a relay')
        if corrupt:
            row['after_sessions'] = sessions(run)
            require('burst_sessions' in row, 'no native corruption burst qualified on the original keys')
            # Default keys rotate about every two minutes. The first observed
            # burst must retain its keys; the longer run must retain its peers.
            validate_sessions(row['before_sessions'], row['after_sessions'], allow_rotation=True)
            before = row['decrypt_failures_before']
            after = row['decrypt_failures_after'] = decrypt_failures(run.nodes['n02'])
            require(after[:len(before)] == before and len(after) - len(before) >= 8,
                    'corruption did not reach the native AEAD rejection path')
            # An eight-frame burst exceeds the former four-failure recovery threshold.
            observed = after[len(before):]
            require(any(observed[i:i + 8] == list(range(value, value + 8))
                        for i, value in enumerate(observed)),
                    'no consecutive eight-frame native decryption-failure burst was observed')
        row['passed'] = True
    finally:
        row['restored'] = loss.clear()
        run.save()


def exercise(run):
    cut = UdpFault(run.nodes['n02'], run.evidence['phone_udp_address'], run.endpoint('n02'))
    row = {'passed': False, 'before_processes': processes(run), 'physical_radio_change': False}
    require(row['before_processes']['phone'] is not None, 'phone process is absent')
    run.evidence['phone_outage'] = row
    run.evidence['harness_sha256']['phone_outage.py'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    run.save()
    identities = {**run.evidence['test_identities'], 'phone': run.evidence['phone_npub']}
    try:
        row['attempted_at'] = time.monotonic()
        run.save()
        row['filter_before'] = cut.enable()
        def observe():
            require(process(run.phone) == row['before_processes']['phone'], 'outage restarted the phone')
            return {**run.screen('background'), 'filter': cut.observe()}
        duplex(run, row, label='phone-outage', count=1024, duration=8, rate=1024,
               observe=observe, expect_denial=True)
        def partition():
            run.monitor.check()
            states = {name: run.accounts.ctl(name, 'status') for name in identities}
            return states if isolated(states, identities) else None
        row['partition'] = eventually('both ends disconnect while other links survive', partition, 90)
        row['filter_after'] = cut.observe()
        require(all(v['packets'] > 0 and v['bytes'] > 0 for v in row['filter_after']['counters'].values()),
                'UDP outage lacks real packet drops in both directions')
        row['outage_seconds'] = time.monotonic() - row['attempted_at']
        row['after_processes'] = processes(run)
        require(row['before_processes'] == row['after_processes'], 'outage restarted a relay')
        row['passed'] = True
    finally:
        row['restored'] = cut.clear()
        run.save()
