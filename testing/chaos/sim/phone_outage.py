"""Cut one paid phone UDP adjacency under the existing router cleanup lease."""

import hashlib
import ipaddress
import json
from pathlib import Path
import time

from .paid_relay import eventually
from .paid_settlement import require
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


class UdpCut:
    def __init__(self, node, phone, router):
        self.node = node
        self.phone, self.router = endpoint(phone), endpoint(router)
        require(self.phone[0] != self.router[0], 'phone and router addresses must differ')
        self.attempted = False

    def rules(self):
        n = self.node
        rules = f'create table netdev {n.table} {{ comment "{n.table_owner}"; }}\n'
        for direction, source, target in (('ingress', self.phone, self.router),
                                          ('egress', self.router, self.phone)):
            rules += (f'add chain netdev {n.table} {direction} {{ type filter hook {direction} '
                      f'device "{n.management}" priority -500; policy accept; }}\n'
                      f'add rule netdev {n.table} {direction} ip saddr {source[0]} '
                      f'ip daddr {target[0]} udp sport {source[1]} udp dport {target[1]} counter drop\n')
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
            require(len(counters) == 1, 'UDP outage counter is missing or ambiguous')
            result[rule['chain']] = {k: natural(counters[0][k]) for k in ('packets', 'bytes')}
        return result

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


def exercise(run):
    cut = UdpCut(run.nodes['n02'], run.evidence['phone_udp_address'], run.endpoint('n02'))
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
