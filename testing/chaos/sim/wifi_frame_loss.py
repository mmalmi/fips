"""Deterministic frame loss inside the existing leased test-only filter table."""

import json
import re

from .paid_settlement import require
from .wifi_link_loss import MAC
from .wifi_priority_checks import natural
from .wifi_remote import ETHERTYPE


EVERY = 20
CHAIN = 'frame_loss'


class FrameLoss:
    def __init__(self, node, source_mac):
        if not isinstance(source_mac, str) or not re.fullmatch(MAC, source_mac):
            raise ValueError('frame loss requires one exact adjacent mesh address')
        self.node, self.source_mac = node, source_mac
        self.comment = node.table_owner + '-loss'

    def owned(self, command, data=None):
        node = self.node
        check = (f'test -f {node.temporary}/table-created\n'
                 f'test "$(nft -j list table netdev {node.table} | '
                 f'jsonfilter -e \'@.nftables[*].table.comment\')" = "{node.table_owner}"\n')
        return node.guarded(check + command, data)

    def observe(self):
        table = json.loads(self.owned(f'nft -j list table netdev {self.node.table}'))
        rows = table['nftables']
        chains = [row['chain']['name'] for row in rows if 'chain' in row]
        jumps = [row['rule'] for row in rows
                 if row.get('rule', {}).get('comment') == self.comment]
        rules = [row['rule'] for row in rows if row.get('rule', {}).get('chain') == CHAIN]
        if CHAIN not in chains:
            require(not jumps and not rules, 'partial frame-loss rule state')
            return {'enabled': False, 'table': table}
        require(chains.count(CHAIN) == 1 and len(jumps) == len(rules) == 1
                and jumps[0]['chain'] == 'ingress', 'ambiguous frame-loss rules')
        counters = [expr['counter'] for expr in rules[0]['expr'] if 'counter' in expr]
        require(len(counters) == 1 and natural(jumps[0]['handle']) > 0,
                'frame-loss counter or jump handle unavailable')
        return {'enabled': True, 'jump_handle': jumps[0]['handle'],
                'dropped_packets': natural(counters[0]['packets']),
                'dropped_bytes': natural(counters[0]['bytes']), 'table': table}

    def enable(self):
        require(not self.observe()['enabled'], 'frame loss is already armed')
        table = self.node.table
        rules = (f'create chain netdev {table} {CHAIN}\n'
                 f'add rule netdev {table} {CHAIN} numgen inc mod {EVERY} 0 counter drop\n'
                 f'add rule netdev {table} ingress ether type 0x{ETHERTYPE:x} '
                 f'ether saddr {self.source_mac} jump {CHAIN} comment "{self.comment}"\n')
        self.owned('nft -f -', rules.encode())
        result = self.observe()
        require(result['enabled'], 'frame-loss installation was not observed')
        return result

    def clear(self):
        # An uncertain enable is reconciled from the owned table, never replayed.
        before = self.observe()
        if before['enabled']:
            table = self.node.table
            rules = (f'delete rule netdev {table} ingress handle {before["jump_handle"]}\n'
                     f'flush chain netdev {table} {CHAIN}\n'
                     f'delete chain netdev {table} {CHAIN}\n')
            self.owned('nft -f -', rules.encode())
        after = self.observe()
        require(not after['enabled'], 'frame loss remains after removal')
        return {'before': before, 'after': after}
