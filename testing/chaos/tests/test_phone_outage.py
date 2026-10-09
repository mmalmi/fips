"""The phone outage must be narrow, observed in both directions and reversible."""
import copy
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace

from sim.phone_outage import UdpCut, isolated


def table():
    return {'nftables': [
        {'table': {'family': 'netdev', 'name': 'fips_test', 'comment': 'owner'}},
        *({'rule': {'chain': chain, 'expr': [{'counter': {'packets': 3, 'bytes': 120}}]}}
          for chain in ('ingress', 'egress'))]}


class PhoneOutageTests(unittest.TestCase):
    def cut(self):
        node = SimpleNamespace(table='fips_test', table_owner='owner', management='br-lan')
        return UdpCut(node, '192.0.2.10:43123', '192.0.2.20:5917')

    def test_rules_match_only_one_udp_pair_on_the_existing_bridge(self):
        rules = self.cut().rules()
        self.assertEqual(rules.count('counter drop'), 2)
        self.assertEqual(rules.count('policy accept'), 2)
        self.assertEqual(rules.count('device "br-lan"'), 2)
        self.assertIn('ip saddr 192.0.2.10 ip daddr 192.0.2.20 udp sport 43123 udp dport 5917', rules)
        self.assertIn('ip saddr 192.0.2.20 ip daddr 192.0.2.10 udp sport 5917 udp dport 43123', rules)
        for endpoint in ('0.0.0.0:5917', '192.0.2.10:0', '192.0.2.10:65536', '192.0.2.10:12;reboot'):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                UdpCut(self.cut().node, endpoint, '192.0.2.20:5917')

    def test_counters_require_the_owned_table_and_one_rule_per_direction(self):
        self.assertEqual(self.cut().counters(table()), {'ingress': {'packets': 3, 'bytes': 120},
                                                       'egress': {'packets': 3, 'bytes': 120}})
        variants = []
        wrong = table(); wrong['nftables'][0]['table']['comment'] = 'another'; variants.append(wrong)
        missing = table(); missing['nftables'].pop(); variants.append(missing)
        duplicate = table(); duplicate['nftables'].append(copy.deepcopy(duplicate['nftables'][1])); variants.append(duplicate)
        negative = table(); negative['nftables'][1]['rule']['expr'][0]['counter']['packets'] = -1; variants.append(negative)
        for value in variants:
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                self.cut().counters(value)

    def test_clear_cannot_delete_another_owners_table(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, body in {
                'nft': '#!/bin/sh\ncase "$*" in *delete*) touch "'+str(root)+'/deleted";; esac\necho unrelated\n',
                'jsonfilter': '#!/bin/sh\ncat >/dev/null\necho another\n',
            }.items():
                (root/name).write_text(body); (root/name).chmod(0o700)
            cut = self.cut(); cut.attempted = True; cut.node.temporary = str(root)
            def guarded(script):
                return subprocess.check_output(['sh'], input=('set -eu\n'+script).encode(),
                                               env={**os.environ, 'PATH': str(root)+':'+os.environ['PATH']})
            cut.node.guarded = guarded
            with self.assertRaises(subprocess.CalledProcessError):
                cut.clear()
            self.assertFalse((root/'deleted').exists())

    def test_partition_requires_both_ends_disconnected_and_other_links_connected(self):
        identities = {name: name for name in ('n01', 'phone', 'n02', 'n03')}
        wanted = {'n01': ['phone'], 'phone': ['n01'], 'n02': ['n03'], 'n03': ['n02']}
        states = {name: {'peers': [{'npub': peer, 'connected': True, 'transport': 'udp'} for peer in peers]}
                  for name, peers in wanted.items()}
        self.assertTrue(isolated(states, identities))
        states['phone']['peers'].append({'npub': 'n02', 'connected': True, 'transport': 'udp'})
        self.assertFalse(isolated(states, identities))
        states['phone']['peers'][-1]['connected'] = False
        self.assertTrue(isolated(states, identities))
        states['n01']['peers'][0]['connected'] = False
        self.assertFalse(isolated(states, identities))
