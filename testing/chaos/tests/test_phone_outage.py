"""The phone outage must be narrow, observed in both directions and reversible."""
import copy
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from sim.phone_outage import UdpFault, isolated, peer_session, validate_sessions


def table():
    return {'nftables': [
        {'table': {'family': 'netdev', 'name': 'fips_test', 'comment': 'owner'}},
        *({'rule': {'chain': chain, 'expr': [{'counter': {'packets': 3, 'bytes': 120}}]}}
          for chain in ('ingress', 'egress'))]}


class PhoneOutageTests(unittest.TestCase):
    def cut(self):
        node = SimpleNamespace(table='fips_test', table_owner='owner', management='br-lan')
        return UdpFault(node, '192.0.2.10:43123', '192.0.2.20:5917')

    def test_rules_match_only_one_udp_pair_on_the_existing_bridge(self):
        rules = self.cut().rules()
        self.assertEqual(rules.count('counter drop'), 2)
        self.assertEqual(rules.count('policy accept'), 2)
        self.assertEqual(rules.count('device "br-lan"'), 2)
        self.assertIn('ip saddr 192.0.2.10 ip daddr 192.0.2.20 udp sport 43123 udp dport 5917', rules)
        self.assertIn('ip saddr 192.0.2.20 ip daddr 192.0.2.10 udp sport 5917 udp dport 43123', rules)
        for endpoint in ('0.0.0.0:5917', '192.0.2.10:0', '192.0.2.10:65536', '192.0.2.10:12;reboot'):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                UdpFault(self.cut().node, endpoint, '192.0.2.20:5917')

    def test_corruption_matches_only_complete_established_frames_and_keeps_udp_deliverable(self):
        fault = UdpFault(self.cut().node, '192.0.2.10:43123', '192.0.2.20:5917',
                         every=100, burst=8, mode='corrupt')
        rules = fault.rules()
        self.assertEqual(rules.count('udp length >= 40 @th,64,8 0'), 2)
        self.assertEqual(rules.count('counter numgen inc mod 100 < 8 counter'), 2)
        self.assertEqual(rules.count('@th,192,8 set @th,192,8 ^ 0x01 udp checksum set 0'), 2)
        self.assertNotIn(' drop', rules)
        for args in ({'burst': 0}, {'every': 20, 'burst': 21}, {'mode': 'unknown'}):
            with self.subTest(args=args), self.assertRaises(RuntimeError):
                UdpFault(fault.node, '192.0.2.10:43123', '192.0.2.20:5917', **args)

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

    def test_corruption_requires_original_mature_sessions_and_fresh_authenticated_traffic(self):
        peer = dict(npub='peer', connectivity='connected', transport_type='udp',
                    our_session_index='1234abcd', link_id=1, authenticated_at_ms=1000,
                    last_seen_ms=32_000, rekey_in_progress=False)
        before = {name: peer_session([peer], 'peer') for name in ('n02', 'phone')}
        after = {name: {**value, 'last_seen_ms': 332_000} for name, value in before.items()}
        validate_sessions(before, after)
        for field, value in [('our_session_index', '1234abce'), ('link_id', 2),
                             ('authenticated_at_ms', 32_000), ('last_seen_ms', 32_000)]:
            invalid = copy.deepcopy(after); invalid['phone'][field] = value
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                validate_sessions(before, invalid)
        rotated = copy.deepcopy(after)
        rotated['phone'].update(our_session_index='5678abcd', rekey_in_progress=True)
        with self.assertRaises(RuntimeError):
            validate_sessions(before, rotated)
        validate_sessions(before, rotated, allow_rotation=True)
        rotated['phone']['authenticated_at_ms'] += 1
        with self.assertRaises(RuntimeError):
            validate_sessions(before, rotated, allow_rotation=True)
        before['n02']['authenticated_at_ms'] = 31_000
        with self.assertRaises(RuntimeError):
            validate_sessions(before, after)

    def test_periodic_loss_observes_real_drops_and_preserves_rule_identity(self):
        loss = UdpFault(self.cut().node, '192.0.2.10:43123', '192.0.2.20:5917', every=20)
        self.assertEqual(loss.rules().count('counter numgen inc mod 20 0 counter drop'), 2)
        def observation(matched, dropped):
            value = table()
            for handle, row in enumerate(value['nftables'][1:], 1):
                row['rule'].update(handle=handle, expr=[
                    {'counter': {'packets': matched, 'bytes': matched * 100}},
                    {'counter': {'packets': dropped, 'bytes': dropped * 100}}])
            return {'table': value}
        before, after = observation(1000, 50), observation(3000, 150)
        self.assertEqual(loss.validate_effect(before, after), {
            chain: {'matched_packets': 2000, 'packets': 100, 'bytes': 10000}
            for chain in ('ingress', 'egress')})
        for invalid in (observation(3000, 50), observation(3000, 500), observation(900, 49)):
            with self.subTest(invalid=invalid), self.assertRaises(RuntimeError):
                loss.validate_effect(before, invalid)
        after['table']['nftables'][1]['rule']['handle'] += 20
        with self.assertRaises(RuntimeError):
            loss.validate_effect(before, after)

    def test_impaired_transfer_failure_still_removes_the_owned_filter(self):
        from sim.phone_outage import impaired_transit
        run = Mock()
        run.nodes = {'n02': Mock()}
        run.args.impaired_transit = 'drop'
        run.evidence = {'phone_udp_address': '192.0.2.10:43123', 'harness_sha256': {}}
        run.stream.side_effect = RuntimeError('transfer did not finish')
        with patch('sim.phone_outage.UdpFault') as fault, \
                patch('sim.phone_outage.processes', return_value={'phone': {'pid': 1}}):
            with self.assertRaisesRegex(RuntimeError, 'did not finish'):
                impaired_transit(run)
            fault.return_value.clear.assert_called_once_with()
            self.assertFalse(run.evidence['phone_impairment']['passed'])

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
