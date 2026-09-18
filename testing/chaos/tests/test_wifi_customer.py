"""Lease cleanup and financial retention through the real Linux shell guard."""

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from sim.wifi_customer import CHAINS, CustomerAccess
from tests import test_wifi_discovery as base


NFT = r'''import json,os,re,sys
from pathlib import Path
p=Path(os.environ['CUSTOMER_RULES']); rules=json.loads(p.read_text()); a=sys.argv[1:]
if a[:6]==['-a','-nn','list','chain','inet','fw4']:
 chain=a[6]
 if chain not in rules or os.environ.get('CUSTOMER_LIST_FAIL')==chain:sys.exit(1)
 print('table inet fw4 {\n\tchain '+chain+' {')
 for row in rules[chain]:print('\t\t'+row['text']+' # handle '+str(row['handle']))
 print('\t}\n}')
elif a==['-f','-']:
 text=sys.stdin.read()
 if os.environ.get('CUSTOMER_REJECT'):sys.exit(1)
 for line in text.splitlines():
  m=re.fullmatch(r'insert rule inet fw4 (\w+) (.+)',line)
  if not m or m[1] not in rules:sys.exit(1)
  handle=max(row['handle'] for rows in rules.values() for row in rows)+1
  rules[m[1]].insert(0,{'handle':handle,'text':m[2]})
 p.write_text(json.dumps(rules))
 if os.environ.get('CUSTOMER_LOST_INSERT'):sys.exit(1)
elif a[:4]==['delete','rule','inet','fw4']:
 chain=a[4];handle=int(a[6]);old=rules[chain]
 rules[chain]=[r for r in old if r['handle']!=handle]
 if len(old)==len(rules[chain]):sys.exit(1)
 p.write_text(json.dumps(rules))
 if os.environ.get('CUSTOMER_LOST_DELETE'):sys.exit(1)
elif a[:3]==['-j','list','tables']:print('{"nftables":[]}')
else:sys.exit(2)
'''
IP = r'''import sys
if sys.argv[1:]==['-o','-4','addr','show','dev','guest0']:
 print('7: guest0 inet 192.0.2.1/24 brd 192.0.2.255 scope global guest0')
else:sys.exit(1)
'''


@unittest.skipUnless(sys.platform == 'linux' and shutil.which('flock'), 'needs Linux procfs and flock')
class CustomerGuardTests(unittest.TestCase):
    local = base.GuardTests.local
    start_guard = base.GuardTests.start_guard
    tearDown = base.GuardTests.tearDown

    def setUp(self):
        base.GuardTests.setUp(self)
        self.original = {chain: [{'handle': i + 1, 'text': 'counter reject'}]
                         for i, chain in enumerate(CHAINS.values())}
        self.rules = self.root / 'customer-rules.json'
        self.rules.write_text(json.dumps(self.original))
        self.env['CUSTOMER_RULES'] = str(self.rules)
        for name, script in (('nft', NFT), ('ip', IP)):
            path = self.root / 'bin' / name
            path.write_text('#!' + sys.executable + '\n' + script)
            path.chmod(0o700)
        self.access = CustomerAccess(self.node, 'guest0', '192.0.2.1/24', 40123,
                                     'http://198.51.100.10:40456')
        self.terminal = {'test_only': True, 'url': self.access.mint_url, 'conserved': True,
                         'issued_sat': 384, 'collected_sat': 384, 'stopped': True}

    def state(self):
        return json.loads(self.rules.read_text())

    def change(self, mutate):
        state = self.state()
        mutate(state)
        self.rules.write_text(json.dumps(state))

    def enable(self):
        self.start_guard()
        status = self.access.enable()
        for kind, chain in CHAINS.items():
            self.assertTrue(status[kind + '_rule'])
            self.assertEqual(self.state()[chain][1:], self.original[chain])
        return status

    def cleanup(self):
        self.local(['sh', str(self.guard), 'cleanup'])

    def assert_mint_retained(self):
        status = self.access.observe()
        self.assertFalse(status['udp_rule'])
        self.assertTrue(status['tcp_rule'])
        self.assertTrue(status['snat_rule'])
        self.assertTrue(status['mint_access_retained'])

    def test_exact_three_rules_and_terminal_release_preserve_all_original_rules(self):
        self.enable()
        self.assertIn('iifname "guest0" ip saddr 192.0.2.0/24 ip daddr 192.0.2.1 udp dport 40123',
                      self.state()[CHAINS['udp']][0]['text'])
        self.assertIn('oifname "br-lan" ip saddr 192.0.2.0/24 ip daddr 198.51.100.10 tcp dport 40456',
                      self.state()[CHAINS['snat']][0]['text'])
        self.cleanup()
        self.assert_mint_retained()
        self.access.release_mint(self.terminal)
        self.assertEqual(self.state(), self.original)
        self.assertFalse((self.remote / 'customer-intent').exists())
        # A lost final cleanup response is safe to resolve with the same terminal proof.
        self.access.release_mint(self.terminal)
        self.assertEqual(self.state(), self.original)

    def test_live_zero_issued_or_uncertain_report_cannot_release_mint_access(self):
        self.enable()
        self.cleanup()
        before = self.state()
        changes = ({'stopped': False, 'issued_sat': 0, 'collected_sat': 0},
                   {'stopped': None}, {'conserved': False}, {'test_only': False},
                   {'url': 'http://198.51.100.11:40456'}, {'collected_sat': 383},
                   {'issued_sat': -1, 'collected_sat': -1}, {'issued_sat': True, 'collected_sat': 1})
        for changed in changes:
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                self.access.release_mint({**self.terminal, **changed})
            self.assertEqual(self.state(), before)
        self.access.release_mint({**self.terminal, 'issued_sat': 0, 'collected_sat': 0})
        self.assertEqual(self.state(), self.original)

    def test_reconstructed_helper_cannot_release_another_mints_recorded_access(self):
        self.enable()
        self.cleanup()
        before = self.state()
        other = CustomerAccess(self.node, 'guest0', '192.0.2.1/24', 40123,
                               'http://198.51.100.11:40456')
        with self.assertRaises(RuntimeError):
            other.release_mint({**self.terminal, 'url': other.mint_url})
        self.assertEqual(self.state(), before)
        self.assertFalse((self.remote / 'customer-release').exists())
        self.access.release_mint(self.terminal)
        self.assertEqual(self.state(), self.original)

    def test_lease_expiry_removes_udp_but_keeps_bootstrap_access(self):
        self.enable()
        (self.remote / 'heartbeat').write_text('0')
        self.children[0].wait(timeout=8)
        self.assertFalse((self.remote / 'active').exists())
        self.assert_mint_retained()
        with self.assertRaises(RuntimeError):
            self.access.enable()
        self.assert_mint_retained()
        self.access.release_mint(self.terminal)
        self.assertEqual(self.state(), self.original)

    def test_lost_insert_reply_leaves_complete_cleanup_intent(self):
        self.start_guard()
        self.env['CUSTOMER_LOST_INSERT'] = '1'
        with self.assertRaises(RuntimeError):
            self.access.enable()
        self.assertTrue((self.remote / 'customer-intent').exists())
        self.assertFalse((self.remote / 'customer-udp.handle').exists())
        self.cleanup()
        self.assert_mint_retained()
        self.access.release_mint(self.terminal)
        self.assertEqual(self.state(), self.original)

    def test_rejected_atomic_insert_never_changes_original_rules(self):
        self.start_guard()
        self.env['CUSTOMER_REJECT'] = '1'
        with self.assertRaises(RuntimeError):
            self.access.enable()
        self.assertEqual(self.state(), self.original)
        self.cleanup()
        self.access.release_mint({**self.terminal, 'issued_sat': 0, 'collected_sat': 0})
        self.assertEqual(self.state(), self.original)

    def test_existing_matching_owner_is_a_collision_not_recovery_authority(self):
        self.start_guard()
        self.change(lambda state: state[CHAINS['tcp']].append(
            {'handle': 100, 'text': self.access.rules['tcp']}))
        before = self.state()
        with self.assertRaises(RuntimeError):
            self.access.enable()
        self.cleanup()
        self.assertEqual(self.state(), before)
        self.assertFalse((self.remote / 'customer-intent').exists())

    def test_changed_rule_or_owner_is_not_deleted_by_a_saved_handle(self):
        self.enable()
        saved = copy.deepcopy(self.state())
        for changed in ('udp dport 40124', 'comment "foreign-owner"'):
            self.rules.write_text(json.dumps(saved))
            self.change(lambda state: state[CHAINS['udp']][0].update(text=changed))
            before = self.state()
            self.cleanup()
            self.assertEqual(self.state(), before)
            self.assertTrue((self.remote / 'customer-cleanup-failed').exists())
            self.assertTrue((self.remote / 'customer-udp.rule').exists())

    def test_duplicate_owner_or_changed_handle_is_not_adopted(self):
        self.enable()
        row = copy.deepcopy(self.state()[CHAINS['tcp']][0])
        row['handle'] = 100
        self.change(lambda state: state[CHAINS['tcp']].append(row))
        with self.assertRaises(RuntimeError):
            self.access.release_mint(self.terminal)
        self.assertEqual(len(self.state()[CHAINS['tcp']]), 3)
        self.assertTrue((self.remote / 'customer-cleanup-failed').exists())

    def test_same_comment_replacement_with_a_new_handle_is_not_adopted(self):
        self.enable()
        self.change(lambda state: state[CHAINS['tcp']][0].update(handle=100))
        foreign = copy.deepcopy(self.state()[CHAINS['tcp']])
        with self.assertRaises(RuntimeError):
            self.access.release_mint(self.terminal)
        self.assertEqual(self.state()[CHAINS['tcp']], foreign)
        self.assertTrue((self.remote / 'customer-tcp.rule').exists())
        self.assertTrue((self.remote / 'customer-cleanup-failed').exists())

    def test_lost_delete_reply_is_reconciled_without_deleting_foreign_rules(self):
        self.enable()
        self.env['CUSTOMER_LOST_DELETE'] = '1'
        self.cleanup()
        self.assertTrue((self.remote / 'customer-cleanup-failed').exists())
        self.assertEqual(self.state()[CHAINS['udp']], self.original[CHAINS['udp']])
        self.env.pop('CUSTOMER_LOST_DELETE')
        self.cleanup()
        self.assert_mint_retained()
        self.access.release_mint(self.terminal)
        self.assertEqual(self.state(), self.original)

    def test_failed_chain_query_retains_ownership_evidence_and_other_recovery_access(self):
        self.enable()
        self.env['CUSTOMER_LIST_FAIL'] = CHAINS['udp']
        before = self.state()
        self.cleanup()
        self.assertEqual(self.state(), before)
        self.assertTrue((self.remote / 'customer-cleanup-failed').exists())
        self.assertTrue((self.remote / 'customer-intent').exists())


@unittest.skipUnless(os.environ.get('FIPS_CUSTOMER_ISOLATED_NFT') == '1' and Path('/.dockerenv').exists(),
                     'requires an explicit network-none Linux test container with NET_ADMIN')
class NativeCustomerTests(unittest.TestCase):
    def test_native_nft_matches_guard_rendering_and_restores_existing_chains(self):
        fixture = CustomerGuardTests()
        fixture.setUp()
        created = False
        def nft(*args):
            return subprocess.check_output(['/usr/sbin/nft', *args], timeout=10)
        try:
            # create refuses an existing table; this test never adopts host rules.
            nft('create', 'table', 'inet', 'fw4')
            created = True
            for chain in CHAINS.values():
                nft('add', 'chain', 'inet', 'fw4', chain)
                nft('add', 'rule', 'inet', 'fw4', chain, 'counter', 'reject')
            before = json.loads(nft('-j', 'list', 'table', 'inet', 'fw4'))
            (fixture.root / 'bin' / 'nft').write_text('#!/bin/sh\nexec /usr/sbin/nft "$@"\n')
            fixture.start_guard()
            status = fixture.access.enable()
            self.assertTrue(all(status[kind + '_rule'] for kind in CHAINS))
            fixture.cleanup()
            fixture.assert_mint_retained()
            fixture.access.release_mint(fixture.terminal)
            self.assertEqual(json.loads(nft('-j', 'list', 'table', 'inet', 'fw4')), before)
        finally:
            fixture.tearDown()
            if created:
                nft('delete', 'table', 'inet', 'fw4')


if __name__ == '__main__':
    unittest.main()
