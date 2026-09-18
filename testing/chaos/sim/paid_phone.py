"""Paid acceptance phone through three fresh, guarded OpenWrt mesh accounts.

The operator selects the guest Wi-Fi and installs a verified isolated acceptance
APK. This harness never installs apps, changes phone networks, or replays an
uncertain funding/UI action. Private scenario/evidence paths are explicit inputs.
"""

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import signal
import time
import traceback

from .paid_finances import financial_snapshot, payments_credited
from .paid_phone_checks import (
    check_customer_access, guest_source, installed_apk_hash, original_hashes,
    scenario,
)
from .paid_phone_finances import check_mint, validate_settled
from .paid_relay import eventually, relay_config
from .paid_settlement import require, validate_report
from .phone_customer import PhoneCustomer, LABELS, save
from .remote_mint import RemoteMint
from .wifi_customer import CustomerAccess
from .wifi_discovery import WifiRun
from .wifi_remote import ETHERTYPE, digest


class Accounts:
    def __init__(self, run):
        self.run = run
        self.nodes = [*run.nodes, 'phone']

    def ctl(self, name, kind):
        if name == 'phone':
            require(kind == 'status', 'phone only exposes actual UI status')
            state = self.run.phone.status()['customer']
            require(state['running'] and state['relay'], 'phone live status unavailable')
            return state['relay']
        return self.run.ctl(name, kind)

    def state_json(self, name, relative):
        if name == 'phone':
            return self.run.phone.account_file(relative)
        node = self.run.nodes[name]
        return json.loads(node.remote(['cat', node.state + '/' + relative]))


class PaidPhoneRun(WifiRun):
    def __init__(self, args):
        self.scenario = scenario(args.scenario)
        self.customer = self.scenario['customer']
        guest = ipaddress.IPv4Interface(self.customer['cidr'])
        self.entry_address = f"{guest.ip}:{self.customer['entry_port']}"
        super().__init__(args)
        phone = self.scenario['phone']
        self.phone = PhoneCustomer(phone['adb'], phone['serial'], phone['evidence_dir'])
        mint = self.scenario['mint']
        self.mint = RemoteMint(
            mint['ssh_spec'], args.mint_binary, self.run, self.root,
            mint['address'],
        )
        self.access = None
        self.mint_url = None
        self.accounts = Accounts(self)
        self.evidence.update(
            test_funds_only=True, money_operations=True,
            phone_adapter=str(self.phone.root),
        )
        self.original_phone = None
        self.steps = self.root / 'operations'
        self.steps.mkdir(mode=0o700)
        save(self.root / 'scenario.json', self.scenario)
        for name in (
            'paid_phone.py', 'paid_phone_checks.py', 'paid_phone_finances.py',
            'phone_customer.py', 'remote_mint.py', 'mint_host.py',
            'wifi_customer.py',
        ):
            self.evidence['harness_sha256'][name] = digest(Path(__file__).with_name(name).read_bytes())

    def once(self, label, function):
        save(self.steps / (label + '-intent.json'), {'label': label, 'at': time.time()})
        result = function()
        # Token-bearing operation results remain in the private run directory.
        save(self.steps / (label + '-result.json'), result)
        return result

    def ui(self, action):
        return self.phone.click(LABELS[action], action, timeout=90)

    def profile_config(self, node):
        config = relay_config([node.interface], self.mint_url)
        config['state_directory'] = node.state
        config['transports']['ethernet'][node.interface]['ethertype'] = ETHERTYPE
        config['return_allowance'] = False
        if node is self.nodes['n01']:
            config['transports']['udp'] = {
                'bind_addr': self.entry_address, 'advertise_on_nostr': False,
            }
            config['customer_network'] = str(ipaddress.IPv4Interface(self.customer['cidr']).network)
        return config

    def setup(self):
        self.phone.check()
        self.phone.ensure_ready()
        self.evidence['phone_apk_sha256'] = installed_apk_hash(
            self.phone, self.scenario['phone']['apk_sha256'],
        )
        state = self.ui('status')
        require(
            state['customer'] == {'configured': False, 'running': False},
            'phone account is not fresh',
        )
        _, wifi = guest_source(self.phone, self.customer)
        (self.root / 'wifi-before.txt').write_text(wifi)
        self.original_phone = original_hashes(self.phone)
        (self.root / 'original-phone-before.sha256').write_bytes(self.original_phone)
        self.mint_url = self.mint.start()
        self.evidence['mint_process'] = self.mint.info
        self.phase('fresh shared mint started with a 512-test-sat cap')
        save(self.root / 'recovery.json', {
            'mint': self.mint.info, 'mint_root': self.mint.root,
            'mint_url': self.mint_url,
            'routers': {
                n: {
                    'table_owner': v.table_owner, 'open_owner': v.open_owner,
                    'temporary': v.temporary, 'config': v.config,
                    'state': v.state,
                }
                for n, v in self.nodes.items()
            },
        })
        super().setup()

    def before_launch(self):
        self.access = CustomerAccess(
            self.nodes['n01'], self.customer['interface'], self.customer['cidr'],
            self.customer['entry_port'], self.mint_url,
        )
        self.evidence['customer_access'] = self.access.enable()
        for node in self.nodes.values():
            node.remote([
                'uclient-fetch', '-q', '-T', '5', '-O', '/dev/null',
                self.mint_url + '/v1/info',
            ], timeout=10)
        self.check_customer_access()
        profile = {
            'version': 1, 'test_only': True, 'billing': 'forwarding_data',
            'entry_npub': self.nodes['n01'].npub,
            'entry_address': self.entry_address,
            'destination_npub': self.nodes['n03'].npub,
            'mint_url': self.mint_url, 'budget_sat': 64,
            'channel_capacity_sat': 32, 'max_rate_msat_per_kib': 8192,
        }
        save(self.root / 'profile.json', profile)
        self.phone.open_setup(profile)
        status = self.ui('setup')
        require(
            status['customer']['configured']
            and not status['customer']['running']
            and status['balance_sat'] == 0,
            'phone setup did not prove an empty stopped account',
        )
        self.evidence['phone_npub'] = status['customer']['npub']
        self.phase('customer entry and shared mint access configured; all accounts still empty')
        balances = {}
        for name, node in self.nodes.items():
            token = self.mint.grant(name)
            self.once(
                'import-' + name,
                lambda node=node, token=token: node.control(
                    'import', action='wallet', token=token,
                ),
            )
            balance = node.control('balance', action='wallet')
            require(
                balance['mint_url'] == self.mint_url
                and balance['unit'] == 'sat' and balance['balance_sat'] == 128,
                'router initial funding differs',
            )
            balances[name] = 128
        token = self.mint.grant('phone')
        self.phone.stage_funds(token)
        self.ui('status')
        status = self.ui('import')
        require(status['balance_sat'] == 128, 'phone initial funding differs')
        balances['phone'] = 128
        self.phase('four stopped accounts funded with 128 test sats each', balances=balances)

    def check_customer_access(self):
        checks = check_customer_access(self.phone, self.customer, self.mint_url, self.root)
        self.phase(
            'phone mint access works before and after the explicit denied TCP probes',
            probes=checks,
        )

    def assert_finances(self):
        for name in self.nodes:
            state = self.ctl(name, 'status')
            require(
                not state['purchases'] and not state['locked_sat']
                and not any(state['funding_budget'].values()),
                'discovery spent or reserved funds',
            )

    def beacon_evidence(self):
        reports = {
            name: node.native({'command': 'show_transports'})
            for name, node in self.nodes.items()
        }
        self.evidence['last_transport_observation'] = reports
        self.save()
        ready = True
        for name, report in reports.items():
            adapters = report['data']['transports']
            ethernet = [x for x in adapters if x['type'] == 'ethernet']
            udp = [x for x in adapters if x['type'] == 'udp']
            require(
                len(ethernet) == 1
                and ethernet[0]['name'] == self.nodes[name].interface
                and len(udp) == (1 if name == 'n01' else 0)
                and len(adapters) == len(ethernet) + len(udp),
                'unexpected transport shortcut',
            )
            ready = ready and bool(
                ethernet[0]['stats']['beacons_recv']
                and ethernet[0]['stats']['beacons_sent']
            )
        return reports if ready else None

    def journals(self, label):
        result = {
            name: {
                kind: self.accounts.state_json(name, path)
                for kind, path in (
                    ('buyer', 'buyer/buyer.json'),
                    ('controller', 'controller/controller.json'),
                    ('seller', 'seller/ledger.json'),
                )
            }
            for name in self.accounts.nodes
        }
        save(self.root / (label + '-journals.json'), result)
        return result

    def finances(self):
        self.ui('status')
        return financial_snapshot(self.accounts, wallet=None)

    def exercise(self):
        self.form_line()
        status = self.ui('start')
        require(status['customer']['running'], 'phone did not start')
        phone_npub = self.evidence['phone_npub']

        def joined():
            states = {n: self.ctl(n, 'status') for n in self.nodes}
            expected = {
                'n01': {self.nodes['n02'].npub: 'ethernet', phone_npub: 'udp'},
                'n02': {
                    self.nodes['n01'].npub: 'ethernet',
                    self.nodes['n03'].npub: 'ethernet',
                },
                'n03': {self.nodes['n02'].npub: 'ethernet'},
            }
            for n, s in states.items():
                if {p['npub']: p['transport'] for p in s['peers'] if p['connected']} != expected[n]:
                    return False
            return states

        eventually('phone authenticated at the wireless entry', joined, 90)
        self.phase('phone UDP entry and exact two-hop wireless line authenticated')
        self.ui('buy')
        self.once('reverse-watch', lambda: self.ctl(
            'n03', 'watch', destination=phone_npub, max_rate_msat_per_kib=8192,
        ))
        initial = eventually('four-account funding observation', self.finances, 45)
        self.journals('funded')
        self.phase('both endpoints authorized paid forwarding', financial=initial)
        delivery = []
        for index in range(4):
            before = self.ctl('n03', 'status')['received']
            self.ui('send')

            def received():
                now = self.ctl('n03', 'status')['received']
                return now if (
                    now['packets'] == before['packets'] + 1
                    and now['bytes'] == before['bytes'] + 1000
                ) else None

            after = eventually('fresh phone payload at far router', received, 30)
            require(
                after['last_sha256']
                and after['last_sha256'] != before['last_sha256'],
                'stale received payload',
            )
            delivery.append({'direction': 'phone_to_router', 'before': before, 'after': after})
        for index in range(4):
            before = self.ui('status')['customer']['relay']['received']
            payload = ('phone-mesh-' + self.run + '-' + str(index) + '-').ljust(1000, 'x')
            expected = hashlib.sha256(payload.encode()).hexdigest()
            self.once(
                'reverse-send-' + str(index),
                lambda payload=payload: self.ctl(
                    'n03', 'send', destination=phone_npub, payload=payload,
                ),
            )

            def received():
                now = self.ui('status')['customer']['relay']['received']
                return now if (
                    now['packets'] == before['packets'] + 1
                    and now['bytes'] == before['bytes'] + 1000
                    and now['last_sha256'] == expected
                ) else None

            after = eventually('fresh reverse payload at phone', received, 30)
            delivery.append({
                'direction': 'router_to_phone', 'before': before, 'after': after,
                'expected_sha256': expected,
            })

        def paid():
            state = self.finances()
            return state if payments_credited(state) and all(
                state[n]['authorized'] > initial[n]['authorized']
                for n in self.accounts.nodes
            ) else None

        final = eventually('automatic payments on all four funded channels', paid, 60)
        save(self.root / 'paid-finances.json', final)
        self.journals('paid')
        self.phase(
            'eight fresh 1000-byte payloads delivered; every paying hop advanced',
            delivery=delivery, financial=final,
        )
        self.phone.screenshot('phone-paid-' + self.run)
        self.verify_shortcuts()
        self.settle()

    def settle(self):
        reports = {}
        for name in ('n03', 'n02', 'n01'):
            result = self.once('settle-' + name, lambda name=name: self.ctl(name, 'settle'))
            for report in result['settlements']:
                require(report['channel_id'] not in reports, 'duplicate settlement')
                reports[report['channel_id']] = validate_report(report)
        status = self.ui('finish')
        require(not status['customer']['running'], 'phone finish did not stop')
        for node in self.nodes.values():
            node.stop()
        journals = self.journals('settled')
        balance_reports = {
            name: node.control('balance', action='wallet')
            for name, node in self.nodes.items()
        }
        require(
            all(b['mint_url'] == self.mint_url and b['unit'] == 'sat'
                for b in balance_reports.values()),
            'settled router balance scope changed',
        )
        save(self.root / 'settled-router-balances.json', balance_reports)
        balances = {name: b['balance_sat'] for name, b in balance_reports.items()}
        balances['phone'] = status['balance_sat']
        save(self.root / 'settled-balances.json', balances)
        report = self.mint.request({'type': 'report'})
        require(report['url'] == self.mint_url, 'mint identity changed')
        checks = validate_settled(
            journals, json.loads((self.root / 'paid-journals.json').read_text()),
            balances, report,
            [('phone', 'n01'), ('n01', 'n02'), ('n03', 'n02'), ('n02', 'n01')],
        )
        self.phase(
            'all four accounts settled and all 512 test sats conserved',
            checks=checks, balances=balances,
        )
        for name, node in self.nodes.items():
            export_id = 'collect-' + name
            exported = self.once(
                'export-' + name,
                lambda node=node, name=name: node.control(
                    'export', action='wallet', id='collect-' + name,
                    amount_sat=balances[name],
                ),
            )
            payment = self.accounts.state_json(name, 'exports/' + export_id + '.json')
            require(
                payment['amount_sat'] == balances[name]
                and payment['mint_url'] == self.mint_url
                and payment['unit'] == 'sat'
                and payment['operation_id'] == exported['operation_id']
                and payment['send_fee_sat'] == 0
                and exported['path'] == node.state + '/exports/' + export_id + '.json',
                'unexpected export',
            )
            collected = self.mint.request({'type': 'collect', 'token': payment['token']})
            require(
                collected['amount_sat'] == balances[name]
                and collected['mint_url'] == self.mint_url
                and collected['unit'] == 'sat',
                'router collection differs',
            )
            empty = node.control('balance', action='wallet')
            require(
                empty['balance_sat'] == 0 and empty['mint_url'] == self.mint_url
                and empty['unit'] == 'sat',
                'router wallet not empty',
            )
        self.ui('status')
        state = self.ui('export')
        exported = self.phone.private('fund-return.json')
        payment = self.phone.account_file('exports/' + Path(exported['path']).name)
        require(
            payment['amount_sat'] == balances['phone']
            and payment['mint_url'] == self.mint_url
            and payment['unit'] == 'sat'
            and payment['operation_id'] == exported['operation_id']
            and payment['send_fee_sat'] == 0,
            'unexpected phone export',
        )
        collected = self.mint.request({'type': 'collect', 'token': payment['token']})
        require(
            collected['amount_sat'] == balances['phone']
            and state['balance_sat'] == 0
            and collected['mint_url'] == self.mint_url
            and collected['unit'] == 'sat',
            'phone collection differs',
        )
        report = self.mint.request({'type': 'report'})
        check_mint(report, 512)
        require(report['url'] == self.mint_url, 'mint identity changed')
        self.evidence['mint'] = report
        self.phase('all 512 test sats collected; four wallets empty')

    def finish(self):
        if not self.evidence['passed']:
            try:
                self.phone.ensure_ready()
                state = self.ui('status')
                if state['customer']['running']:
                    state = self.ui('stop')
                self.evidence['phone_failure_cleanup'] = {'stopped': not state['customer']['running']}
            except Exception as error:
                self.evidence['phone_failure_cleanup'] = {
                    'uncertain': True, 'error': type(error).__name__,
                }
        try:
            if self.mint_url:
                result = self.mint.finish()
                self.evidence['mint_cleanup'] = result
                if result.get('retained_for_recovery'):
                    self.evidence['passed'] = False
                elif self.access:
                    self.evidence['customer_cleanup'] = self.access.release_mint(result)
            elif self.mint.attempted:
                self.evidence['mint_cleanup'] = {
                    'startup_uncertain': True, 'retained_for_recovery': True,
                }
                self.evidence['passed'] = False
        except Exception as e:
            self.evidence['mint_cleanup_error'] = str(e)
            self.evidence['passed'] = False
        try:
            super().finish()
        except Exception as error:
            self.evidence['router_cleanup_error'] = type(error).__name__
            self.evidence['passed'] = False
        finally:
            try:
                if self.original_phone is not None:
                    after = original_hashes(self.phone)
                    (self.root / 'original-phone-after.sha256').write_bytes(after)
                    self.evidence['original_phone_unchanged'] = after == self.original_phone
                    if after != self.original_phone:
                        self.evidence['passed'] = False
            except Exception as error:
                self.evidence['original_phone_check_error'] = type(error).__name__
                self.evidence['passed'] = False
            finally:
                self.save()
        require(
            self.evidence['passed'],
            'phone acceptance incomplete; preserve exact recorded accounts and mint',
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scenario', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--binary', type=Path, required=True)
    parser.add_argument('--mint-binary', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument(
        '--open-mesh', action='store_true',
        help='use the existing guarded temporary open radio profile',
    )
    args = parser.parse_args()
    os.umask(0o077)

    def deadline(_signal, _frame):
        raise TimeoutError('phone mesh acceptance exceeded 1200 seconds')

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(1200)
    run = PaidPhoneRun(args)
    try:
        run.execute()
    except Exception:
        (run.root / 'failure-private.txt').write_text(traceback.format_exc())
        raise


if __name__ == '__main__':
    main()
