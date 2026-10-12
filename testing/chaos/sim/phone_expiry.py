"""Recover a stopped Android relay's original buyer and seller channels at expiry.

Uses the existing paid transit workload, immutable accounts and settlement checks.
The phone is force-stopped; router processes stop normally. No power loss or
network configuration change is implied by this controlled LAN test.
"""

import hashlib
import json
from pathlib import Path
import time

from .paid_phone_checks import guest_source
from .paid_phone_transit import PhoneTransitRun
from .paid_relay import eventually
from .paid_settlement import require, validate_report
from .phone_diagnostics import control, native
from .phone_restart import force_stop, process
from .wifi_profiles import configure_stopped


class PhoneExpiryRun(PhoneTransitRun):
    def __init__(self, args):
        require(not any(getattr(args, flag, False) for flag in (
            'screen_off', 'sustained_transit', 'forced_idle', 'phone_outage',
            'phone_restart', 'phone_renewal', 'impaired_transit', 'compare_transit_rates')),
            'expiry recovery is a separate transit workload')
        super().__init__(args)
        self.evidence['phone_expiry'] = {'passed': False, 'physical_power_loss': False}
        self.evidence['harness_sha256']['phone_expiry.py'] = hashlib.sha256(
            Path(__file__).read_bytes()).hexdigest()

    def profile_config(self, node):
        config = super().profile_config(node)
        config['terms']['controller']['channel_lifetime_secs'] = 600
        if node is self.nodes['n02']:
            config['terms']['quote_lifetime_secs'] = 210
        return config

    def controller(self, name):
        return self.accounts.state_json(name, 'controller/controller.json')

    def expired_sale(self, owner, provider, channel):
        def complete():
            self.monitor.check()
            sale = self.controller(provider)['seller_settlements'].get(channel)
            return sale if sale and sale['report'] is not None else None
        sale = eventually('independent expiry of ' + owner + ' channel', complete, 180)
        report = validate_report(sale['report'])
        require(sale['payment'] is None and not sale['released']
                and report['channel_id'] == channel and 0 < report['paid_sat'] < 32
                and sale['report']['signed_sat'] == report['paid_sat'],
                'provider did not independently complete the original paid channel')
        self.evidence['phone_expiry'].setdefault('provider_reports', {})[owner] = {
            'provider': provider, 'sale': sale, 'observed_at': time.time(),
        }
        self.save()
        return sale['report']

    def settle(self):
        before = json.loads((self.root / 'paid-journals.json').read_text())
        channels = {}
        for name in self.accounts.nodes:
            outgoing = list(before[name]['controller']['outgoing'].values())
            require(len(outgoing) == 1, 'expiry requires one original purchase per account')
            channels[name] = outgoing[0]['purchase']['channel']['id']
        row = self.evidence['phone_expiry']
        row['channels'] = channels
        purchases = {name: next(iter(before[name]['controller']['outgoing'].values()))['purchase']
                     for name in channels}
        expiry = max(purchases[name]['channel']['expires_unix'] for name in ('n01', 'n02'))
        expiry = max(expiry, purchases['phone']['contract']['expires_unix'])
        require(expiry < purchases['phone']['channel']['expires_unix'],
                'phone route must expire before its long-lived channel')
        row['reopen_after_unix'] = expiry
        customer = self.phone.status()['customer']
        self.once('pause-phone-renewals', lambda: control(self.phone, 'pause_renewals'))
        self.once('stop-expiry-buyer-n01', self.nodes['n01'].stop)
        row['phone_stop'] = force_stop(self.phone)
        self.once('stop-expiry-buyer-n02', self.nodes['n02'].stop)
        require(not self.controller('n02')['seller_settlements'].get(channels['phone']),
                'phone outgoing channel settled before its interruption')
        self.phase('phone and its buyers stopped with their original paid accounts')

        def expired():
            self.monitor.check()
            return time.time() > expiry
        eventually('phone route and sold channels expire while stopped', expired, 330)
        require(process(self.phone) is None, 'phone restarted before expiry')
        self.expiry_reports = {}
        reopened = self.phone.launch()['customer']
        require(reopened['configured'] and not reopened['running']
                and all(reopened[key] == customer[key] for key in ('npub', 'profile')),
                'reopen changed the saved phone identity or profile')
        current = process(self.phone)
        require(current and current['start_ticks'] > row['phone_stop']['before']['start_ticks'],
                'phone did not reopen in a new process')
        row['phone_reopened'] = current
        require(self.ui('start')['customer']['running'], 'original phone account did not start')
        for name in ('n01', 'n02'):
            self.nodes[name].remote(['sh', self.nodes[name].temporary + '/guard.sh', 'stopped'])
            self.expiry_reports[channels[name]] = self.expired_sale(name, 'phone', channels[name])
        self.phase('phone recovered both seller reports while its buyers remained stopped')

        # A restarted phone gets a fresh UDP port. Update only the stopped peer's
        # discovery input; immutable financial terms and channel owners stay put.
        adapters = native(self.phone, 'show_transports')['data']['transports']
        require(len(adapters) == 1 and adapters[0]['type'] == 'udp', 'unexpected phone transport')
        port = int(adapters[0]['local_addr'].rsplit(':', 1)[1])
        require(0 < port <= 65535, 'phone listener has no bound port')
        source, _ = guest_source(self.phone, self.customer)
        configure_stopped(self.nodes['n02'], neighbors=[
            {'npub': self.evidence['phone_npub'],
             'addresses': [{'transport': 'udp', 'addr': f'{source}:{port}'}]},
            {'npub': self.nodes['n03'].npub,
             'addresses': [{'transport': 'udp', 'addr': self.endpoint('n03')}]},
        ])
        for name in ('n02', 'n01'):
            self.nodes[name].start()
        eventually('original phone transit line after expiry', self.topology, 90)

        def refunded():
            states = {name: self.controller(name) for name in self.accounts.nodes}
            for owner, provider in self.expected_edges():
                channel = channels[owner]
                purchase = states[owner]['buyer_settlements'].get(channel)
                sale = states[provider]['seller_settlements'].get(channel)
                if not purchase or not sale or not (purchase['refunded'] and purchase['released'] and sale['released']):
                    return None
                require(purchase['report'] == sale['report'], 'buyer and provider reports differ')
                if channel in self.expiry_reports:
                    require(sale['report'] == self.expiry_reports[channel] and sale['payment'] is None,
                            'recovery replaced the original expiry report')
            for name, state in states.items():
                old = before[name]['controller']
                require(all(state[key] == old[key] for key in ('funding', 'next_funding', 'policy')),
                        'expiry recovery changed original funding or spending policy')
            return states

        states = eventually('automatic refunds after phone expiry', refunded, 60)
        phone_sale = states['n02']['seller_settlements'][channels['phone']]
        require(phone_sale['payment'] is not None,
                'phone route refund unexpectedly waited for native channel expiry')
        row['phone_buyer_report'] = phone_sale['report']
        # The fourth buyer stays online. Its provider may finish at expiry before
        # the cooperative request arrives; retain that report before final replay.
        other = states['n02']['seller_settlements'][channels['n03']]
        if other['payment'] is None:
            report = validate_report(other['report'])
            require(other['report']['signed_sat'] == report['paid_sat'], 'fourth expiry signature changed')
            self.expiry_reports[channels['n03']] = other['report']
            row['additional_expiry_report'] = other['report']
        row.update(passed=True, automatic_refunds=True, original_funding_preserved=True)
        self.phase('phone route and seller channels recovered refunds without a settlement request')
        super().settle()
