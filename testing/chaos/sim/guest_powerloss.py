"""Exercise saved paid accounts across loss of an isolated guest's kernel/cache.

Uses the existing test mint, workload, financial and settlement checks. This is
guest power-loss coverage on ext4, not physical flash or mint-host power loss.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shlex
import time
from types import SimpleNamespace
from urllib.parse import urlsplit

from .cadence_workloads import stream
from .guest_system import Guest, digest
from .paid_finances import financial_snapshot, payments_credited
from .paid_relay import eventually, relay_config
from .paid_settlement import original_channels, require, settle_and_collect, validate_report
from .paid_wifi_mint import LocalMint
from .restart_finances import QUOTE_UNITS, recovered_exposure, retained_finances


class PowerLossRun:
    stream = stream

    def __init__(self, args):
        self.root = args.output.resolve()
        self.root.mkdir(mode=0o700)
        self.nodes = {f'n{i:02}': SimpleNamespace(npub=None) for i in range(1, 4)}
        self.evidence = {'status': 'preparing', 'physical_power_loss': False, 'phases': [],
                         'test_funds_only': True, 'source_revision': args.source_revision,
                         'binaries': {name: digest(args.binary_dir / name) for name in
                                      ('fips-relay', 'fips-relay-test-mint')}}
        self.guest = Guest(self.root / 'guest', args.kernel, args.binary_dir / 'fips-relay')
        mint_root = self.root / 'mint'
        mint_root.mkdir(mode=0o700)
        self.mint = LocalMint(args.binary_dir / 'fips-relay-test-mint', '127.0.0.1', mint_root)
        self.configs = {}
        self.funded = False
        self.cut_at = args.cut_at
        self.evidence['cut_at'] = self.cut_at

    def save(self):
        temporary = self.root / 'result.pending'
        temporary.write_text(json.dumps(self.evidence, indent=2) + '\n')
        temporary.replace(self.root / 'result.json')

    def execute(self, node, binary, action, request=None, timeout=90):
        if node == 'mint':
            require(binary == 'fips-relay-test-mint' and action == 'ctl', 'invalid mint action')
            return self.mint.request(request)
        require(node in self.nodes and binary == 'fips-relay', 'unknown guest account')
        output = self.guest.execute(['/opt/bench/fips-relay', action, f'/data/{node}/config.json'],
                                    json.dumps(request).encode() if request is not None else None,
                                    timeout=timeout)
        return output.decode().strip() if action == 'init' else json.loads(output)

    def ctl(self, node, kind, **fields):
        return self.execute(node, 'fips-relay', 'ctl', {'type': kind, **fields},
                            timeout=10 if kind == 'status' else 90)

    def state_json(self, node, relative):
        require(node in self.nodes and '..' not in Path(relative).parts
                and not Path(relative).is_absolute(), 'invalid state path')
        return json.loads(self.guest.execute(['cat', f'/data/{node}/state/{relative}']))

    def finances(self):
        return financial_snapshot(self, wallet=None)

    def write_config(self, node):
        self.guest.execute(['sh', '-c', 'umask 077; cat > "$1"', '_',
                            f'/data/{node}/config.json'], json.dumps(self.configs[node]).encode())

    def launch(self, node):
        # All names are from the fixed three-node fixture. The supervisor records
        # a real exit status while the guest kernel reaps the original child.
        script = (f'/opt/bench/fips-relay run /data/{node}/config.json & '
                  f'child=$!; echo $child > /run/{node}.pid; wait $child; '
                  f'echo $? > /run/{node}.exit')
        self.guest.execute(['sh', '-c',
            f'setsid sh -c {shlex.quote(script)} >/run/{node}.log 2>&1 </dev/null &'])

    def stop(self, node):
        pid = int(self.guest.execute(['cat', f'/run/{node}.pid']))
        expected = f'/opt/bench/fips-relay\0run\0/data/{node}/config.json\0'.encode()
        require(pid > 1 and self.guest.execute(['cat', f'/proc/{pid}/cmdline']) == expected,
                'guest relay PID no longer matches the owned account')
        self.guest.execute(['kill', '-TERM', str(pid)])
        result = eventually('guest relay graceful exit', lambda: self.guest.execute(
            ['cat', f'/run/{node}.exit']).decode().strip(), 50)
        require(result == '0', 'guest relay did not stop cleanly')

    def ready(self):
        for index, node in enumerate(self.nodes):
            status = self.ctl(node, 'status')
            require(status['npub'] == self.nodes[node].npub, 'saved guest identity changed')
            peers = [peer for peer in status['peers'] if peer['connected']]
            expected = {other.npub for i, other in enumerate(self.nodes.values())
                        if abs(i - index) == 1}
            if {peer['npub'] for peer in peers} != expected:
                return False
            require(all(peer['transport'] == 'udp' for peer in peers), 'unexpected test carrier')
        return True

    def prepare_accounts(self, mint):
        for index, node in enumerate(self.nodes):
            self.guest.execute(['mkdir', '-m', '700', f'/data/{node}'])
            config = relay_config([], mint)
            config['state_directory'] = f'/data/{node}/state'
            config['transports'] = {'udp': {'bind_addr': f'127.0.0.1:{12001 + index}',
                                             'advertise_on_nostr': False}}
            config['terms'].update(fee_msat_per_kib=1, max_rate_msat_per_kib=1,
                                   quote_max_units=QUOTE_UNITS)
            self.configs[node] = config
            self.write_config(node)
            self.nodes[node].npub = self.execute(node, 'fips-relay', 'init')
        # Never reinitialize these accounts on subsequent boots.
        for index, node in enumerate(self.nodes):
            self.configs[node]['neighbors'] = [
                {'npub': other.npub, 'addresses': [
                    {'transport': 'udp', 'addr': f'127.0.0.1:{12001 + i}'}]}
                for i, other in enumerate(self.nodes.values()) if abs(i - index) == 1]
            self.write_config(node)
            self.funded = True
            token = self.mint.grant(node)
            self.execute(node, 'fips-relay', 'wallet', {'type': 'import', 'token': token})
            require(self.execute(node, 'fips-relay', 'wallet', {'type': 'balance'})['balance_sat']
                    == 128, 'initial guest wallet balance differs')
        self.guest.execute(['sync'])
        for node in self.nodes:
            self.launch(node)
        eventually('initial guest line', self.ready, 60)

    def warmup(self):
        for source, destination in [('n01', 'n03'), ('n03', 'n01')]:
            for _ in range(6):
                probe = self.stream(1, 1, source=source, destination=destination)
                if probe['receiver']['unique_packets'] == 1:
                    break
            require(probe['receiver']['unique_packets'] == 1, 'guest session warmup failed')

    def payloads(self):
        for source, destination in [('n01', 'n03'), ('n03', 'n01')]:
            probe = self.stream(1280, 1000, source=source, destination=destination)
            require(probe['sender']['submitted_packets'] == 1280
                    and probe['receiver']['unique_packets'] == 1280, 'paid guest payload loss')
            self.evidence['phases'].append({'source': source, 'destination': destination, **probe})
        self.save()

    def interrupt_traffic(self):
        previous_stream = self.ctl('n03', 'status')['probe']['stream_id']
        with ThreadPoolExecutor(max_workers=1) as pool:
            sending = pool.submit(self.stream, 4000, 500)

            def active():
                probe = self.ctl('n03', 'status')['probe']
                return probe if (probe and probe['stream_id'] != previous_stream
                                 and probe['expected_packets'] == 4000
                                 and probe['source'] == self.nodes['n01'].npub
                                 and 100 <= probe['unique_packets'] < 4000) else None

            observed = eventually('active paid stream before guest power loss', active, 15)
            require(not sending.done(), 'stream completed before guest power loss')
            self.evidence['power_cut'] = {'receiver_before': observed, 'at': time.time(),
                                          'guest_pid': self.guest.process.pid}
            self.save()
            self.guest.cut_power()
            try:
                sending.result(timeout=15)
            except RuntimeError:
                pass
            else:
                raise RuntimeError('interrupted sender unexpectedly completed')

    def interrupt_settlement(self, anchor):
        channel, _ = next(iter(anchor['n01']['funding'].values()))
        before = {node: self.state_json(node, 'controller/controller.json') for node in self.nodes}
        require(all(not state['buyer_settlements'] and not state['seller_settlements']
                    for state in before.values()), 'settlement already started')
        armed = self.mint.request({'type': 'fault', 'command': {'action': 'arm_swap_reply'}})
        require(armed['phase'] == 'armed', 'mint response barrier did not arm')
        with ThreadPoolExecutor(max_workers=1) as pool:
            settling = pool.submit(self.ctl, 'n01', 'settle')

            def committed():
                status = self.mint.request({'type': 'fault', 'command': {'action': 'status'}})
                return status if status['phase'] == 'held' else None

            held = eventually('committed settlement swap before guest power loss', committed, 30)
            require(held['generation'] == armed['generation']
                    and held['swaps'] == armed['swaps'] + 1 and not settling.done(),
                    'settlement did not reach its single committed swap boundary')
            pending = {node: self.state_json(node, 'controller/controller.json') for node in self.nodes}
            sale = pending['n02']['seller_settlements'][channel]
            purchase = pending['n01']['buyer_settlements'][channel]
            require(set(pending['n02']['seller_settlements']) == {channel}
                    and set(pending['n01']['buyer_settlements']) == {channel}
                    and sale['report'] is None and purchase['report'] is None
                    and not sale['released'] and not purchase['refunded']
                    and sale['channel'] == purchase['channel']
                    and sale['payment'] == purchase['payment']
                    and 0 < sale['payment']['balance'] < 32,
                    'the original paid channel is not pending settlement')
            for node in self.nodes:
                require(pending[node]['funding'] == before[node]['funding']
                        and pending[node]['next_funding'] == before[node]['next_funding'],
                        'settlement created or changed channel funding')
            self.evidence['power_cut'] = {
                'channel_id': channel, 'paid_sat': sale['payment']['balance'],
                'mint_armed': armed, 'mint_held': held, 'at': time.time(),
                'guest_pid': self.guest.process.pid,
                'pending_controller_sha256': {node: hashlib.sha256(
                    json.dumps(state, sort_keys=True).encode()).hexdigest()
                    for node, state in pending.items()},
            }
            self.save()
            self.guest.cut_power()
            try:
                settling.result(timeout=15)
            except RuntimeError:
                pass
            else:
                raise RuntimeError('interrupted settlement unexpectedly completed')
        released = self.mint.request({'type': 'fault', 'command': {
            'action': 'release', 'generation': held['generation']}})
        require(released['phase'] == 'released', 'mint response barrier remained active')
        return channel, pending

    def recover_settlement(self, channel, pending):
        # Observe the recovered disk before starting any wallet or relay process.
        for node in self.nodes:
            stopped = self.state_json(node, 'controller/controller.json')
            for key in ('funding', 'next_funding', 'buyer_settlements', 'seller_settlements'):
                require(stopped[key] == pending[node][key], 'guest lost durable settlement intent')
        self.launch('n02')

        def provider_recovered():
            sale = self.state_json('n02', 'controller/controller.json')['seller_settlements'][channel]
            return sale if sale['report'] is not None else None

        sale = eventually('provider recovery without its buyer', provider_recovered, 60)
        report = validate_report(sale['report'])
        require(sale == {**pending['n02']['seller_settlements'][channel], 'report': sale['report']}
                and report['channel_id'] == channel
                and report['paid_sat'] == pending['n01']['buyer_settlements'][channel]['payment']['balance'],
                'provider recovery changed the original settlement')
        restored = self.mint.request({'type': 'fault', 'command': {'action': 'status'}})
        require(restored['restores'] > self.evidence['power_cut']['mint_held']['restores'],
                'provider did not restore the committed mint response')
        for node in ('n01', 'n03'):
            self.launch(node)
        eventually('recovered guest line', self.ready, 90)

        def buyer_recovered():
            purchase = self.state_json('n01', 'controller/controller.json')['buyer_settlements'][channel]
            return purchase if purchase['refunded'] and purchase['released'] else None

        purchase = eventually('automatic original buyer refund', buyer_recovered, 60)
        require(purchase == {**pending['n01']['buyer_settlements'][channel],
                             'report': sale['report'], 'released': True, 'refunded': True,
                             'wallet_refund_sat': report['refunded_sat']},
                'buyer recovery changed the original settlement or refund')
        for node in self.nodes:
            current = self.state_json(node, 'controller/controller.json')
            require(current['funding'] == pending[node]['funding']
                    and current['next_funding'] == pending[node]['next_funding'],
                    'recovery changed original funding or allocated a new operation')
        self.evidence['automatic_settlement_recovery'] = {
            'report': report, 'provider_recovered_without_buyer': True,
            'buyer_refunded_without_new_settle': True, 'mint_restored': restored,
        }
        self.save()

    def run(self):
        try:
            self.guest.prepare()
            mint = self.mint.start()
            first_boot = self.guest.boot(urlsplit(mint).port)
            mounts = self.guest.execute(['cat', '/proc/mounts']).decode().splitlines()
            require(any(line.startswith('/dev/vda /data ext4 ') and 'commit=60' in line
                        for line in mounts), 'guest state is not on the explicit ext4 filesystem')
            self.prepare_accounts(mint)
            for source, destination in [('n01', 'n03'), ('n03', 'n01')]:
                self.ctl(source, 'buy', destination=self.nodes[destination].npub)
            self.warmup()
            self.payloads()
            anchor = eventually('initial paid credit', lambda: (
                current if payments_credited(current := self.finances()) else None), 30)
            original_channels(self.nodes, anchor)
            self.evidence.update(status='funded', initial_finances=anchor, first_boot=first_boot)
            self.save()
            if self.cut_at == 'traffic':
                self.interrupt_traffic()
            else:
                channel, pending = self.interrupt_settlement(anchor)
            second_boot = self.guest.boot(urlsplit(mint).port)
            require(second_boot != first_boot, 'guest did not enter a new kernel boot')
            self.evidence['second_boot'] = second_boot
            self.save()
            if self.cut_at == 'traffic':
                stopped = self.state_json('n02', 'seller/ledger.json')
                lost = recovered_exposure(stopped)
                self.evidence['expected_lost_msat'] = lost
                for node in self.nodes:
                    self.launch(node)
                eventually('recovered guest line', self.ready, 90)
                self.warmup()
                self.payloads()
                anchor = eventually('original guest financial limits after power loss',
                    lambda: retained_finances(anchor, self.finances(), lost), 45)
                self.evidence['recovered_finances'] = anchor
            else:
                self.recover_settlement(channel, pending)
            settle_and_collect(self, anchor, stop=self.stop,
                               export_path=lambda node, relative: f'/data/{node}/state/{relative}')
            self.evidence['mint_closure'] = self.mint.finish()
            require(not self.evidence['mint_closure'].get('retained_for_recovery'),
                    'test mint still owns uncollected funds')
            self.guest.shutdown()
            self.evidence['status'] = 'passed'
        except BaseException as error:
            self.evidence.update(status='failed', error=repr(error), retained_for_recovery=self.funded)
            if not self.funded:
                self.evidence['mint_closure'] = self.mint.finish()
                self.guest.shutdown()
            raise
        finally:
            self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--binary-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--source-revision', required=True)
    parser.add_argument('--cut-at', choices=('traffic', 'settlement'), default='traffic')
    args = parser.parse_args()
    os.umask(0o077)
    PowerLossRun(args).run()


if __name__ == '__main__':
    main()
