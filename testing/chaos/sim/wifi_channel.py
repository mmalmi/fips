"""Staggered radio channel handover without changing relay or payment identity."""

from pathlib import Path
import re
import time

from .paid_relay import eventually
from .paid_settlement import require
from .wifi_active_outage import processes
from .wifi_remote import digest
from . import wifi_probes as probes


def options(args):
    frequency = getattr(args, 'handover_frequency', None)
    if frequency is not None:
        require(type(frequency) is int and frequency > 0 and getattr(args, 'open_mesh', False)
                and not any(getattr(args, key, None) for key in (
                    'streams', 'active_outage', 'brief_outage', 'outage_node', 'root_outage',
                    'recovery_timing', 'beacon_interval_secs', 'interrupted_promotion',
                    'carrier_pressure_port', 'crowded_rejoin', 'crowded_pressure', 'crowded_newcomer')),
                'channel handover requires open mesh and its own outage scenario')
    return frequency


def usable_frequencies(text):
    # Accept only plain enabled entries. Radar, no-IR and unknown restrictions
    # must not be silently treated as permission to start a mesh on that channel.
    return {int(value) for value in re.findall(
        r'^\s*\* (\d+)(?:\.0)? MHz \[\d+\] \(\d+(?:\.\d+)? dBm\)\s*$', text, re.MULTILINE)}


def observe(node):
    info = node.remote(['iw', 'dev', node.interface, 'info']).decode()
    result = {}
    for key, pattern in (
            ('frequency', r'channel \d+ \((\d+) MHz\)'),
            ('ifindex', r'^\s*ifindex (\d+)$'), ('wiphy', r'^\s*wiphy (\d+)$')):
        values = re.findall(pattern, info, re.MULTILINE)
        require(len(values) == 1, 'missing or ambiguous radio channel identity')
        result[key] = int(values[0])
    require(result['ifindex'] == node.mesh['ifindex']
            and re.findall(r'^\s*addr ([0-9a-f:]+)$', info, re.MULTILINE) == [node.mac],
            'channel handover replaced the mesh interface')
    return result


def change_frequency(node, frequency):
    require(node.open_mesh and type(frequency) is int and frequency > 0,
            'only an owned open mesh may change channel')
    node.guarded(f'open_change_frequency {frequency}', timeout=60)


def exercise(run):
    target = options(run.args)
    original = {name: observe(node) for name, node in run.nodes.items()}
    frequencies = {row['frequency'] for row in original.values()}
    require(len(frequencies) == 1 and target not in frequencies, 'handover must change channel')
    home, = frequencies
    for name, node in run.nodes.items():
        supported = usable_frequencies(node.remote(
            ['iw', 'phy', 'phy' + str(original[name]['wiphy']), 'info']).decode())
        require({home, target} <= supported, 'handover requires two enabled non-DFS channels')
    evidence = {'passed': False, 'before': original, 'target_frequency': target,
                'processes_before': processes(run), 'switches': [], 'automatic_channel_selection': False}
    run.evidence['channel_handover'] = evidence
    run.evidence['harness_sha256']['wifi_channel.py'] = digest(Path(__file__).read_bytes())
    run.save()
    try:
        for frequency in (target, home):
            row = {'frequency': frequency}
            evidence['switches'].append(row)
            shape = probes.arm(run, 'n01', 'n03', 40, 128, round_trip=True)
            row['shape'] = shape
            probes.send_with_radio_cut(
                run, 'n01', 'n03', shape, 2, run.nodes['n03'], row, round_trip=True,
                cut=lambda: change_frequency(run.nodes['n03'], frequency))
            row['separated_radios'] = {name: observe(node) for name, node in run.nodes.items()}
            require(row['separated_radios']['n03']['frequency'] == frequency
                    and all(row['separated_radios'][name]['frequency'] != frequency
                            for name in ('n01', 'n02')), 'radio channels were not separated')
            first = probes.receive(run, 'n01', 'n03', shape, round_trip=True)
            require(0 < first['unique_packets'] < shape['packet_count'], 'channel switch did not interrupt delivery')
            time.sleep(2)
            row['interrupted_receiver'] = probes.receive(run, 'n01', 'n03', shape, round_trip=True)
            require(row['interrupted_receiver']['unique_packets'] == first['unique_packets'],
                    'separate radio channels continued forwarding')
            row['isolated_peers'] = eventually('channel separation evicts the leaf peer',
                                               lambda: run.ready(line=True, isolated=True), 100)
            row['financial_during_separation'] = run.assert_finances()
            row['rejoin_started'] = time.monotonic()
            for name in ('n02', 'n01'):
                change_frequency(run.nodes[name], frequency)
            eventually('paid radio line on the new channel', lambda: run.ready(line=True), 150)
            run.verify_open_profiles()
            row['joined_radios'] = {name: observe(node) for name, node in run.nodes.items()}
            require(all(value['frequency'] == frequency for value in row['joined_radios'].values()),
                    'routers did not converge on the requested radio channel')
            row['financial_after'] = run.paid_streams(run.assert_finances(),
                                                     'same channels pay after radio frequency change')
            run.retain_channels(run.channel_anchor, row['financial_after'])
            row['recovery_seconds'] = time.monotonic() - row['rejoin_started']
            require(processes(run) == evidence['processes_before'], 'handover restarted a relay')
            run.save()
        evidence['passed'] = True
    finally:
        for name, node in run.nodes.items():
            if not evidence['passed']:
                change_frequency(node, home)
        eventually('original open-mesh channel restored', lambda: run.ready(line=True), 150)
        evidence['restored'] = {name: observe(node) for name, node in run.nodes.items()}
        require(evidence['restored'] == original, 'handover changed the original radio identity')
        run.save()
