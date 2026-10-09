"""Bounded windows of simultaneous paid traffic through automatic channel renewal.

Fresh capped test accounts, one middle relay and the saved guarded radio mesh.
Finite sends are never replayed; optional loss requires observed filter counters.
This is neither a cadence comparison nor maximum-throughput qualification.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import signal
import time

from . import wifi_probes as probes
from .cadence_workloads import stream
from .paid_finances import FinancialObservationChanged, payments_credited
from .paid_relay import eventually
from .paid_settlement import require
from .paid_wifi import PaidWifiRun
from .wifi_diamond_checks import require_same_process
from .wifi_frame_loss import EVERY, FrameLoss, clear_filters, loss_delta, validate_delivery
from .wifi_measurements import snapshot
from .wifi_priority_checks import received, submitted
from .wifi_remote import digest
from .wifi_renewal_finances import EXPIRY_RENEWAL, ENDPOINTS, NAMES, QUOTE_UNITS, RENEWAL, RenewalAccounts


PACKETS, RATE, SEND_SECONDS, RECEIVE_SECONDS = 42_000, 140, 300, 360
SEND_TIMEOUT, SAMPLE_INTERVAL, FINAL_TAIL = 330, 10, 3
RECOVERY_PACKETS = 64
EXPIRY_QUOTES = {1: 180, 3: 90}
MAX_NEIGHBOR_OBSERVATIONS = 800
LINK_LOG_FILTER = ("warn,fips_relay::controller::renewal=debug,"
                   "fips_core::dataplane::source_wait=debug,"
                   "fips_core::node::handlers::mmp=debug,"
                   "fips_core::node::handlers::rekey=debug,"
                   "fips_core::node::retry=debug,fips_core::node::lifecycle=info")


def destination(source):
    return "n03" if source == "n01" else "n01"


def distinct_shape(shape, count, identifiers):
    identifier = shape["stream_id"]
    require(set(shape) == {"stream_id", "packet_count", "payload_bytes"}
            and type(shape["packet_count"]) is int and shape["packet_count"] == count
            and type(shape["payload_bytes"]) is int and shape["payload_bytes"] == 1000
            and isinstance(identifier, str) and len(identifier) == 32
            and all(char in "0123456789abcdef" for char in identifier) and identifier not in identifiers,
            f"renewal requires distinct exact {count}-packet, 1000-byte streams")
    identifiers.add(identifier)


def successor_chain(rows, count):
    remaining = {row["previous"]: row for row in rows}
    roots = set(remaining) - {row["replacement"] for row in rows}
    require(len(rows) == len(remaining) == count and len(roots) == 1,
            "renewal requires one complete successor chain")
    current, ordered = roots.pop(), []
    while current in remaining:
        row = remaining.pop(current)
        ordered.append(row)
        current = row["replacement"]
    require(not remaining and current not in {row["previous"] for row in ordered},
            "renewal successor chain contains a branch or cycle")
    return ordered


def validate_window(evidence, identities, ids):
    """Verify each original stream before using its live payment observations."""
    streams, samples = evidence["streams"], evidence["samples"]
    require(set(streams) == set(ENDPOINTS) and samples, "renewal run lacks both streams and observations")
    every = evidence.get("frame_loss_every")
    require(every is None or type(every) is int and every == EVERY, "unexpected frame-loss policy")
    impaired = every is not None
    if impaired:
        require(set(evidence.get("loss_removed", {})) == set(ENDPOINTS)
                and set(evidence.get("recovery_streams", {})) == set(ENDPOINTS),
                "impaired renewal lacks filter removal or recovery streams")
    live = {}
    for source in ENDPOINTS:
        row = streams[source]
        shape = row["shape"]
        distinct_shape(shape, PACKETS, ids)
        submitted(row["sender"], shape)
        delivered = received(row["receiver"], shape, identities[source], complete=not impaired)
        require((row.get("frame_loss") is not None) == impaired, "stream frame-loss policy differs")
        if impaired:
            fault = row["frame_loss"]
            validate_delivery(fault, delivered, PACKETS)
            previous = fault["before"]
        for sample in samples:
            received(sample["receivers"][source], shape, identities[source])
            if impaired:
                current = sample["frame_loss"][destination(source)]
                loss_delta(previous, current)
                previous = current
        if impaired:
            loss_delta(previous, fault["after"])
            removal = evidence["loss_removed"][destination(source)]
            loss_delta(fault["after"], removal["before"])
            require(removal["after"]["enabled"] is False, "frame loss remained during recovery")
            recovery = evidence["recovery_streams"][source]
            distinct_shape(recovery["shape"], RECOVERY_PACKETS, ids)
            submitted(recovery["sender"], recovery["shape"])
            received(recovery["receiver"], recovery["shape"], identities[source], complete=True)
        require(row["sender"]["elapsed_us"] >= (PACKETS - 1) * 1_000_000 // RATE,
                "renewal send finished before the continuous paced window")
        live[source] = [sample for sample in samples if row["dispatch_started"] <= sample["ended_at"]
                < row["dispatch_started"] + (PACKETS - 1) / RATE]
    return live


def validate(evidence, identities):
    """Require every successor to deliver and receive credit during offered load."""
    count = evidence.get('window_count', 1)
    require(type(count) is int and count in (1, 2), 'unexpected traffic window count')
    windows = evidence.get('windows', [evidence])
    require(len(windows) == count, 'missing sustained traffic window')
    expected = evidence.get('expected_renewals', 1)
    require(type(expected) is int and expected in EXPIRY_QUOTES
            and (expected == 1 or evidence.get('expiry_renewal', False)),
            'unexpected renewal count or mode')
    impaired = evidence.get('frame_loss_every') is not None
    require(count == 1 or expected == 3 and evidence.get('expiry_renewal') and not impaired,
            'two windows require three expiry renewals without frame loss')
    budget = evidence.get('buyer_budget_sat', 64)
    require(type(budget) is int and budget == 64 * count, 'unexpected lifetime budget')
    ids, live = set(), {source: [] for source in ENDPOINTS}
    for index, window in enumerate(windows):
        require(window.get('frame_loss_every') == evidence.get('frame_loss_every'),
                'window frame-loss policy changed')
        observed = validate_window(window, identities, ids)
        for source in ENDPOINTS:
            live[source].extend(observed[source])
            if count > 1:
                row = window['streams'][source]
                require((PACKETS - 1) / RATE <= row['dispatch_finished'] - row['dispatch_started'] <= SEND_TIMEOUT,
                        'traffic window did not span its declared paced send')
            if index:
                gap = window['streams'][source]['dispatch_started'] - windows[index - 1]['streams'][source]['dispatch_finished']
                require(0 <= gap <= 30, 'traffic windows overlap or pause for more than 30 seconds')
        for name in NAMES:
            require_same_process(windows[0]['before'][name], window['before'][name])
            require_same_process(window['before'][name], window['after'][name])
    for source in ENDPOINTS:
        chain = successor_chain(evidence["accounts_after"]["renewals"][source], expected)
        for lineage in chain:
            replacement = lineage["replacement"]
            paid, observed = [], []
            for sample in live[source]:
                rows = sample["accounts"]["renewals"][source]
                matching = [r for r in rows if r["previous"] == lineage["previous"]
                            and r["replacement"] == replacement]
                if len(matching) == 1 and not any(r["previous"] == replacement for r in rows):
                    paid.append(sample)
                    observed.extend(matching)
            require(len(paid) >= 2, "no paid successor observations during the continuous stream")
            if evidence.get("expiry_renewal", False):
                fields = ("previous_expires_unix", "replacement_created_unix",
                          "previous_paid_sat", "previous_observed_units")
                expiry, created = lineage[fields[0]], lineage[fields[1]]
                require(evidence["renewal"] == EXPIRY_RENEWAL
                        and evidence["quote_lifetime_secs"] == EXPIRY_QUOTES[expected] * count
                        and expiry - EXPIRY_RENEWAL["before_expiry_secs"] <= created < expiry
                        and lineage["previous_paid_sat"] < 32
                        and lineage["previous_observed_units"] < QUOTE_UNITS
                        and all(row[field] == lineage[field] for row in observed for field in fields),
                        "expiry renewal must precede expiry without exhausting capacity or byte allowance")
            require(any(
                second['receivers'][source]['stream_id'] == first['receivers'][source]['stream_id']
                and second['receivers'][source]['unique_packets'] > first['receivers'][source]['unique_packets']
                and second['accounts']['financial']['n02']['credited'].get(replacement, 0)
                    > first['accounts']['financial']['n02']['credited'].get(replacement, 0)
                and (not impaired or loss_delta(first['frame_loss'][destination(source)],
                                               second['frame_loss'][destination(source)]) > 0)
                for first, second in zip(paid, paid[1:])),
                'fresh delivery and automatic successor credit did not advance')
        final = evidence["accounts_after"]["financial"][source]
        require(len(final["funding"]) == expected + 1
                and all(0 < final["signed"][row["replacement"]] <= 32 for row in chain)
                and final["authorized"] <= budget,
                "expected real replacements within unchanged lifetime authority")


class RenewalLoadRun(PaidWifiRun):
    stream = stream

    def __init__(self, args):
        super().__init__(args)
        self.loss_filters = {}
        self.evidence["renewal_load"] = {"passed": False, "samples": [], "streams": {},
            "sample_errors": [], "packets_per_direction": PACKETS,
            "window_count": self.window_count, "buyer_budget_sat": self.buyer_budget, "packets_per_second": RATE,
            "payload_bytes": 1000, "send_seconds": SEND_SECONDS, "receive_seconds": RECEIVE_SECONDS,
            "quote_max_units": QUOTE_UNITS, "renewal": dict(self.renewal_policy),
            "expiry_renewal": bool(getattr(args, "expiry_renewal", False)),
            "expected_renewals": self.expected_renewals, "quote_lifetime_secs": self.quote_lifetime,
            "frame_loss_every": EVERY if getattr(args, "frame_loss", False) else None,
            "final_tail_seconds": FINAL_TAIL,
            "diagnostic_log_filter": LINK_LOG_FILTER,
            "neighbor_observation_clock": "host_monotonic_seconds",
            "neighbor_observations": [], "neighbor_observations_truncated": False,
            "one_way_latency": False, "physical_power_loss": False, "cadence_comparison": False}
        for node in self.nodes.values():
            node.diagnostic_log_filter = LINK_LOG_FILTER
        for name in ("wifi_renewal_load.py", "wifi_renewal_finances.py", "wifi_frame_loss.py", "wifi_probes.py",
                     "wifi_profiles.py", "paid_settlement.py", "paid_finances.py", "wifi_measurements.py"):
            self.evidence["harness_sha256"][name] = digest(Path(__file__).with_name(name).read_bytes())

    def ctl(self, node, kind, **fields):
        if kind != "status":
            return super().ctl(node, kind, **fields)
        started = time.monotonic()
        result = super().ctl(node, kind, **fields)
        finished = time.monotonic()
        evidence = self.evidence["renewal_load"]
        rows = evidence.setdefault("neighbor_observations", [])
        if len(rows) >= MAX_NEIGHBOR_OBSERVATIONS:
            # Diagnostic capacity must never prevent financial cleanup.
            evidence["neighbor_observations_truncated"] = True
            return result
        known = {peer.npub: name for name, peer in self.nodes.items() if peer.npub}
        peers = result.get("peers", [])
        reason = result.get("last_error")
        error = ("provider_unavailable" if isinstance(reason, str)
                 and "provider is not a connected native neighbor" in reason
                 else "other" if reason else None)
        # Keep only fixture identities and scalar link diagnostics. Backend error
        # text and the rest of status may contain private wallet material.
        rows.append({"node": node, "started_at": started, "ended_at": finished,
            "process_id": (result.get("measurements") or {}).get("process_id"),
            "error": error,
            "peers": [{"node": known[peer["npub"]], **{key: peer.get(key) for key in (
                "connected", "link_id", "transport", "sent_packets", "received_packets", "srtt_ms")}}
                for peer in peers if peer.get("npub") in known],
            "unrecognized_peers": sum(peer.get("npub") not in known for peer in peers)})
        return result

    @property
    def window_count(self):
        count = getattr(self.args, 'windows', 1)
        require(type(count) is int and count in (1, 2), 'unexpected traffic window count')
        require(count == 1 or getattr(self.args, 'expiry_renewal', 0) == 3
                and not getattr(self.args, 'frame_loss', False),
                'two windows require three expiry renewals without frame loss')
        return count

    @property
    def buyer_budget(self):
        return 64 * self.window_count

    @property
    def renewal_policy(self):
        return EXPIRY_RENEWAL if getattr(self.args, "expiry_renewal", False) else RENEWAL

    @property
    def expected_renewals(self):
        value = getattr(self.args, "expiry_renewal", False)
        require(type(value) in (bool, int) and value in (0, 1, 3), "unexpected expiry renewal mode")
        return int(value) or 1

    @property
    def quote_lifetime(self):
        return EXPIRY_QUOTES[self.expected_renewals] * self.window_count if getattr(self.args, "expiry_renewal", False) else 1200

    def profile_config(self, node):
        config = super().profile_config(node)
        config["terms"].update(fee_msat_per_kib=1, max_rate_msat_per_kib=1, quote_max_units=QUOTE_UNITS)
        if getattr(self.args, "expiry_renewal", False):
            config["terms"]["quote_lifetime_secs"] = self.quote_lifetime
        config["terms"]["controller"]["renewal"] = dict(self.renewal_policy)
        return config

    def samples(self):
        self.monitor.check()
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {name: pool.submit(snapshot, node, name, native_counters=True)
                       for name, node in self.nodes.items()}
            return {name: future.result() for name, future in futures.items()}

    def warmup(self):
        results = []
        for source in ENDPOINTS:
            for _ in range(6):
                probe = self.stream(1, 1, source=source, destination=destination(source))
                results.append({"source": source, **probe})
                if probe["receiver"]["unique_packets"] == 1:
                    break
            require(probe["receiver"]["unique_packets"] == 1, "renewal session warmup failed")
        self.evidence["renewal_load"]["warmup"] = results
        time.sleep(FINAL_TAIL)

    def clear_loss(self):
        if self.loss_filters:
            outcomes, errors = clear_filters(self.loss_filters)
            self.evidence["renewal_load"]["loss_removed"] = outcomes
            self.phase("test frame-loss removal checked", filters=outcomes)
            require(not errors, "frame-loss removal incomplete: " + ", ".join(errors))
            self.loss_filters.clear()

    def recover_delivery(self):
        evidence = self.evidence["renewal_load"]
        evidence["recovery_streams"] = {}
        for source in ENDPOINTS:
            row = self.stream(RECOVERY_PACKETS, RATE, source=source, destination=destination(source))
            row["shape"] = {"stream_id": row["sender"]["stream_id"],
                            "packet_count": RECOVERY_PACKETS, "payload_bytes": 1000}
            evidence["recovery_streams"][source] = row
            self.save()

    def continuous_streams(self, accounts):
        evidence = self.evidence["renewal_load"]
        evidence["before"] = self.samples()
        # An endpoint rejects ReceiveProbe while its sender owns the diagnostic
        # permit. Both receive states must exist before either send starts.
        for source in ENDPOINTS:
            shape = probes.arm(self, source, destination(source), PACKETS, 1000,
                               lifetime_secs=RECEIVE_SECONDS)
            evidence["streams"][source] = {"shape": shape}
            if self.loss_filters:
                evidence["streams"][source]["frame_loss"] = {
                    "before": evidence["loss_armed"][destination(source)]}
        self.save()

        def send(source):
            started = time.monotonic()
            sent = probes.send(self, source, destination(source), evidence["streams"][source]["shape"], RATE,
                               max_duration_secs=SEND_SECONDS, operation_timeout=SEND_TIMEOUT)
            return {"sender": sent, "dispatch_started": started, "dispatch_finished": time.monotonic()}

        failure, last_observed = None, time.monotonic()
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = {source: pool.submit(send, source) for source in ENDPOINTS}
            try:
                while not all(future.done() for future in futures.values()):
                    started = time.monotonic()
                    try:
                        observed, _ = accounts.observe()
                        receivers = {source: probes.receive(self, source, destination(source),
                            evidence["streams"][source]["shape"]) for source in ENDPOINTS}
                        loss = {name: fault.observe() for name, fault in self.loss_filters.items()}
                        last_observed = time.monotonic()
                        evidence["samples"].append({"started_at": started, "ended_at": last_observed,
                                                    "accounts": observed, "receivers": receivers,
                                                    "frame_loss": loss})
                    except FinancialObservationChanged as error:
                        evidence["sample_errors"].append({"at": started, "error": type(error).__name__,
                                                          "reason": str(error)[:240]})
                        require(time.monotonic() - last_observed < 30,
                                "renewal accounting remained unobservable for 30 seconds")
                    self.save()
                    if not all(future.done() for future in futures.values()):
                        time.sleep(max(0, SAMPLE_INTERVAL - (time.monotonic() - started)))
            except Exception as error:
                evidence["observation_failure"] = {"error": type(error).__name__, "reason": str(error)[:240]}
                failure = error
            finally:
                # A failed observation cannot replay, abandon or settle beneath
                # a sender. Drain both exact operations even if one failed.
                for source, future in futures.items():
                    try:
                        evidence["streams"][source].update(future.result(timeout=SEND_TIMEOUT))
                    except Exception as error:
                        evidence["streams"][source]["sender_error"] = type(error).__name__
                        failure = failure or error
                time.sleep(FINAL_TAIL)
                for source, row in evidence["streams"].items():
                    try:
                        # Save the raw result before any delivery validator can
                        # reject it. No later arrivals replace this fixed read.
                        row["receiver"] = self.ctl(destination(source), "status")["probe"]
                        if self.loss_filters:
                            row["frame_loss"]["after"] = self.loss_filters[destination(source)].observe()
                    except Exception as error:
                        row["receiver_error"] = type(error).__name__
                        failure = failure or error
                self.save()
        if failure is not None:
            raise failure
        evidence["after"] = self.samples()
        def credited():
            observed, fixture = accounts.observe()
            return (observed, fixture) if payments_credited(observed["financial"]) else None
        evidence["accounts_after"], _ = eventually("post-stream automatic renewal credit", credited, 30)
        self.save()

    def exercise(self):
        evidence = self.evidence["renewal_load"]
        self.form_line()
        initial = self.samples()
        identities = {}
        for name, node in self.nodes.items():
            native = initial[name]["native"]["status"]["data"]
            require(native["npub"] == node.npub, "renewal native identity differs from prepared profile")
            identities[name] = list(bytes.fromhex(native["node_addr"]))
        accounts = RenewalAccounts(self, identities, self.renewal_policy, self.expected_renewals,
                                   buyer_budget_sat=self.buyer_budget)
        try:
            for source in ENDPOINTS:
                self.ctl(source, "buy", destination=self.nodes[destination(source)].npub)
            evidence["funded"], _ = eventually("original funded renewal accounts", accounts.observe)
            require(all(len(evidence["funded"]["financial"][source]["funding"]) == 1 for source in ENDPOINTS),
                    "renewal run did not start with one channel per direction")
            self.warmup()
            if getattr(self.args, "frame_loss", False):
                self.loss_filters = {name: FrameLoss(self.nodes[name], self.nodes["n02"].mac)
                                     for name in ENDPOINTS}
                evidence["loss_armed"] = {name: fault.enable() for name, fault in self.loss_filters.items()}
                self.save()
            if self.window_count == 1:
                self.continuous_streams(accounts)
            else:
                evidence['windows'] = []
                for _ in range(self.window_count):
                    evidence.update(streams={}, samples=[])
                    self.continuous_streams(accounts)
                    evidence['windows'].append({key: evidence.pop(key)
                        for key in ('streams', 'samples', 'before', 'after')})
                    self.save()
            if self.loss_filters:
                self.clear_loss()
                self.recover_delivery()
            self.verify_shortcuts()
            validate(evidence, {name: node.npub for name, node in self.nodes.items()})
            evidence["traffic_accepted"] = True
            self.phase("continuous bidirectional traffic crossed automatic paid replacements")
        except Exception as error:
            evidence["acceptance_failure"] = type(error).__name__
            evidence["acceptance_failure_reason"] = str(error)[:240]
            self.save()
            raise
        finally:
            signal.alarm(0)
            try:
                self.clear_loss()
            finally:
                accounts.collect()
        evidence["passed"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("inventory", "binary", "mint-binary", "mint-host", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--mint-address", required=True)
    parser.add_argument("--expiry-renewal", nargs="?", type=int, choices=(1, 3), const=1, default=0,
                        help="require one expiry replacement (180-second quotes) or three (90-second quotes)")
    parser.add_argument("--frame-loss", action="store_true",
                        help="drop every twentieth test frame during both streams, then verify full recovery")
    parser.add_argument('--windows', type=int, choices=(1, 2), default=1,
                        help='two five-minute windows use 180-second quotes and a fresh 128-sat signing limit; requires --expiry-renewal 3')
    args = parser.parse_args()
    args.mint_ssh_forward = False
    os.umask(0o077)

    def deadline(_signum, _frame):
        raise TimeoutError("router renewal acceptance exceeded its bounded window")

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(900 + (args.windows - 1) * SEND_SECONDS)
    RenewalLoadRun(args).execute()


if __name__ == "__main__":
    main()
