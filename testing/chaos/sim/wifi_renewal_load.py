"""Five minutes of simultaneous paid traffic through automatic channel renewal.

Fresh capped test accounts, one middle relay and the saved guarded radio mesh.
Finite sends are never replayed; a lost packet remains an acceptance failure.
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
from .wifi_measurements import snapshot
from .wifi_priority_checks import received, submitted
from .wifi_remote import digest
from .wifi_renewal_finances import ENDPOINTS, NAMES, QUOTE_UNITS, RENEWAL, RenewalAccounts


PACKETS, RATE, SEND_SECONDS, RECEIVE_SECONDS = 42_000, 140, 300, 360
SEND_TIMEOUT, SAMPLE_INTERVAL, FINAL_TAIL = 330, 10, 3


def destination(source):
    return "n03" if source == "n01" else "n01"


def validate(evidence, identities):
    """Require paid successor delivery while both one-shot streams are active."""
    streams, samples = evidence["streams"], evidence["samples"]
    require(set(streams) == set(ENDPOINTS) and samples, "renewal run lacks both streams and observations")
    ids = set()
    for source in ENDPOINTS:
        row = streams[source]
        shape = row["shape"]
        identifier = shape["stream_id"]
        require(set(shape) == {"stream_id", "packet_count", "payload_bytes"}
                and type(shape["packet_count"]) is int and shape["packet_count"] == PACKETS
                and type(shape["payload_bytes"]) is int and shape["payload_bytes"] == 1000
                and isinstance(identifier, str) and len(identifier) == 32
                and all(char in "0123456789abcdef" for char in identifier) and identifier not in ids,
                "renewal requires distinct exact 42000-packet, 1000-byte streams")
        ids.add(identifier)
        submitted(row["sender"], shape)
        received(row["receiver"], shape, identities[source], complete=True)
        for sample in samples:
            received(sample["receivers"][source], shape, identities[source])
        require(row["sender"]["elapsed_us"] >= (PACKETS - 1) * 1_000_000 // RATE,
                "renewal send finished before the continuous paced window")
        live = [sample for sample in samples if sample["ended_at"]
                < row["dispatch_started"] + (PACKETS - 1) / RATE]
        paid = [sample for sample in live if len(sample["accounts"]["renewals"][source]) == 1]
        require(len(paid) >= 2, "no paid successor observations during the continuous stream")
        first = paid[0]
        lineage = first["accounts"]["renewals"][source][0]
        replacement = lineage["replacement"]
        first_count = first["receivers"][source]["unique_packets"]
        first_credit = first["accounts"]["financial"]["n02"]["credited"].get(replacement, 0)
        require(any(sample["receivers"][source]["unique_packets"] > first_count
                    and sample["accounts"]["financial"]["n02"]["credited"].get(replacement, 0) > first_credit
                    and sample["accounts"]["renewals"][source][0]["replacement"] == replacement
                    for sample in paid[1:]), "fresh delivery and automatic successor credit did not advance")
        final = evidence["accounts_after"]["financial"][source]
        require(len(final["funding"]) == 2 and len(evidence["accounts_after"]["renewals"][source]) == 1
                and 0 < final["signed"][replacement] <= 32 and final["authorized"] <= 64,
                "expected one real replacement within unchanged lifetime authority")
    for name in NAMES:
        require_same_process(evidence["before"][name], evidence["after"][name])


class RenewalLoadRun(PaidWifiRun):
    stream = stream

    def __init__(self, args):
        super().__init__(args)
        self.evidence["renewal_load"] = {"passed": False, "samples": [], "streams": {},
            "sample_errors": [], "packets_per_direction": PACKETS, "packets_per_second": RATE,
            "payload_bytes": 1000, "send_seconds": SEND_SECONDS, "receive_seconds": RECEIVE_SECONDS,
            "quote_max_units": QUOTE_UNITS, "renewal": RENEWAL, "final_tail_seconds": FINAL_TAIL,
            "one_way_latency": False, "physical_power_loss": False, "cadence_comparison": False}
        for name in ("wifi_renewal_load.py", "wifi_renewal_finances.py", "wifi_probes.py",
                     "wifi_profiles.py", "paid_settlement.py", "paid_finances.py", "wifi_measurements.py"):
            self.evidence["harness_sha256"][name] = digest(Path(__file__).with_name(name).read_bytes())

    def profile_config(self, node):
        config = super().profile_config(node)
        config["terms"].update(fee_msat_per_kib=1, max_rate_msat_per_kib=1, quote_max_units=QUOTE_UNITS)
        config["terms"]["controller"]["renewal"] = dict(RENEWAL)
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

    def continuous_streams(self, accounts):
        evidence = self.evidence["renewal_load"]
        evidence["before"] = self.samples()
        # An endpoint rejects ReceiveProbe while its sender owns the diagnostic
        # permit. Both receive states must exist before either send starts.
        for source in ENDPOINTS:
            shape = probes.arm(self, source, destination(source), PACKETS, 1000,
                               lifetime_secs=RECEIVE_SECONDS)
            evidence["streams"][source] = {"shape": shape}
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
                        last_observed = time.monotonic()
                        evidence["samples"].append({"started_at": started, "ended_at": last_observed,
                                                    "accounts": observed, "receivers": receivers})
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
        validate(evidence, {name: node.npub for name, node in self.nodes.items()})

    def exercise(self):
        evidence = self.evidence["renewal_load"]
        self.form_line()
        initial = self.samples()
        identities = {}
        for name, node in self.nodes.items():
            native = initial[name]["native"]["status"]["data"]
            require(native["npub"] == node.npub, "renewal native identity differs from prepared profile")
            identities[name] = list(bytes.fromhex(native["node_addr"]))
        accounts = RenewalAccounts(self, identities)
        try:
            for source in ENDPOINTS:
                self.ctl(source, "buy", destination=self.nodes[destination(source)].npub)
            evidence["funded"], _ = eventually("original funded renewal accounts", accounts.observe)
            require(all(len(evidence["funded"]["financial"][source]["funding"]) == 1 for source in ENDPOINTS),
                    "renewal run did not start with one channel per direction")
            self.warmup()
            self.continuous_streams(accounts)
            self.verify_shortcuts()
            evidence["traffic_accepted"] = True
            self.phase("continuous bidirectional traffic crossed automatic paid replacements")
        except Exception as error:
            evidence["acceptance_failure"] = type(error).__name__
            evidence["acceptance_failure_reason"] = str(error)[:240]
            self.save()
            raise
        finally:
            signal.alarm(0)
            accounts.collect()
        evidence["passed"] = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("inventory", "binary", "mint-binary", "mint-host", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--mint-address", required=True)
    args = parser.parse_args()
    args.mint_ssh_forward = False
    os.umask(0o077)

    def deadline(_signum, _frame):
        raise TimeoutError("router renewal acceptance exceeded its bounded window")

    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(900)
    RenewalLoadRun(args).execute()


if __name__ == "__main__":
    main()
