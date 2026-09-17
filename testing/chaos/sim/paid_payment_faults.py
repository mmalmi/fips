"""Optional carrier interruption; opaque drops do not identify payment records."""

from __future__ import annotations

from contextlib import contextmanager
import signal
import time

from .netem_params import NetemParams
from .paid_faults import (PACKETS, PAYLOAD_BYTES, capture_probe, financial_sample,
                          original_quote, paid_progress, validate_impairment)

PAYMENT_PORT = 44743
FAULT_SECONDS = 8
FAULT_LIMIT = 12
STABLE_SECONDS = 1


def natural(value):
    if type(value) is not int or value < 0:
        raise RuntimeError("payment diagnostic requires nonnegative integer evidence")
    return value


def diagnostics(status, channel=None):
    """Keep only counters and public amounts; never persist request bodies."""
    try:
        measurement = status["measurements"]
        if not isinstance(measurement, dict) or measurement["version"] != 1:
            raise RuntimeError("payment faults require the measurements build feature")
        pid = natural(measurement["process_id"])
        if pid == 0:
            raise RuntimeError("payment diagnostic requires a process identity")
        control = [item["counters"] for item in status["control_traffic"]
                   if item["service_port"] == PAYMENT_PORT]
        if len(control) != 1:
            raise RuntimeError("payment diagnostic requires exactly one payment control port")
        counters = {key: natural(control[0][key]) for key in (
            "stream_bytes_sent", "stream_bytes_received", "requests_started", "requests_received")}
        operations = {name: {key: natural(value) for key, value in measurement["operations"][name].items()}
                      for name in ("payment_usage", "payment_update", "payment_sign")}
        for operation in operations.values():
            for key in ("spans", "journal_commits"):
                natural(operation[key])
        progress = status["payment_progress"]
        if not isinstance(progress, dict):
            raise RuntimeError("payment diagnostic requires channel progress")
        selected = None
        if channel is not None:
            if set(progress) != {channel}:
                raise RuntimeError("payment diagnostic changed its original buyer channel")
            item = progress[channel]
            selected = {key: natural(item[key]) for key in ("evidence_msat", "authorized_sat")}
            selected["acknowledged_msat"] = (None if item["acknowledged_msat"] is None
                                             else natural(item["acknowledged_msat"]))
            if type(item["in_flight"]) is not bool:
                raise RuntimeError("payment diagnostic has invalid scheduler state")
            selected["in_flight"] = item["in_flight"]
        return {"process_id": pid, "control": counters, "operations": operations, "progress": selected}
    except (KeyError, TypeError, AttributeError):
        raise RuntimeError("missing payment measurement or progress evidence") from None


def sample(run, source, channel):
    started = time.monotonic()
    buyer = diagnostics(run.ctl(source, "status"), channel)
    provider = diagnostics(run.ctl("n02", "status"))
    ledger = run.state_json("n02", "seller/ledger.json")["ledger"]
    matching = [entry["usage"] for entry in ledger["channels"] if entry["terms"]["id"] == channel]
    if len(matching) != 1:
        raise RuntimeError("payment diagnostic lost the original seller channel")
    usage = {key: natural(matching[0][key]) for key in
             ("paid_msat", "submitted_msat", "reserved_msat", "lost_msat")}
    return {"started": started, "finished": time.monotonic(), "buyer": buyer,
            "provider": provider, "seller_usage": usage}


def validate_samples(before, after):
    if not before["started"] <= before["finished"] <= after["started"] <= after["finished"]:
        raise RuntimeError("payment observations are not ordered")
    for side in ("buyer", "provider"):
        old, new = before[side], after[side]
        if old["process_id"] != new["process_id"]:
            raise RuntimeError("payment diagnostic process restarted")
        if any(new["control"][key] < value for key, value in old["control"].items()):
            raise RuntimeError("payment control counter decreased")
        for operation, counters in old["operations"].items():
            if any(new["operations"][operation].get(key, -1) < value for key, value in counters.items()):
                raise RuntimeError("payment operation counter decreased")
    for key in ("evidence_msat", "authorized_sat"):
        if after["buyer"]["progress"][key] < before["buyer"]["progress"][key]:
            raise RuntimeError("payment evidence or authorization decreased")
    if after["seller_usage"]["paid_msat"] < before["seller_usage"]["paid_msat"]:
        raise RuntimeError("seller credit decreased")


def unresolved(before, observation):
    validate_samples(before, observation)
    prior, current = before["buyer"]["progress"], observation["buyer"]["progress"]
    ack = current["acknowledged_msat"]
    return (current["in_flight"] and ack is not None and prior["acknowledged_msat"] is not None
            and ack >= prior["acknowledged_msat"]
            and current["evidence_msat"] >= prior["evidence_msat"] + PACKETS * PAYLOAD_BYTES
            and ack < current["evidence_msat"]
            and observation["buyer"]["control"]["requests_started"]
            > before["buyer"]["control"]["requests_started"])


def validate_interruption(phase):
    observations = phase["observations"]
    if (len(observations) < 2 or observations[-1]["started"] - observations[0]["finished"]
            < STABLE_SECONDS):
        raise RuntimeError("payment interruption requires separated unresolved observations")
    if not FAULT_SECONDS <= phase["observation_seconds"] < FAULT_LIMIT:
        raise RuntimeError("payment fault did not stay within its short observation bound")
    for observation in observations:
        if not unresolved(phase["before"], observation):
            raise RuntimeError("payment acknowledgment was not stably unresolved")
        if observation["buyer"]["progress"]["acknowledged_msat"] != observations[0]["buyer"]["progress"]["acknowledged_msat"]:
            raise RuntimeError("payment acknowledgment changed among the selected observations")
    for left, right in zip(observations, observations[1:]):
        validate_samples(left, right)
    if validate_impairment("loss", phase)["drops"] == 0:
        raise RuntimeError("payment carrier loss produced no observed drops")


def supported_target(observation):
    buyer, seller = observation["buyer"]["progress"], observation["seller_usage"]
    supported = min(buyer["evidence_msat"], seller["submitted_msat"])
    target = max(buyer["authorized_sat"], (supported + 999) // 1000) * 1000
    if target > 32_000:
        raise RuntimeError("payment recovery target exceeds the original channel")
    return target


def classify(before, after):
    return {
        "payment_requests_started_delta": after["buyer"]["control"]["requests_started"]
        - before["buyer"]["control"]["requests_started"],
        "provider_usage_spans_delta": after["provider"]["operations"]["payment_usage"]["spans"]
        - before["provider"]["operations"]["payment_usage"]["spans"],
        "provider_update_spans_delta": after["provider"]["operations"]["payment_update"]["spans"]
        - before["provider"]["operations"]["payment_update"]["spans"],
        "original_channel_credit_delta_msat": after["seller_usage"]["paid_msat"]
        - before["seller_usage"]["paid_msat"],
        "request_type": "opaque carrier loss cannot identify a Usage or Update request/reply",
        "handler_counters": "aggregate completed handlers include rejected requests and other channels",
        "scope": "repeated scheduler acknowledgment lag; not proof of an accepted Update with a lost reply",
    }


@contextmanager
def short_fault():
    """Interrupt stalled observation calls; retain the outer scenario deadline."""
    started = time.monotonic()
    prior_handler = signal.getsignal(signal.SIGALRM)
    prior_timer = signal.getitimer(signal.ITIMER_REAL)
    def deadline(_signum, _frame):
        raise TimeoutError("payment carrier observation exceeded its 12-second bound")
    signal.signal(signal.SIGALRM, deadline)
    signal.setitimer(signal.ITIMER_REAL, min(prior_timer[0], FAULT_LIMIT) if prior_timer[0] else FAULT_LIMIT)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, prior_handler)
        if prior_timer[0]:
            signal.setitimer(signal.ITIMER_REAL, max(0.001, prior_timer[0] - (time.monotonic() - started)),
                             prior_timer[1])


def ready(run, source, channel):
    observation = sample(run, source, channel)
    progress = observation["buyer"]["progress"]
    # No zero-debt requirement: establish a harvested prior acknowledgment only.
    return observation if not progress["in_flight"] and progress["acknowledged_msat"] is not None else None


def reconciled(run, prior_finances, source, channel, phase):
    finances = financial_sample(run, prior_finances, phase)
    observation = sample(run, source, channel)
    validate_samples(phase["before"], observation)
    phase["last_recovery_observation"] = observation
    progress = observation["buyer"]["progress"]
    target = phase["target_msat"]
    if (progress["acknowledged_msat"] is None or progress["acknowledged_msat"] < target
            or observation["seller_usage"]["paid_msat"] < target
            or progress["authorized_sat"] * 1000 < target
            or finances["n02"]["credited"].get(channel, -1) < target
            or finances[source]["signed"].get(channel, -1) * 1000 < target):
        return None
    return finances


def interrupt(run, previous, source, destination, wait):
    channels = previous[source]["signed"]
    if len(channels) != 1:
        raise RuntimeError("payment interruption requires one original buyer channel")
    channel = next(iter(channels))
    phase = {"payment_carrier_fault": f"{source}->{destination}", "channel": channel,
             "before": wait("harvested payment acknowledgment", lambda: ready(run, source, channel), 30),
             "financial_before": previous, "observations": [], "passed": False}
    run.evidence["phases"].append(phase)
    started = time.monotonic()
    try:
        with short_fault():
            phase["installed"] = run.veth.set_scoped_impairment("n02", source, NetemParams(loss_pct=100))
            phase["qdisc_before"] = run.veth.scoped_impairment_stats("n02", source)
            capture_probe(run, source, destination, wait, phase, rate=40)
            while time.monotonic() - started < FAULT_SECONDS or len(phase["observations"]) < 2:
                observation = sample(run, source, channel)
                phase["last_fault_observation"] = observation
                if unresolved(phase["before"], observation):
                    if (phase["observations"] and observation["buyer"]["progress"]["acknowledged_msat"]
                            != phase["observations"][0]["buyer"]["progress"]["acknowledged_msat"]):
                        raise RuntimeError("payment acknowledgment changed during the interruption")
                    phase["observations"].append(observation)
                elif phase["observations"]:
                    raise RuntimeError("payment acknowledgment changed during the interruption")
                time.sleep(0.25)
            phase["qdisc_after"] = run.veth.scoped_impairment_stats("n02", source)
            phase["observation_seconds"] = time.monotonic() - started
            validate_interruption(phase)
    finally:
        # Never let the observation alarm skip ownership-checked qdisc cleanup.
        # A setup/readback failure can have installed the recorded qdisc too.
        run.veth.clear_scoped_impairment("n02", source)
        phase["restored_after_seconds"] = time.monotonic() - started
    if phase["restored_after_seconds"] >= FAULT_LIMIT:
        raise RuntimeError("payment carrier restoration exceeded its short fault bound")
    last = phase["observations"][-1]
    phase["classification"] = classify(phase["before"], last)
    phase["target_msat"] = supported_target(last)
    if phase["target_msat"] <= last["buyer"]["progress"]["acknowledged_msat"]:
        raise RuntimeError("fresh paid burst did not create a new supported payment target")
    current = wait("automatic payment reconciliation", lambda: reconciled(
        run, previous, source, channel, phase), 90)
    quote = original_quote(previous, source)
    if any(current[node][key][quote] - previous[node][key][quote] < PACKETS * PAYLOAD_BYTES
           for node, key in ((source, "buyer_units"), ("n02", "seller_units"))):
        raise RuntimeError("payment fault burst lacks matching billable route evidence")
    phase.update(financial_after=current, passed=True)
    return current


def exercise_payment_faults(run, baseline, wait):
    previous = baseline
    for source, destination in (("n01", "n03"), ("n03", "n01")):
        previous = interrupt(run, previous, source, destination, wait)
        healthy = {"payment_carrier_recovery": f"{source}->{destination}", "passed": False}
        run.evidence["phases"].append(healthy)
        capture_probe(run, source, destination, wait, healthy, rate=40)
        current = wait("healthy paid burst after payment interruption", lambda: paid_progress(
            run, previous, source, healthy), 90)
        healthy.update(financial=current, passed=True)
        previous = current
    run.evidence["fault_scope"]["payment"] = (
        "short reverse carrier blackholes with delivered charged data and repeated unresolved "
        "scheduler acknowledgments; original channels reconcile automatically after restoration; "
        "carrier drops do not distinguish Usage from Update requests or replies")
    return previous
