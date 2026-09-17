"""Observe real data faults without interpreting submission as delivery."""

from __future__ import annotations

import secrets
import time


PACKETS = 8
PAYLOAD_BYTES = 256


def validate_probe(sent, received, *, loss=False, measure_latency=True):
    if (sent["requested_packets"] != PACKETS or sent["submitted_packets"] != PACKETS
            or sent["submitted_bytes"] != PACKETS * PAYLOAD_BYTES
            or sent["stopped_reason"] is not None):
        raise RuntimeError("paid probe was not fully submitted")
    if (received["stream_id"] != sent["stream_id"]
            or received["expected_packets"] != PACKETS
            or received["payload_bytes"] != PAYLOAD_BYTES
            or received["invalid_packets"] != 0 or received["duplicate_packets"] != 0
            or received["unique_bytes"] != received["unique_packets"] * PAYLOAD_BYTES
            or received["missing_packets"] + received["unique_packets"] != PACKETS):
        raise RuntimeError("invalid or duplicate paid probe data")
    expected = 0 if loss else PACKETS
    if received["unique_packets"] != expected:
        raise RuntimeError("paid probe delivery differs from the expected fault")
    latency = received["latency"]
    if not measure_latency:
        if latency is not None:
            raise RuntimeError("probe unexpectedly reports unrequested latency measurements")
        return
    if latency is None or latency["invalid_timestamps"] != 0 or latency["samples"] != expected:
        raise RuntimeError("paid probe latency evidence is incomplete")


def capture_probe(run, source, destination, wait, evidence, *, rate=4, loss=False, measure_latency=True):
    shape = {"stream_id": secrets.token_hex(16), "packet_count": PACKETS,
             "payload_bytes": PAYLOAD_BYTES}
    run.ctl(destination, "receive_probe", probe={
        **shape, "source": run.nodes[source].npub, "measure_one_way_latency": measure_latency,
    })
    # Loss is observed for the whole interval, not accepted from an initially
    # empty receive queue. This bound includes the paced send itself.
    until = time.monotonic() + 3
    sent = run.ctl(source, "send_probe", probe={
        **shape, "destination": run.nodes[destination].npub, "packets_per_second": rate,
    })["probe"]
    evidence["sent"] = sent
    if sent["stream_id"] != shape["stream_id"] or sent["submitted_packets"] != PACKETS:
        raise RuntimeError("paid probe did not submit its fresh stream")

    def sample():
        received = run.ctl(destination, "status")["probe"]
        evidence["received"] = received
        if received["source"] != run.nodes[source].npub or received["stream_id"] != shape["stream_id"]:
            raise RuntimeError("receiver did not observe the fresh source stream")
        if loss:
            validate_probe(sent, received, loss=True, measure_latency=measure_latency)
        return received if received["unique_packets"] == PACKETS else None

    if loss:
        while True:
            sample()
            if time.monotonic() >= until:
                break
            time.sleep(0.25)
    else:
        wait("paid probe delivery", sample, 30)
    validate_probe(sent, evidence["received"], loss=loss, measure_latency=measure_latency)


def qdisc_counters(snapshot):
    roots = [item for item in snapshot["qdiscs"]
             if item.get("kind") == "netem" and item.get("root") is True]
    if len(roots) != 1:
        raise RuntimeError("missing unique netem root evidence")
    # iproute2 emits these generic qdisc counters alongside kind/options.
    counters = {key: roots[0].get(key) for key in ("packets", "drops")}
    if any(type(value) is not int or value < 0 for value in counters.values()):
        raise RuntimeError("missing numeric netem counters")
    return counters


def validate_impairment(kind, evidence):
    before, after = evidence["qdisc_before"], evidence["qdisc_after"]
    for key in ("node", "peer", "container_id", "interface", "alias"):
        if before[key] != after[key]:
            raise RuntimeError("impairment observation changed its owned interface")
    initial, final = qdisc_counters(before), qdisc_counters(after)
    expected = {"gap": 2 if kind == "reorder" else 0}
    if kind in ("delay", "reorder"):
        expected["delay"] = {"delay": 0.08, "jitter": 0, "correlation": 0}
    if kind == "loss":
        expected["loss-random"] = {"loss": 1, "correlation": 0}
    if kind == "reorder":
        expected["reorder"] = {"reorder": 1, "correlation": 0}
    for snapshot in (before, after):
        options = snapshot["qdiscs"][0].get("options", {})
        actual = {key: value for key, value in options.items() if key not in ("limit", "seed", "ecn")}
        if actual != expected:
            raise RuntimeError("installed netem fault options differ from the requested phase")
    if any(final[key] < initial[key] for key in initial):
        raise RuntimeError("impairment counters reset during the probe")
    return {key: final[key] - initial[key] for key in initial}


def validate_effect(kind, evidence):
    delta = validate_impairment(kind, evidence)
    received = evidence["received"]
    validate_probe(evidence["sent"], received, loss=kind == "loss")
    if kind == "loss":
        if delta["drops"] < PACKETS:
            raise RuntimeError("packet loss did not reach the impaired carrier")
    elif delta["packets"] < PACKETS:
        raise RuntimeError("probe did not traverse the impaired carrier")
    if kind == "delay" and received["latency"]["min_us"] < 60_000:
        raise RuntimeError("configured delay was not observed by the receiver")
    if kind == "reorder" and received["out_of_order_packets"] == 0:
        raise RuntimeError("configured reordering was not observed by the receiver")


def validate_finances(before, after):
    signed = {key: value for state in after.values() for key, value in state["signed"].items()}
    credited = {key: value for state in after.values() for key, value in state["credited"].items()}
    if len(signed) != 2 or set(signed) != set(credited):
        raise RuntimeError("paid line must retain exactly two funded channels")
    for node, state in after.items():
        old = before[node]
        if any(state[key] != old[key] for key in ("funding", "budget", "wallet")):
            raise RuntimeError("data fault changed funding, capital or wallet custody")
        if set(state["signed"]) != set(old["signed"]):
            raise RuntimeError("data fault replaced a paid channel")
        if not 0 <= state["remaining"] <= old["remaining"] <= 64:
            raise RuntimeError("data fault reset the lifetime buyer budget")
        if (state["authorized"] != sum(state["signed"].values())
                or state["remaining"] + state["authorized"] != 64):
            raise RuntimeError("buyer liability differs from its signed channels")
        if set(state["signed_after"]) != set(state["signed"]):
            raise RuntimeError("authorization observation changed its channels")
        for channel, amount in state["signed"].items():
            if not old["signed"][channel] <= amount <= 32:
                raise RuntimeError("channel liability decreased or exceeded its capacity")
            if credited[channel] < old["signed"][channel] * 1000:
                raise RuntimeError("signed payment has not reconciled with relay credit")
            if (state["signed_after"][channel] < amount
                    or not credited[channel] <= state["signed_after"][channel] * 1000 <= 32_000):
                raise RuntimeError("relay credit exceeds later durable authorization")
        if set(state["seller_channels"]) != set(state["credited"]):
            raise RuntimeError("seller exposure changed its channels")
        for channel, usage in state["seller_channels"].items():
            # Ongoing mesh traffic may legitimately have unpaid usage. The
            # seller bounds it by grace and capacity in this same journal.
            if (usage["paid_msat"] != state["credited"][channel]
                    or not 0 <= usage["submitted_msat"] <= usage["reserved_msat"]
                    <= min(32_000, usage["paid_msat"] + 8000)
                    or usage["lost_msat"] != 0):
                raise RuntimeError("seller exposure exceeds the original allowance")
        for key in ("buyer_units", "seller_units"):
            if set(state[key]) != set(old[key]):
                raise RuntimeError("data fault replaced its original route agreement")
            for quote, units in state[key].items():
                if not old[key][quote] <= units <= 30_000:
                    raise RuntimeError("billable units decreased or exceeded the original quote")


def original_quote(before, source):
    quotes = before[source]["buyer_units"]
    if len(quotes) != 1 or not set(quotes) <= set(before["n02"]["seller_units"]):
        raise RuntimeError("observation requires the matching original route")
    return next(iter(quotes))


def financial_sample(run, before, evidence):
    evidence["financial_sample_attempts"] = evidence.get("financial_sample_attempts", 0) + 1
    evidence["financial_sample_started"] = time.monotonic()
    try:
        current = run.finances()
    except RuntimeError as error:
        race = "financial observation changed during sampling"
        evidence["last_financial_validation_error"] = race if str(error) == race else type(error).__name__
        raise
    finally:
        evidence["financial_sample_finished"] = time.monotonic()
    evidence["last_financial_observation"] = current
    try:
        validate_finances(before, current)
    except RuntimeError as error:
        # Validation messages are fixed local strings, with no request bodies.
        evidence["last_financial_validation_error"] = str(error)
        raise
    evidence.pop("last_financial_validation_error", None)
    return current


def paid_progress(run, before, source, evidence):
    current = financial_sample(run, before, evidence)
    quote = original_quote(before, source)
    if any(current[node][key][quote] - before[node][key][quote] < PACKETS * PAYLOAD_BYTES
           for node, key in ((source, "buyer_units"), ("n02", "seller_units"))):
        return None
    channels = {channel: usage for state in current.values()
                for channel, usage in state["seller_channels"].items()}
    if "payment_targets_sat" not in evidence:
        # At one msat per unit, these are the controller's supported claims.
        # Freeze the target: background FIPS traffic need not become idle.
        evidence["payment_targets_sat"] = {
            channel: max(signed, (min(sum(state["buyer_units"].values()),
                                     channels[channel]["submitted_msat"]) + 999) // 1000)
            for state in current.values() for channel, signed in state["signed"].items()}
    paid = all(channels[channel]["paid_msat"] >= target * 1000
               for channel, target in evidence["payment_targets_sat"].items())
    return current if paid and current[source]["authorized"] > before[source]["authorized"] else None


def in_fault_progress(run, before, source):
    current = run.finances()
    quote = original_quote(before, source)
    for node, key in ((source, "buyer_units"), ("n02", "seller_units")):
        if set(current[node][key]) != set(before[node][key]):
            raise RuntimeError("loss observation replaced its original route")
        if current[node][key][quote] - before[node][key][quote] < PAYLOAD_BYTES:
            return None
    return current


def sample_lost_stream(run, source, destination, phase):
    received = run.ctl(destination, "status")["probe"]
    if received["source"] != run.nodes[source].npub:
        raise RuntimeError("loss observation changed its original source")
    validate_probe(phase["sent"], received, loss=True)
    return received


def exercise_faults(run, baseline, wait):
    from .netem_params import NetemParams

    phases = (("delay", NetemParams(delay_ms=80)),
              ("loss", NetemParams(loss_pct=100)),
              ("reorder", NetemParams(delay_ms=80, reorder_pct=100, gap=2)))
    previous = baseline
    for source, destination in (("n01", "n03"), ("n03", "n01")):
        for kind, params in phases:
            phase = {"data_fault": kind, "source": source, "destination": destination,
                     "financial_before": previous, "passed": False}
            run.evidence["phases"].append(phase)
            phase["installed"] = run.veth.set_scoped_impairment("n02", destination, params)
            started = time.monotonic()
            try:
                phase["qdisc_before"] = run.veth.scoped_impairment_stats("n02", destination)
                capture_probe(run, source, destination, wait, phase,
                              rate=4 if kind == "loss" else 40, loss=kind == "loss")
                if kind == "loss":
                    phase["financial_during_fault"] = wait(
                        "accounted traffic on the impaired route",
                        lambda: in_fault_progress(run, previous, source), 15)
                    phase["received_before_clear"] = sample_lost_stream(run, source, destination, phase)
                phase["qdisc_after"] = run.veth.scoped_impairment_stats("n02", destination)
                validate_effect(kind, phase)
            finally:
                phase["active_observation_seconds"] = time.monotonic() - started
                run.veth.clear_scoped_impairment("n02", destination)
            current = wait("payments after data fault", lambda: paid_progress(run, previous, source, phase))
            if kind == "loss":
                phase["received_after_reconciliation"] = sample_lost_stream(run, source, destination, phase)
            # These are opaque-envelope forwarding attempts, not delivered
            # application bytes. Loss downstream must not erase their evidence.
            quote = original_quote(previous, source)
            for node, key in ((source, "buyer_units"), ("n02", "seller_units")):
                delta = current[node][key][quote] - previous[node][key][quote]
                phase[f"{key}_delta"] = delta
            phase.update(financial_after=current, passed=True)
            previous = current
        recovery = {"data_fault_recovery": f"{source}->{destination}"}
        run.evidence["phases"].append(recovery)
        capture_probe(run, source, destination, wait, recovery)
        current = wait("payments after healthy recovery", lambda: paid_progress(run, previous, source, recovery))
        recovery["financial"] = current
        previous = current
    run.evidence["fault_scope"] = {
        "data": "observed delay, loss and reordering on relay egress in both directions",
        "payment": "automatic reconciliation after data faults; interrupted payment replies not injected",
        "attribution": "route accounting and carrier drops are observed during loss; individual encrypted packets are not correlated",
    }
    return previous
