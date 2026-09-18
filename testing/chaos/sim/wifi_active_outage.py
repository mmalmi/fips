"""Interrupt an active paid stream, retaining identities and original channels."""

import time

from . import wifi_probes as probes
from .paid_relay import eventually
from .paid_settlement import require
from .wifi_measurements import snapshot
from .wifi_priority_checks import round_trip_latency, submitted


def processes(run):
    result = {}
    for name, node in run.nodes.items():
        run.monitor.check()
        run.check_forwards()
        state = snapshot(node, name)
        identity = state["host_process"]
        result[name] = {"npub": state["npub"], "pid": identity["pid"],
                        "start_ticks": identity["start_ticks"]}
    return result


def active_radio_outage(run):
    evidence = {"passed": False, "processes_before": processes(run)}
    run.evidence["active_outage"] = evidence
    shape = probes.arm(run, "n01", "n03", 24, 128, round_trip=True)
    evidence["shape"] = shape
    leaf = run.nodes["n03"]
    try:
        probes.send_with_radio_cut(run, "n01", "n03", shape, 2, leaf, evidence, round_trip=True)
        run.phase("radio left during partially delivered paid round trips")
        evidence["isolated_peers"] = eventually(
            "active radio departure evicts the leaf", lambda: run.ready(line=True, isolated=True), 100)
        evidence["eviction_observed"] = time.monotonic()
        first = probes.receive(run, "n01", "n03", shape, round_trip=True)
        require(0 < evidence["before_cut"]["unique_packets"] <= first["unique_packets"]
                < shape["packet_count"], "active radio cut did not interrupt paid replies")
        time.sleep(2)
        last = probes.receive(run, "n01", "n03", shape, round_trip=True)
        require(last["unique_packets"] == first["unique_packets"],
                "isolated radio still delivered paid replies")
        evidence.update(outage_receiver=last, isolated_observation=first,
                        financial_during_outage=run.assert_finances())
        run.phase("paid replies stopped during peer eviction; original channels retained")
    finally:
        if evidence.get("cut_attempted", False):
            evidence["rejoin_started"] = time.monotonic()
            run.save()
            leaf.mesh_up()
            evidence["rejoin_completed"] = time.monotonic()
            evidence["rejoined_peers"] = eventually(
                "same paid processes rejoin automatically", lambda: run.ready(line=True), 150)
            evidence["rejoin_observed"] = time.monotonic()
            run.verify_open_profiles()
        run.save()

    evidence["processes_after"] = processes(run)
    require(evidence["processes_before"] == evidence["processes_after"],
            "radio recovery restarted a relay or replaced its identity")
    recovery = probes.arm(run, "n01", "n03", 8, 128, round_trip=True)
    require(recovery["stream_id"] != shape["stream_id"], "recovery reused the interrupted stream")
    evidence["recovery_shape"] = recovery
    evidence["recovery_sender"] = probes.send(run, "n01", "n03", recovery, 4, round_trip=True)
    submitted(evidence["recovery_sender"], recovery)

    def recovered():
        report = probes.receive(run, "n01", "n03", recovery, round_trip=True)
        return report if report["unique_packets"] == recovery["packet_count"] else None

    evidence["recovery_receiver"] = eventually("fresh paid replies after radio rejoin", recovered, 30)
    evidence["recovery_observed"] = time.monotonic()
    evidence["recovery_upper_bound_seconds"] = evidence["recovery_observed"] - evidence["rejoin_started"]
    evidence["recovery_latency"] = round_trip_latency(evidence["recovery_receiver"])
    evidence["passed"] = True
    run.phase("same processes deliver fresh paid round trips after automatic radio rejoin")
