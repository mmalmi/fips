"""Interrupt an active paid stream, retaining identities and original channels."""

import re
import time

from . import wifi_probes as probes
from .paid_relay import eventually
from .paid_settlement import require
from .wifi_measurements import snapshot, unsigned
from .wifi_priority_checks import round_trip_latency, submitted
from .wifi_recovery_timing import RecoveryTiming, stations


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


def peer_sessions(run):
    """Observe the same authenticated link and Noise session on each side of the cut."""
    result = {}
    for name, node in run.nodes.items():
        run.monitor.check()
        run.check_forwards()
        reply = node.native({"command": "show_peers"})
        require(reply.get("status") == "ok", "native peer session observation failed")
        peers = reply["data"]["peers"]
        wanted = {other.npub for key, other in run.nodes.items()
                  if abs(int(key[-1]) - int(name[-1])) == 1}
        require(len(peers) == len(wanted) and {peer["npub"] for peer in peers} == wanted,
                "peer sessions no longer describe the original two-hop line")
        observed = {}
        for peer in peers:
            require(peer["connectivity"] == "connected" and peer["transport_type"] == "ethernet",
                    "peer session is not connected over Ethernet")
            index = peer.get("our_session_index")
            require(isinstance(index, str) and re.fullmatch(r"[0-9a-f]{8}", index) is not None,
                    "missing native peer session index")
            observed[peer["npub"]] = {"link_id": unsigned(peer["link_id"]),
                                       "authenticated_at_ms": unsigned(peer["authenticated_at_ms"]),
                                       "our_session_index": index}
        result[name] = observed
    return result


def active_radio_outage(run, *, outage_node="n03"):
    require(outage_node in ("n02", "n03"), "unsupported active outage node")
    brief = getattr(getattr(run, "args", None), "brief_outage", False) is True
    evidence = {"passed": False, "outage_node": outage_node, "brief_outage": brief,
                "processes_before": processes(run)}
    run.evidence["active_outage"] = evidence
    if brief:
        evidence["peer_sessions_before"] = peer_sessions(run)
    timing = (RecoveryTiming(run, evidence, outage_node)
              if getattr(getattr(run, "args", None), "recovery_timing", False) is True else None)
    if timing:
        timing.anchor("before_cut")
    ready = timing.ready if timing else lambda _phase, **kwargs: run.ready(**kwargs)
    shape = probes.arm(run, "n01", "n03", 24, 128, round_trip=True)
    evidence["shape"] = shape
    radio = run.nodes[outage_node]
    try:
        probes.send_with_radio_cut(run, "n01", "n03", shape, 2, radio, evidence, round_trip=True)
        run.phase("radio left during partially delivered paid round trips")
        if not brief:
            evidence["isolated_peers"] = eventually(
                "active radio departure establishes the partition", lambda: ready(
                    "partition", line=True, isolated=True, outage_node=outage_node), 100)
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
        if brief:
            evidence["radio_stations_during_outage"] = stations(radio)
            require(not evidence["radio_stations_during_outage"].strip(),
                    "brief interruption still has radio stations")
            # Do not wait for removed peers to return: the live roster must survive the cut.
            evidence["retained_peers"] = ready("retained_before_rejoin", line=True)
            require(bool(evidence["retained_peers"]), "brief interruption no longer retained every peer")
            run.phase("paid replies stopped before peer eviction; original channels retained")
        else:
            run.phase("paid replies stopped during peer eviction; original channels retained")
    finally:
        if evidence.get("cut_attempted", False):
            evidence["rejoin_started"] = time.monotonic()
            run.save()
            radio.mesh_up()
            evidence["rejoin_completed"] = time.monotonic()
            evidence["rejoined_peers"] = eventually(
                "same paid processes rejoin automatically", lambda: ready("rejoin", line=True), 150)
            evidence["rejoin_observed"] = time.monotonic()
            evidence["profile_check_started"] = time.monotonic()
            run.verify_open_profiles()
            evidence["profile_check_completed"] = time.monotonic()
        run.save()

    evidence["process_check_started"] = time.monotonic()
    evidence["processes_after"] = processes(run)
    evidence["process_check_completed"] = time.monotonic()
    require(evidence["processes_before"] == evidence["processes_after"],
            "radio recovery restarted a relay or replaced its identity")
    evidence["recovery_arm_started"] = time.monotonic()
    recovery = probes.arm(run, "n01", "n03", 8, 128, round_trip=True)
    evidence["recovery_arm_completed"] = time.monotonic()
    require(recovery["stream_id"] != shape["stream_id"], "recovery reused the interrupted stream")
    evidence["recovery_shape"] = recovery
    evidence["recovery_send_started"] = time.monotonic()
    evidence["recovery_sender"] = probes.send(run, "n01", "n03", recovery, 4, round_trip=True)
    evidence["recovery_send_completed"] = time.monotonic()
    submitted(evidence["recovery_sender"], recovery)

    def recovered():
        report = probes.receive(run, "n01", "n03", recovery, round_trip=True)
        return report if report["unique_packets"] == recovery["packet_count"] else None

    evidence["recovery_receiver"] = eventually("fresh paid replies after radio rejoin", recovered, 30)
    evidence["recovery_observed"] = time.monotonic()
    evidence["recovery_upper_bound_seconds"] = evidence["recovery_observed"] - evidence["rejoin_started"]
    evidence["recovery_latency"] = round_trip_latency(evidence["recovery_receiver"])
    if timing:
        timing.anchor("after_recovery")
    if brief:
        evidence["peer_sessions_after"] = peer_sessions(run)
        require(evidence["peer_sessions_after"] == evidence["peer_sessions_before"],
                "brief recovery replaced the original peer sessions")
    evidence["passed"] = True
    run.phase("same processes deliver fresh paid round trips after automatic radio rejoin")
