"""Exact identities and transports for two physical wireless relay choices."""

import ipaddress

from .paid_settlement import require


PRIVATE_NETWORKS = tuple(map(ipaddress.ip_network, ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")))


def management_address(output, interface):
    """Accept one observed RFC1918 address, never a guessed host or wildcard."""
    lines = output.decode().strip().splitlines()
    require(len(lines) == 1, "management interface needs one unambiguous IPv4 address")
    fields = lines[0].split()
    require(len(fields) >= 6 and fields[1] == interface and fields[2] == "inet",
            "unexpected management address record")
    assigned = ipaddress.IPv4Interface(fields[3])
    tail = fields[4:]
    if tail[0] == "brd":
        require(ipaddress.IPv4Address(tail[1]) == assigned.network.broadcast_address,
                "unexpected management broadcast address")
        tail = tail[2:]
    require(tail[:2] == ["scope", "global"], "unexpected management address scope")
    address = assigned.ip
    require(any(address in network for network in PRIVATE_NETWORKS),
            "test UDP listener requires an existing private LAN address")
    return str(address)


def listener(value, address):
    require(isinstance(value, str), "missing UDP listener")
    host, separator, port = value.rpartition(":")
    require(separator and host == address and port.isascii() and port.isdecimal()
            and 1 <= int(port) <= 65535, "UDP listener escaped its observed management address")
    return value


def adjacency(states, identities, addresses, *, source=True, radio_down=None):
    expected = {
        "n01": {"n03": "ethernet"}, "n02": {"n03": "ethernet"},
        "n03": {"n01": "ethernet", "n02": "ethernet"},
    }
    if source:
        expected["source"] = {"n01": "udp", "n02": "udp"}
        for name in ("n01", "n02"):
            expected[name]["source"] = "udp"
    require(radio_down in (None, "n01", "n02"), "invalid provider outage")
    if radio_down:
        del expected[radio_down]["n03"]
        del expected["n03"][radio_down]
    require(set(states) == set(identities) == set(expected)
            and len(set(identities.values())) == len(expected), "diamond identity set changed")
    for name, neighbors in expected.items():
        state = states[name]
        require(state["npub"] == identities[name], "diamond identity changed")
        peers = state["peers"]
        wanted = {identities[key]: (key, transport) for key, transport in neighbors.items()}
        require(len(peers) == len(wanted) and {peer["npub"] for peer in peers} == set(wanted),
                "diamond has an unexpected, duplicate or stale peer")
        for peer in peers:
            other, transport = wanted[peer["npub"]]
            require(peer["connected"] is True and peer["transport"] == transport,
                    "diamond adjacency is disconnected or uses the wrong transport")
            if transport == "udp":
                require(peer["address"] == addresses[other], "UDP peer differs from its owned listener")
    return states


def counter(value):
    require(type(value) is int and value >= 0, "invalid unsigned diamond counter")
    return value


def require_same_process(before, after):
    def identity(state):
        process = state["host_process"]
        return (state["npub"], process["host"], counter(process["pid"]), counter(process["start_ticks"]))
    require(identity(before) == identity(after), "diamond process changed during observation")


def session_counters(report, destination, *, absent=False):
    require(report["status"] == "ok", "native session observation failed")
    sessions = [row for row in report["data"]["sessions"] if row["npub"] == destination]
    if not sessions and absent:
        return 0, 0
    require(len(sessions) == 1 and sessions[0]["state"] == "established",
            "unpaid probe has no unique established destination session")
    stats = sessions[0]["stats"]
    return counter(stats["packets_sent"]), counter(stats["bytes_sent"])


def denied_stream(before, after, destination, packets, payload_bytes):
    """Require native data attempts and real policy drops, not just an empty queue."""
    drops = {}
    for name in ("n01", "n02", "source"):
        require_same_process(before[name], after[name])
        if name == "source":
            continue
        first = before[name]["native"]["routing"]["data"]["forwarding"]
        last = after[name]["native"]["routing"]["data"]["forwarding"]
        drops[name] = {}
        for suffix in ("packets", "bytes"):
            key = "drop_policy_denied_" + suffix
            delta = counter(last[key]) - counter(first[key])
            require(delta >= 0, "provider policy-denial counter decreased")
            drops[name][suffix] = delta
    first = session_counters(before["sessions"], destination, absent=True)
    last = session_counters(after["sessions"], destination)
    sent = {"packets": last[0] - first[0], "bytes": last[1] - first[1]}
    require(sent["packets"] >= packets and sent["bytes"] >= packets * payload_bytes,
            "zero reception lacks actual native application-data attempts")
    require(sum(value["packets"] for value in drops.values()) >= packets
            and sum(value["bytes"] for value in drops.values()) >= packets * payload_bytes,
            "zero reception lacks provider policy-denial evidence")
    return {"source_application_data": sent, "provider_policy_denials": drops,
            "attribution": "bounded phase aggregates, not matched packet receipts"}
