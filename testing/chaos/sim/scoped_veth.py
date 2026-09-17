"""Strict veth ownership for run-scoped acceptance tests."""

from __future__ import annotations

import json
import re

from .netem_params import NetemParams
from .run_scope import RUN_LABEL, docker, inspect_owned
from .topology import veth_interface_name


def host_names(run_name: str, a: str, b: str) -> tuple[str, str]:
    if not all(re.fullmatch(r"n[0-9]{2}", node) for node in (a, b)):
        raise ValueError("scoped veth nodes require n01..n99 names")
    prefix = f"v{run_name}{a[1:]}{b[1:]}"
    return prefix + "a", prefix + "b"


class ScopedVeth:
    def __init__(self, topology):
        self.topology = topology
        self.created: list[tuple[str, str]] = []
        self.image: str | None = None
        self.impairments: dict[tuple[str, str], dict] = {}

    def host(self, args: list[str], entrypoint="ip") -> str:
        return docker([
            "run", "--rm", "--pull=never", "--privileged", "--network=host",
            "--pid=host", "--label", f"{RUN_LABEL}={self.topology.run_name}",
            "--entrypoint", entrypoint, self.image, *args,
        ])

    def container(self, node: str) -> dict:
        item = inspect_owned("container", self.topology.container_name(node), self.topology.run_name)
        if not item["State"]["Running"] or item["State"]["Pid"] <= 0:
            raise RuntimeError("scoped veth requires a running owned container")
        return item

    def links(self, container: str | None = None) -> dict:
        output = (docker(["exec", container, "ip", "-j", "link", "show"])
                  if container else self.host(["-j", "link", "show"]))
        return {item["ifname"]: item for item in json.loads(output)}

    def owner(self, a: str, b: str) -> str:
        return f"fips-chaos:{self.topology.run_name}:{a}:{b}"

    def setup_all(self, image: str):
        self.image = image
        for a, b in self.topology.ethernet_edges():
            self.create(a, b)

    def create(self, a: str, b: str):
        left, right = self.container(a), self.container(b)
        host_a, host_b = host_names(self.topology.run_name, a, b)
        final_a, final_b = veth_interface_name(a, b), veth_interface_name(b, a)
        if any(name in self.links() for name in (host_a, host_b)):
            raise RuntimeError("refusing existing scoped host interface")
        for item, names in ((left, (host_a, final_a)), (right, (host_b, final_b))):
            existing = self.links(item["Id"])
            if any(name in existing for name in names):
                raise RuntimeError("refusing existing container interface")
        # Create inside an owned namespace so even an interruption before
        # aliases are assigned cannot leave an unlabelled pair on the host.
        # Some iproute2 versions silently ignore aliases in `link add`.
        owner = self.owner(a, b)
        self.created.append((a, b))
        docker(["exec", left["Id"], "ip", "link", "add", "name", host_a,
                "type", "veth", "peer", "name", host_b])
        for temporary in (host_a, host_b):
            docker(["exec", left["Id"], "ip", "link", "set", temporary, "alias", owner])
            if self.links(left["Id"]).get(temporary, {}).get("ifalias") != owner:
                raise RuntimeError("created interface did not retain its ownership alias")
        for node, expected in ((a, left), (b, right)):
            current = self.container(node)
            if current["Id"] != expected["Id"] or current["State"]["Pid"] != expected["State"]["Pid"]:
                raise RuntimeError("owned namespace changed during veth setup")
        self.host(["-t", str(left["State"]["Pid"]), "-n", "ip", "link", "set", host_b,
                   "netns", str(right["State"]["Pid"])], entrypoint="nsenter")
        for item, temporary, final in ((left, host_a, final_a), (right, host_b, final_b)):
            docker(["exec", item["Id"], "ip", "link", "set", temporary, "name", final])
            docker(["exec", item["Id"], "ip", "link", "set", final, "up"])
        for node, peer, item, final in ((a, b, left, final_a), (b, a, right, final_b)):
            link = self.links(item["Id"])[final]
            if link.get("ifalias") != owner:
                raise RuntimeError("moved interface did not retain its ownership alias")
            self.topology.nodes[node].ethernet_macs[peer] = link["address"]

    def endpoint(self, node: str, peer: str) -> tuple[str, str, str]:
        edge = next((pair for pair in self.created if pair in ((node, peer), (peer, node))), None)
        if edge is None:
            raise RuntimeError("cannot change an edge this run did not create")
        container = self.container(node)["Id"]
        name, owner = veth_interface_name(node, peer), self.owner(*edge)
        if self.links(container).get(name, {}).get("ifalias") != owner:
            raise RuntimeError("refusing an interface with changed ownership")
        return container, name, owner

    def set_edge(self, a: str, b: str, up: bool):
        endpoints = [self.endpoint(a, b), self.endpoint(b, a)]
        for container, name, _ in endpoints:
            docker(["exec", container, "ip", "link", "set", name, "up" if up else "down"])

    @staticmethod
    def qdiscs(container: str, name: str) -> list[dict]:
        result = json.loads(docker(["exec", container, "tc", "-j", "-s", "qdisc", "show", "dev", name]))
        if not isinstance(result, list) or not all(isinstance(item, dict) for item in result):
            raise RuntimeError("invalid tc qdisc statistics")
        return result

    @staticmethod
    def is_noqueue(qdiscs: list[dict]) -> bool:
        return (len(qdiscs) == 1 and qdiscs[0].get("kind") == "noqueue"
                and qdiscs[0].get("handle") == "0:" and qdiscs[0].get("root") is True)

    def set_impairment(self, node: str, peer: str, params: NetemParams) -> dict:
        args = params.to_tc_argv()
        container, name, owner = self.endpoint(node, peer)
        if (node, peer) in self.impairments or not self.is_noqueue(self.qdiscs(container, name)):
            raise RuntimeError("refusing to replace an existing qdisc")
        # Record before mutation so a failed readback never licenses replacement.
        self.impairments[node, peer] = {"node": node, "peer": peer, "container_id": container,
                                       "interface": name, "alias": owner, "requested": args}
        docker(["exec", container, "tc", "qdisc", "add", "dev", name, "root", "handle",
                "7a11:", "netem", *args])
        return self.impairment_stats(node, peer)

    def impairment_stats(self, node: str, peer: str) -> dict:
        record = self.impairments.get((node, peer))
        if record is None:
            raise RuntimeError("no recorded impairment for this direction")
        container, name, owner = self.endpoint(node, peer)
        if (container, name, owner) != (record["container_id"], record["interface"], record["alias"]):
            raise RuntimeError("impaired interface ownership changed")
        qdiscs = self.qdiscs(container, name)
        if (len(qdiscs) != 1 or qdiscs[0].get("kind") != "netem"
                or qdiscs[0].get("handle") != "7a11:" or qdiscs[0].get("root") is not True):
            raise RuntimeError("expected netem qdisc is absent or changed")
        return {**record, "qdiscs": qdiscs}

    def clear_impairment(self, node: str, peer: str):
        snapshot = self.impairment_stats(node, peer)
        container, name = snapshot["container_id"], snapshot["interface"]
        docker(["exec", container, "tc", "qdisc", "del", "dev", name, "root", "handle", "7a11:"])
        if not self.is_noqueue(self.qdiscs(container, name)):
            raise RuntimeError("cleared impairment did not restore the default qdisc")
        del self.impairments[node, peer]

    def teardown_all(self):
        errors = []
        for a, b in reversed(self.created):
            owner = self.owner(a, b)
            temporary = host_names(self.topology.run_name, a, b)
            for node, peer, name in ((a, b, temporary[0]), (b, a, temporary[1])):
                try:
                    container = self.container(node)["Id"]
                    links = self.links(container)
                    for candidate in (name, veth_interface_name(node, peer)):
                        if candidate in links:
                            if links[candidate].get("ifalias") != owner:
                                raise RuntimeError("refusing cleanup of unowned container interface")
                            docker(["exec", container, "ip", "link", "delete", candidate])
                except RuntimeError as error:
                    errors.append(str(error))
            try:
                links = self.links()
                for name in temporary:
                    if name in links:
                        if links[name].get("ifalias") != owner:
                            raise RuntimeError("refusing cleanup of unowned host interface")
                        self.host(["link", "delete", name])
                        break  # Deleting either endpoint deletes the pair.
            except RuntimeError as error:
                errors.append(str(error))
        if errors:
            raise RuntimeError("; ".join(errors))
        self.created.clear()
        self.impairments.clear()
