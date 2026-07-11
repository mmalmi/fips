#!/usr/bin/env python3
"""Verify two FIPS cgroups and separate load-generator cgroups."""

import json
import subprocess


def inspect(*names: str) -> list[dict]:
    return json.loads(subprocess.check_output(["docker", "inspect", *names], text=True))


def main() -> None:
    node_a, node_b = inspect("fips-tun-a", "fips-tun-b")
    networks_a = {v["NetworkID"] for v in node_a["NetworkSettings"]["Networks"].values()}
    networks_b = {v["NetworkID"] for v in node_b["NetworkSettings"]["Networks"].values()}
    if len(networks_a) != 1 or networks_a != networks_b:
        raise SystemExit(f"nodes do not share exactly one underlay: A={networks_a} B={networks_b}")

    load_a, load_b = inspect("fips-tun-load-a", "fips-tun-load-b")
    id_a = node_a["Id"]
    id_b = node_b["Id"]
    if load_a["HostConfig"]["NetworkMode"] != f"container:{id_a}":
        raise SystemExit("load-a does not share node-a's network namespace")
    if load_b["HostConfig"]["NetworkMode"] != f"container:{id_b}":
        raise SystemExit("load-b does not share node-b's network namespace")
    print("verified: direct A-B underlay; load generators have separate CPU cgroups")


if __name__ == "__main__":
    main()
