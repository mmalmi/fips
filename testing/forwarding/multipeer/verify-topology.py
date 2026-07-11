#!/usr/bin/env python3
"""Fail unless only B joins the three isolated leaf underlays."""

import json
import subprocess


CONTAINERS = {
    "a": "fips-fair-a",
    "b": "fips-fair-b",
    "c": "fips-fair-c",
    "d": "fips-fair-d",
}


def verify(networks: dict[str, set[str]]) -> None:
    b = networks[CONTAINERS["b"]]
    leaves = [networks[CONTAINERS[node]] for node in ("a", "c", "d")]
    if len(b) != 3 or any(len(leaf) != 1 for leaf in leaves):
        raise SystemExit(f"wrong network degree: {networks}")
    if any(len(leaf & b) != 1 for leaf in leaves):
        raise SystemExit(f"a leaf is not attached exactly once to B: {networks}")
    if any(leaves[i] & leaves[j] for i in range(3) for j in range(i + 1, 3)):
        raise SystemExit(f"leaf underlay bypass exists: {networks}")
    if len(set().union(*leaves)) != 3:
        raise SystemExit(f"leaf underlays are not distinct: {networks}")


def main() -> None:
    raw = subprocess.check_output(
        ["docker", "inspect", *CONTAINERS.values()], text=True
    )
    inspected = json.loads(raw)
    networks = {
        item["Name"].removeprefix("/"): {
            details["NetworkID"]
            for details in item["NetworkSettings"]["Networks"].values()
        }
        for item in inspected
    }
    verify(networks)
    print("verified: three isolated leaves; only B is multi-homed")


if __name__ == "__main__":
    main()
