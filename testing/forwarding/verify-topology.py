#!/usr/bin/env python3
"""Fail unless Docker attached exactly A--B and B--C, with no A--C LAN."""

import json
import subprocess


CONTAINERS = ["fips-forward-a", "fips-forward-b", "fips-forward-c"]


def main() -> None:
    raw = subprocess.check_output(["docker", "inspect", *CONTAINERS], text=True)
    inspected = json.loads(raw)
    networks = {
        item["Name"].removeprefix("/"): {
            details["NetworkID"] for details in item["NetworkSettings"]["Networks"].values()
        }
        for item in inspected
    }
    a, b, c = (networks[name] for name in CONTAINERS)
    if len(a) != 1 or len(b) != 2 or len(c) != 1:
        raise SystemExit(f"wrong network degree: A={len(a)} B={len(b)} C={len(c)}")
    if len(a & b) != 1 or len(b & c) != 1 or a & c:
        raise SystemExit(f"not an isolated chain: A={a} B={b} C={c}")
    print("verified: A and C share no underlay; only B is dual-homed")


if __name__ == "__main__":
    main()
