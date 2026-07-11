#!/usr/bin/env python3

import importlib.util
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location(
    "fairness_topology", Path(__file__).with_name("verify-topology.py")
)
assert SPEC and SPEC.loader
TOPOLOGY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOPOLOGY)


class TopologyTests(unittest.TestCase):
    def networks(self) -> dict[str, set[str]]:
        return {
            "fips-fair-a": {"ab"},
            "fips-fair-b": {"ab", "bc", "db"},
            "fips-fair-c": {"bc"},
            "fips-fair-d": {"db"},
        }

    def test_three_isolated_leaves_pass(self) -> None:
        TOPOLOGY.verify(self.networks())

    def test_shared_leaf_underlay_is_rejected(self) -> None:
        networks = self.networks()
        networks["fips-fair-d"].add("bc")
        with self.assertRaises(SystemExit):
            TOPOLOGY.verify(networks)

    def test_leaf_not_attached_to_b_is_rejected(self) -> None:
        networks = self.networks()
        networks["fips-fair-d"] = {"other"}
        with self.assertRaises(SystemExit):
            TOPOLOGY.verify(networks)


if __name__ == "__main__":
    unittest.main()
