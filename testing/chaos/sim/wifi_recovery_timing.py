"""Opt-in observation brackets, separate from radio and route acceptance."""

import copy
import math
import time

from .paid_settlement import require
from .wifi_measurements import unsigned
from .wifi_link_loss import stations


MAX_SAMPLES = 512
LOG_FILTER = ("warn,fips_core::transport::ethernet=trace,"
              "fips_core::node::handlers::mmp=debug,"
              "fips_core::node::handlers::rekey=trace,"
              "fips_core::node::handlers::session=debug,"
              "fips_core::node::lifecycle=debug")


def bracket(operation):
    started = time.monotonic()
    value = operation()
    return {"started": started, "completed": time.monotonic(), "value": value}


def radio_state(node):
    transports = node.native({"command": "show_transports"})
    require(transports.get("status") == "ok", "native transport observation failed")
    adapters = [item for item in transports["data"]["transports"]
                if item["type"] == "ethernet" and item["name"] == node.interface]
    require(len(adapters) == 1, "timing requires the exact mesh adapter")
    adapter = adapters[0]
    for field in ("beacons_sent", "beacons_recv", "beacons_dropped"):
        unsigned(adapter["stats"][field])
    return adapter


class RecoveryTiming:
    def __init__(self, run, evidence, outage_node):
        self.run = run
        self.radio = run.nodes[outage_node]
        self.data = {"clock": "controller_monotonic_seconds", "samples": [], "anchors": {},
                     "sample_limit": MAX_SAMPLES, "radio_node": outage_node,
                     "log_filter": LOG_FILTER,
                     "scope": "serial observation intervals, not exact transition times; "
                              "received beacon totals include unparsed frames, not authentication; "
                              "station membership is not the filtered FIPS topology"}
        evidence["timing"] = self.data

    def anchor(self, phase):
        anchors = self.data["anchors"][phase] = {}
        for name, node in self.run.nodes.items():
            self.run.monitor.check()
            sample = bracket(lambda: node.remote("date +%s\ncut -d ' ' -f 1 /proc/uptime"))
            wall, uptime = sample.pop("value").decode().splitlines()
            require(wall.isascii() and wall.isdecimal(), "invalid remote wall-clock anchor")
            uptime = float(uptime)
            require(math.isfinite(uptime) and uptime >= 0, "invalid remote uptime anchor")
            sample.update(wall_seconds=int(wall), wall_resolution_seconds=1, uptime_seconds=uptime)
            anchors[name] = sample
            self.run.save()

    def ready(self, phase, **kwargs):
        require(len(self.data["samples"]) < MAX_SAMPLES, "recovery timing sample limit reached")
        sample = {"phase": phase, "started": time.monotonic()}
        self.data["samples"].append(sample)
        try:
            result = self.run.ready(**kwargs)
            sample.update(peers_observed=time.monotonic(), ready=bool(result),
                          peers=copy.deepcopy(self.run.evidence["last_peer_observation"]))
            sample["adapter"] = bracket(lambda: radio_state(self.radio))
            sample["stations"] = bracket(lambda: stations(self.radio))
            return result
        except Exception as error:
            sample["error"] = type(error).__name__
            raise
        finally:
            sample["completed"] = time.monotonic()
            self.run.save()
