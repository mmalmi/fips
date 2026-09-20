"""Optional bounded link observations; counters are not packet delivery receipts."""

import math
import re
import shlex

from .wifi_remote import checked_name, checked_path


SYS_NET = "/sys/class/net"
DEBUGFS = "/sys/kernel/debug/ieee80211"
MAX_STATION_BYTES = 65536
MAX_AQM_BYTES = 4096
COUNTERS = ("tx_packets", "tx_bytes", "tx_dropped", "tx_errors",
            "rx_packets", "rx_bytes", "rx_dropped", "rx_errors")
STATION_COUNTERS = ("tx packets", "tx bytes", "tx retries", "tx failed",
                    "rx packets", "rx bytes", "rx drop misc")
FIELDS = ("link_started", "link_identity_before", "link_counters", "link_stations_status",
          "link_stations_rc", "link_stations", "link_qdisc_status", "link_qdisc_rc",
          "link_qdisc", "link_identity_after", "link_finished")
MAC = r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}"
AQM_FIELDS = ("link_aqm_started", "link_aqm_phy_before", "link_aqm_status",
              "link_aqm_rc", "link_aqm", "link_aqm_phy_after",
              "link_aqm_station_status", "link_aqm_station_rc", "link_aqm_station",
              "link_aqm_finished")


def bounded_command(arguments):
    return f"set -o pipefail\n{shlex.join(arguments)} 2>&1 | head -c {MAX_STATION_BYTES + 1}"


def station_command(interface):
    return bounded_command(["iw", "dev", checked_name(interface), "station", "dump"])


def stations(node):
    """Shared with the existing recovery-timing observation, with the same limit."""
    value = node.remote(["sh", "-c", station_command(node.interface)])
    if len(value) > MAX_STATION_BYTES:
        raise RuntimeError("station observation exceeds its bound")
    return value.decode()


def optional_tool(name, program, command):
    return f"""link_{name}=''
link_{name}_rc=''
link_{name}_status=missing
if command -v {shlex.quote(program)} >/dev/null 2>&1; then
  if link_{name}=$({command}); then
    link_{name}_status=available
    link_{name}_rc=0
  else
    link_{name}_rc=$?
    link_{name}_status=error
  fi
fi
"""


def fields(aqm_peer=None):
    if aqm_peer is not None and (not isinstance(aqm_peer, str) or not re.fullmatch(MAC, aqm_peer)):
        raise ValueError("invalid AQM peer")
    return FIELDS + (AQM_FIELDS if aqm_peer is not None else ())


def aqm_command(interface, net, uptime, peer):
    directory = shlex.quote(checked_path(DEBUGFS))
    suffix = shlex.quote(f"/netdev:{interface}/stations/{peer}/aqm")
    return f"""link_aqm_started=$(cut -d ' ' -f 1 {uptime})
link_aqm_phy_before=$(cat {net}/phy80211/name)
case "$link_aqm_phy_before" in ''|*[!a-zA-Z0-9_.-]*) exit 1;; esac
link_aqm_path={directory}/"$link_aqm_phy_before"{suffix}
link_aqm=''
link_aqm_rc=''
link_aqm_status=missing
if test -e "$link_aqm_path" || test -L "$link_aqm_path"; then
  if link_aqm=$(set -o pipefail
    aqm_read_status=0
    cat "$link_aqm_path" 2>&1 | head -c {MAX_AQM_BYTES + 1} || aqm_read_status=$?
    printf '.'
    exit "$aqm_read_status"); then
    link_aqm_status=available
    link_aqm_rc=0
  else
    link_aqm_rc=$?
    link_aqm_status=error
  fi
  link_aqm=${{link_aqm%.}}
fi
{optional_tool('aqm_station', 'iw', bounded_command(['iw', 'dev', interface, 'station', 'get', peer]))}
link_aqm_phy_after=$(cat {net}/phy80211/name)
link_aqm_finished=$(cut -d ' ' -f 1 {uptime})
"""


def command(node, proc, aqm_peer=None):
    """Assignments only; the caller emits fields after its final process check."""
    fields(aqm_peer)
    interface = checked_name(node.interface)
    net = shlex.quote(checked_path(SYS_NET + "/" + interface))
    uptime = shlex.quote(checked_path(proc + "/uptime"))
    identity = f"cat {net}/ifindex {net}/address"
    counters = " ".join(COUNTERS)
    return f"""link_started=$(cut -d ' ' -f 1 {uptime})
link_identity_before=$({identity})
link_counters=$(
  for field in {counters}; do
    path={net}/statistics/$field
    value=''
    availability=missing
    if test -e "$path" || test -L "$path"; then
      if value=$(cat "$path" 2>/dev/null); then availability=available; else availability=error; value=''; fi
    fi
    printf '%s\\t%s\\t%s\\n' "$field" "$availability" "$value"
  done
)
{optional_tool('stations', 'iw', station_command(interface))}
{optional_tool('qdisc', 'tc', bounded_command(['tc', '-s', 'qdisc', 'show', 'dev', interface]))}
{aqm_command(interface, net, uptime, aqm_peer) if aqm_peer is not None else ''}
link_identity_after=$({identity})
link_finished=$(cut -d ' ' -f 1 {uptime})
"""


def counter(value):
    if not value or len(value) > 20 or not value.isascii() or not value.isdecimal():
        raise ValueError("invalid link counter")
    result = int(value)
    if result > (1 << 64) - 1:
        raise ValueError("link counter exceeds u64")
    return result


def identity(value):
    fields = value.splitlines()
    if len(fields) != 2 or not re.fullmatch(MAC, fields[1]):
        raise ValueError("invalid link interface identity")
    index = counter(fields[0])
    if not index:
        raise ValueError("invalid interface index")
    return {"ifindex": index, "mac": fields[1]}


def tool_observation(status, code, text):
    if len(text.encode()) > MAX_STATION_BYTES:
        raise ValueError("link tool observation exceeds its bound")
    if status == "missing" and code == "" and text == "":
        return {"availability": status, "exit_code": None, "raw": None}
    if status not in ("available", "error") or not code.isdecimal():
        raise ValueError("invalid link tool availability")
    code = int(code)
    if (status == "available") != (code == 0) or not 0 <= code <= 255:
        raise ValueError("inconsistent link tool exit status")
    return {"availability": status, "exit_code": code, "raw": text}


def station_records(text, interface):
    """Keep association identity and explicit unavailable counters alongside raw iw output."""
    records, fields = {}, None
    for line in text.splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(rf"Station ({MAC}) \(on {re.escape(interface)}\)", line)
        if match:
            peer = match[1]
            if peer in records:
                raise ValueError("duplicate station identity")
            fields = records[peer] = {}
            continue
        if fields is None or not line[:1].isspace() or ":" not in line:
            raise ValueError("unrecognized station observation")
        name, value = line.strip().split(":", 1)
        if name in fields:
            raise ValueError("duplicate station field")
        fields[name] = value.strip()
    return [{"peer": peer, "association": {
                "associated_at_boottime": fields.get("associated at [boottime]"),
                "connected_time": fields.get("connected time"),
                "mesh_plink": fields.get("mesh plink")},
             "counters": {name: counter(fields[name]) if name in fields else None
                          for name in STATION_COUNTERS}}
            for peer, fields in records.items()]


def parse_aqm(raw, peer, interface, station_before, timing):
    phy = raw["link_aqm_phy_before"]
    if not re.fullmatch(r"phy[0-9]+", phy) or phy != raw["link_aqm_phy_after"]:
        raise ValueError("AQM radio identity changed or invalid")
    started, finished = (float(raw["link_aqm_" + field]) for field in ("started", "finished"))
    if not timing["started"] <= started <= finished <= timing["finished"]:
        raise ValueError("AQM observation outside link timing bracket")
    aqm = tool_observation(raw["link_aqm_status"], raw["link_aqm_rc"], raw["link_aqm"])
    text = aqm["raw"]
    size = len(text.encode()) if text is not None else 0
    if size > MAX_AQM_BYTES + 1:
        raise ValueError("AQM output exceeds capture bound")
    aqm["truncated"] = size > MAX_AQM_BYTES
    if aqm["truncated"]:
        aqm["availability"] = "truncated"
        aqm["raw"] = text.encode()[:MAX_AQM_BYTES].decode("utf-8", errors="ignore")
    station_after = tool_observation(raw["link_aqm_station_status"],
                                    raw["link_aqm_station_rc"], raw["link_aqm_station"])
    station_after["records"] = (station_records(station_after["raw"], interface)
                                if station_after["availability"] == "available" else None)
    observations = [[record for record in (value["records"] or []) if record["peer"] == peer]
                    for value in (station_before, station_after)]
    associations = [records[0]["association"] if records else None for records in observations]
    before, after = associations
    state = "unknown"
    if before is not None and after is not None:
        epochs = [value["associated_at_boottime"] for value in associations]
        connected = [re.fullmatch(r"([0-9]+) seconds", value["connected_time"] or "")
                     for value in associations]
        if all(re.fullmatch(r"[0-9]+(?:\.[0-9]+)?s", epoch or "") for epoch in epochs) and all(connected):
            if any(float(epoch[:-1]) > timing["finished"] for epoch in epochs):
                raise ValueError("AQM association epoch is after its observation")
            state = ("changed" if epochs[0] != epochs[1] or int(connected[1][1]) < int(connected[0][1])
                     else "stable" if all(value["mesh_plink"] == "ESTAB" for value in associations)
                     else "not_established")
    return {**aqm, "peer": peer, "phy": phy,
            "timing": {"clock": "router_uptime_seconds", "started": started, "finished": finished},
            "association": {"status": state, "before": before, "after": after},
            "station_after": station_after}


def parse(node, values, aqm_peer=None):
    names = fields(aqm_peer)
    if len(values) != len(names):
        raise ValueError("invalid link observation framing")
    raw = dict(zip(names, values))
    before, after = (identity(raw["link_identity_" + position]) for position in ("before", "after"))
    if before != after:
        raise ValueError("link interface changed during observation")
    baseline = getattr(node, "mesh", None)
    if baseline is not None and any(before[key] != baseline[key] for key in before):
        raise ValueError("link interface differs from its owned baseline")
    started, finished = (float(raw["link_" + field]) for field in ("started", "finished"))
    if not all(math.isfinite(v) and v >= 0 for v in (started, finished)) or finished < started:
        raise ValueError("invalid router uptime observation interval")
    counters = {}
    for line in raw["link_counters"].splitlines():
        name, availability, value = line.split("\t")
        if name not in COUNTERS or name in counters:
            raise ValueError("invalid or duplicate interface counter")
        if availability == "available":
            value = counter(value)
        elif availability in ("missing", "error") and value == "":
            value = None
        else:
            raise ValueError("invalid interface counter availability")
        counters[name] = {"availability": availability, "value": value}
    if set(counters) != set(COUNTERS):
        raise ValueError("missing interface counter availability")
    station = tool_observation(raw["link_stations_status"], raw["link_stations_rc"], raw["link_stations"])
    station["records"] = (station_records(station["raw"], node.interface)
                          if station["availability"] == "available" else None)
    timing = {"clock": "router_uptime_seconds", "started": started, "finished": finished}
    result = {"interface": node.interface, **before, "timing": timing, "sysfs": counters, "stations": station,
              "qdisc": tool_observation(raw["link_qdisc_status"], raw["link_qdisc_rc"], raw["link_qdisc"]),
              "scope": "serial interface and peer observations; not FIPS-specific drops or delivery receipts"}
    if aqm_peer is not None:
        result["aqm"] = parse_aqm(raw, aqm_peer, node.interface, station, timing)
    return result
