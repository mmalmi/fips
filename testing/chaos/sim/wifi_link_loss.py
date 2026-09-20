"""Optional bounded link observations; counters are not packet delivery receipts."""

import math
import re
import shlex

from .wifi_remote import checked_name, checked_path


SYS_NET = "/sys/class/net"
MAX_STATION_BYTES = 65536
COUNTERS = ("tx_packets", "tx_bytes", "tx_dropped", "tx_errors",
            "rx_packets", "rx_bytes", "rx_dropped", "rx_errors")
STATION_COUNTERS = ("tx packets", "tx bytes", "tx retries", "tx failed",
                    "rx packets", "rx bytes", "rx drop misc")
FIELDS = ("link_started", "link_identity_before", "link_counters", "link_stations_status",
          "link_stations_rc", "link_stations", "link_qdisc_status", "link_qdisc_rc",
          "link_qdisc", "link_identity_after", "link_finished")
MAC = r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}"


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


def command(node, proc):
    """Assignments only; the caller emits fields after its final process check."""
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


def parse(node, values):
    if len(values) != len(FIELDS):
        raise ValueError("invalid link observation framing")
    raw = dict(zip(FIELDS, values))
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
    return {"interface": node.interface, **before,
            "timing": {"clock": "router_uptime_seconds", "started": started, "finished": finished},
            "sysfs": counters, "stations": station,
            "qdisc": tool_observation(raw["link_qdisc_status"], raw["link_qdisc_rc"], raw["link_qdisc"]),
            "scope": "serial interface and peer observations; not FIPS-specific drops or delivery receipts"}
