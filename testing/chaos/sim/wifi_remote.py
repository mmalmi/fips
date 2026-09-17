"""Ownership-checked SSH operations for an explicitly supplied OpenWrt bench."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import shlex
import subprocess
from pathlib import Path, PurePosixPath

from .wifi_mesh import helpers as mesh_helpers, profile as mesh_profile


ETHERTYPE = 0x88B5
# A lost-peer quote can take 30 seconds; controller shutdown drains that work.
CANDIDATE_STOP_SECONDS = 65
CLEANUP_TIMEOUT_SECONDS = 180


def checked_name(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", value):
        raise ValueError("invalid host or interface name")
    return value


def checked_path(value):
    if not isinstance(value, str) or not re.fullmatch(r"/[A-Za-z0-9/_.-]+", value):
        raise ValueError("expected a simple absolute path")
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts or str(path) == "/":
        raise ValueError("expected a non-root absolute path")
    return str(path)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Router:
    def __init__(self, spec, run, output):
        if not re.fullmatch(r"[0-9a-f]{12}", run):
            raise ValueError("invalid run identity")
        self.spec = spec
        self.host = checked_name(spec["host"])
        self.interface = checked_name(spec["interface"])
        self.management = checked_name(spec["management_interface"])
        if self.interface == self.management:
            raise ValueError("mesh and management must be different interfaces")
        self.original_binary = checked_path(spec["original_binary"])
        self.original_config = checked_path(spec["original_config"])
        self.parent = checked_path(spec["state_parent"]) + "/wifi-" + run
        self.state = self.parent + "/state"
        self.config = self.parent + "/config.json"
        self.temporary = "/tmp/fips-wifi-" + run
        self.binary = self.temporary + "/fips-relay"
        self.table = "fips_wifi_" + run
        self.table_owner = "fips-wifi-owner-" + secrets.token_hex(16)
        self.output = output / self.host
        self.output.mkdir(mode=0o700)
        self.created = False
        self.guard_ready = False
        self.npub = None
        self.mac = None
        self.mesh = None

    def remote(self, command, data=None, timeout=20):
        args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5"]
        if self.spec.get("ssh_config"):
            args += ["-F", str(Path(self.spec["ssh_config"]).resolve(strict=True))]
        args += [self.host, command if isinstance(command, str) else shlex.join(command)]
        result = subprocess.run(args, input=data, capture_output=True, timeout=timeout)
        if result.returncode:
            (self.output / "last-error.txt").write_bytes(result.stderr + b"\n" + result.stdout)
            raise RuntimeError(f"{self.host}: remote operation failed; private error saved")
        return result.stdout

    def write(self, path, content):
        self.remote("umask 077; set -C; cat > " + shlex.quote(path), content)

    def control(self, kind, original=False, action="ctl", **fields):
        binary = self.original_binary if original else self.binary
        config = self.original_config if original else self.config
        return json.loads(self.remote([binary, action, config],
                                     json.dumps({"type": kind, **fields}).encode(), timeout=45))

    def native(self, command):
        return json.loads(self.remote([self.binary, "native", self.config],
                                     json.dumps(command).encode()))

    def baseline(self):
        board = json.loads(self.remote(["ubus", "call", "system", "board"]))
        if board["board_name"] != self.spec["expected_board"]:
            raise RuntimeError("router does not match the supplied inventory")
        status = self.control("status", original=True)
        if status["purchases"] or status["locked_sat"] or status["watched_routes"]:
            raise RuntimeError("original instance must have no active purchases or watches")
        config = json.loads(self.remote(["cat", self.original_config]))
        ethernet = config.get("transports", {}).get("ethernet", {})
        entries = [ethernet] if "interface" in ethernet else list(ethernet.values())
        if any(item.get("ethertype", 0x2121) == ETHERTYPE for item in entries):
            raise RuntimeError("test EtherType is already used by the original instance")
        state = checked_path(config["state_directory"])
        paths = [self.original_binary, self.original_config, "/etc/config/network",
                 "/etc/config/wireless", "/etc/config/fips-relay", state + "/identity.key",
                 state + "/service.json", state + "/buyer/buyer.json",
                 state + "/seller/ledger.json", state + "/controller/controller.json"]
        hashes = self.remote(["sha256sum", *paths]).decode()
        # Only hashes leave the router; never copy private keys or payment proofs.
        self.mac = self.remote(["cat", f"/sys/class/net/{self.interface}/address"]).decode().strip()
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", self.mac):
            raise RuntimeError("invalid mesh address")
        if self.mac != self.spec["expected_mesh_mac"]:
            raise RuntimeError("mesh address does not match the supplied inventory")
        self.remote(f"test ! -e /sys/class/net/{self.interface}/master && "
                    f"test ! -d /sys/class/net/{self.interface}/bridge && "
                    f"test \"$(iw dev {self.interface} get mesh_param mesh_fwding)\" = 0 && "
                    f"test \"$(cat /sys/class/net/{self.interface}/carrier)\" = 1 && "
                    "test -f /var/run/fips-relay.time-valid")
        if self.remote(["ip", "-o", "addr", "show", "dev", self.interface]).strip():
            raise RuntimeError("mesh test interface must have no IP addresses")
        wireless = json.loads(self.remote(["ubus", "call", "network.wireless", "status"]))
        mesh_radios = [radio for radio in wireless.values()
                       if any(i["ifname"] == self.interface for i in radio.get("interfaces", []))]
        if (len(mesh_radios) != 1 or len(mesh_radios[0]["interfaces"]) != 1
                or mesh_radios[0]["interfaces"][0]["config"]["mode"] != "mesh"):
            raise RuntimeError("mesh recovery requires a dedicated radio without access points")
        self.mesh = mesh_profile(self.remote, self.interface)
        aps = []
        for radio in wireless.values():
            interfaces = [item for item in radio.get("interfaces", []) if item["config"]["mode"] == "ap"]
            if interfaces and not radio["up"]:
                raise RuntimeError("an original access point is unavailable")
            aps.extend(item["ifname"] for item in interfaces)
        self.management_check(heartbeat=False)
        self.remote(["uclient-fetch", "-q", "-T", "5", "-O", "/dev/null", "https://openwrt.org"], timeout=10)
        return {"hashes": hashes, "identity": status["npub"], "history": status["history"],
                "remaining_budget_sat": status["remaining_budget_sat"],
                "purchases": status["purchases"], "locked_sat": status["locked_sat"],
                "watched_routes": status["watched_routes"], "access_points_up": sorted(aps),
                "https_and_dns": True, "mesh_runtime": self.mesh,
                "connected_peers": sorted((p["npub"], p["transport"], p["address"])
                                          for p in status["peers"] if p["connected"])}

    def management_check(self, heartbeat=True):
        command = (f"test \"$(cat /sys/class/net/{self.management}/carrier)\" = 1; "
                   f"gateway=$(ip -4 route show default dev {self.management} | "
                   "awk '$1 == \"default\" {print $3; exit}'); "
                   f"test -n \"$gateway\"; ping -I {self.management} -c 1 -W 2 \"$gateway\" >/dev/null")
        if heartbeat:
            command += (f"; if [ -f {self.temporary}/active ]; then "
                        f"cut -d . -f 1 /proc/uptime >{self.temporary}/heartbeat.new; "
                        f"mv {self.temporary}/heartbeat.new {self.temporary}/heartbeat; fi")
        self.remote("set -eu; " + command, timeout=10)

    def guard_script(self):
        # Independent remote expiry restores an owned outage even if SSH/the runner dies.
        t = self.temporary
        return f"""#!/bin/sh
set -eu
. {t}/mesh.sh
owned_candidate() {{
  [ -r /proc/$pid/cmdline ] || return 1
  actual=$(tr '\\000' '\\n' </proc/$pid/cmdline)
  expected=$(printf '%s\\n' {self.binary} run {shlex.quote(self.config)})
  [ "$actual" = "$expected" ] && return 0
  expected=$(printf '%s\\n' sh {t}/start.sh)
  [ "$actual" = "$expected" ]
}}
stop_candidate() {{
  if [ -f {t}/process.pid ]; then
    pid=$(cat {t}/process.pid)
    if owned_candidate; then
      kill -TERM "$pid" || :
      for attempt in $(seq 1 {CANDIDATE_STOP_SECONDS}); do owned_candidate || break; sleep 1; done
      if owned_candidate; then
        touch {t}/candidate-forced-stop
        kill -KILL "$pid" || :
        for attempt in $(seq 1 5); do owned_candidate || break; sleep 1; done
      fi
      if owned_candidate; then touch {t}/candidate-stop-failed; fi
    fi
  fi
}}
cleanup() {{
  exec 9>{t}/operation.lock
  flock -x 9
  rm -f {t}/active
  if [ -f {t}/mesh-down ]; then
    mesh_restore && rm -f {t}/mesh-down || echo 'mesh restore failed' >&2
  fi
  if [ -f {t}/table-created ]; then
    owner=$(nft -j list table netdev {self.table} 2>/dev/null | jsonfilter -e '@.nftables[*].table.comment' || :)
    if [ "$owner" = "{self.table_owner}" ]; then
      nft delete table netdev {self.table} && rm -f {t}/table-created || echo 'table restore failed' >&2
    fi
  fi
  stop_candidate
  touch {t}/guard-cleaned
  flock -u 9
  exec 9>&-
}}
[ "${{1:-}}" != cleanup ] || {{ cleanup; exit 0; }}
# The caller holds operation.lock and checks the live lease for this path.
[ "${{1:-}}" != stop ] || {{ stop_candidate; exit 0; }}
trap cleanup EXIT
trap 'exit 0' TERM INT
echo $$ >{t}/guard.pid
touch {t}/guard-ready
while [ -f {t}/active ]; do
  age=$(( $(cut -d . -f 1 /proc/uptime) - $(cat {t}/heartbeat) ))
  [ "$age" -le 35 ] || exit 0
  sleep 5
done
""".encode()

    def guarded_script(self, command):
        t = self.temporary
        # The cleanup guard uses this same kernel lock. A command arriving after
        # lease expiry cannot mutate the interface, filter or process set.
        prologue = f"""set -eu
exec 9>{t}/operation.lock
flock -x 9
trap 'flock -u 9' EXIT
test -f {t}/active
test -f {t}/guard-ready
pid=$(cat {t}/guard.pid)
actual=$(tr '\\000' '\\n' </proc/$pid/cmdline)
expected=$(printf '%s\\n' sh {t}/guard.sh)
test "$actual" = "$expected"
age=$(( $(cut -d . -f 1 /proc/uptime) - $(cat {t}/heartbeat) ))
test "$age" -le 35
. {t}/mesh.sh
"""
        return prologue + command

    def guarded(self, command, data=None, timeout=20):
        return self.remote(self.guarded_script(command), data, timeout=timeout)

    def start_script(self):
        # The child fences itself after dispatch, then records its PID before
        # unlocking. Cleanup recognizes both this launcher and the final binary.
        t = self.temporary
        command = (f"echo $$ > {t}/process.pid\nflock -u 9\nexec 9>&-\ntrap - EXIT\n"
                   + shlex.join(["exec", self.binary, "run", self.config]) + "\n")
        return ("#!/bin/sh\n" + self.guarded_script(command)).encode()

    def prepare(self, binary, config):
        # Persistent accounts and RAM-backed executable have distinct fresh owned paths.
        self.remote(["mkdir", "-m", "700", self.temporary])
        self.created = True
        self.write(self.temporary + "/mesh.sh", mesh_helpers(self.interface, self.mesh).encode())
        self.write(self.temporary + "/guard.sh", self.guard_script())
        self.remote(f"touch {self.temporary}/active; "
                    f"cut -d . -f 1 /proc/uptime >{self.temporary}/heartbeat; "
                    f"setsid sh {self.temporary}/guard.sh </dev/null "
                    f">{self.temporary}/guard.log 2>&1 &")
        self.remote(f"set -eu; for attempt in $(seq 1 10); do "
                    f"[ ! -f {self.temporary}/guard-ready ] || break; sleep 0.1; done; "
                    f"test -f {self.temporary}/guard-ready")
        self.guarded(":")
        self.guard_ready = True
        self.remote(["mkdir", "-m", "700", self.parent])
        filesystem = self.remote(["df", "-PT", self.parent]).decode().splitlines()[-1].split()[1]
        if filesystem in ("tmpfs", "ramfs", "squashfs"):
            raise RuntimeError("test accounts require writable persistent storage")
        self.write(self.config, json.dumps(config).encode())
        self.write(self.binary, binary)
        self.remote(["chmod", "700", self.binary])
        if self.remote(["sha256sum", self.binary]).decode().split()[0] != digest(binary):
            raise RuntimeError("staged binary checksum differs")
        self.npub = self.remote([self.binary, "init", self.config], timeout=45).decode().strip()
        self.write(self.temporary + "/start.sh", self.start_script())

    def start(self):
        self.remote(f"setsid sh {self.temporary}/start.sh </dev/null "
                    f">{self.temporary}/process.log 2>&1 &")

    def stop(self):
        # Preserve the guard, executable and profiles for offline wallet collection.
        t = self.temporary
        self.guarded(f"sh {t}/guard.sh stop; test ! -f {t}/candidate-stop-failed; "
                     f"test ! -f {t}/candidate-forced-stop", timeout=CLEANUP_TIMEOUT_SECONDS)

    def install_filter(self, excluded_mac):
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", excluded_mac):
            raise ValueError("invalid excluded mesh address")
        # Collision refusal and creation are one nft transaction; existing rules are untouched.
        rules = (f'create table netdev {self.table} {{ comment "{self.table_owner}"; }}\n'
                 f'add chain netdev {self.table} ingress {{ type filter hook ingress '
                 f'device "{self.interface}" priority -500; policy accept; }}\n'
                 f'add rule netdev {self.table} ingress ether type 0x{ETHERTYPE:x} '
                 f'ether saddr {excluded_mac} counter drop\n')
        # Reject any prior table before arming recovery. The independent token
        # also distinguishes uncertain creation from an unrelated same-name rule.
        t = self.temporary
        self.guarded(f"""nft -j list tables >{t}/tables-before.json
names=$(jsonfilter -i {t}/tables-before.json -e '@.nftables[*].table.name' || :)
if printf '%s\\n' "$names" | grep -Fxq {self.table}; then exit 1; fi
touch {t}/table-created
nft -f -
""", rules.encode())
        return json.loads(self.remote(["nft", "-j", "list", "table", "netdev", self.table]))

    def mesh_down(self):
        # Keep the netdev and saved network; a raw link toggle leaves supplicant
        # believing it still owns a joined mesh after the kernel has left it.
        self.guarded(f"mesh_profile; mesh_joined; touch {self.temporary}/mesh-down; "
                     f"test \"$(mesh_control 'MESH_GROUP_REMOVE {self.interface}')\" = OK")

    def mesh_up(self):
        self.guarded(f"test -f {self.temporary}/mesh-down; "
                     f"mesh_restore; rm -f {self.temporary}/mesh-down", timeout=60)

    def monetary_journals(self):
        result = {name: json.loads(self.remote(["cat", self.state + "/" + path]))
                  for name, path in (("buyer", "buyer/buyer.json"),
                                     ("seller", "seller/ledger.json"),
                                     ("controller", "controller/controller.json"))}
        for field in ("selling_stopped", "renewals_paused", "watched_routes"):
            result["controller"].pop(field, None)
        return result

    def cleanup(self):
        if not self.guard_ready:
            return
        # The same script handles normal and abandoned runs; it checks process ownership.
        self.remote(["sh", self.temporary + "/guard.sh", "cleanup"],
                    timeout=CLEANUP_TIMEOUT_SECONDS)
        t = self.temporary
        # Wait for both owned processes, without killing any unrelated PID reuse.
        self.remote(f"""set -eu
owned() {{
  [ -f {t}/$1.pid ] || return 1
  pid=$(cat {t}/$1.pid)
  [ -r /proc/$pid/cmdline ] || return 1
  tr '\\000' '\\n' </proc/$pid/cmdline | grep -Fxq "$2"
}}
for attempt in $(seq 1 35); do
  if ! owned process {shlex.quote(self.config)} && ! owned guard {t}/guard.sh; then break; fi
  sleep 1
done
! owned process {shlex.quote(self.config)}
! owned guard {t}/guard.sh
""", timeout=45)
        tables = json.loads(self.remote(["nft", "-j", "list", "tables"]))
        if any(row.get("table", {}).get("name") == self.table for row in tables["nftables"]):
            raise RuntimeError("owned test table remains after cleanup")
        for name in ("process.log", "guard.log"):
            data = self.remote(f"test ! -f {self.temporary}/{name} || cat {self.temporary}/{name}")
            (self.output / name).write_bytes(data)
        self.remote(["rm", "-f", self.binary])
        # Preserve failure markers and logs, but finish safe cleanup first.
        self.remote(f"test ! -f {t}/mesh-down && test ! -f {t}/table-created && "
                    f"test ! -f {t}/candidate-stop-failed && test ! -f {t}/candidate-forced-stop")
