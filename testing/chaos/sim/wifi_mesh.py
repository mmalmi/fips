"""OpenWrt mesh leave/join without recreating its netdev or saved SAE network."""

import hashlib
import json
from pathlib import Path
import shlex


SYS_NET = Path("/sys/class/net")
JOIN_ATTEMPTS = 10


def control(remote, interface, command):
    response = remote(["ubus", "-t", "2", "call", "wpa_supplicant." + interface,
                       "control", json.dumps({"command": command})])
    return json.loads(response)["result"].strip()


def profile(remote, interface):
    networks = control(remote, interface, "LIST_NETWORKS").splitlines()[1:]
    if len(networks) != 1:
        raise RuntimeError("mesh recovery requires exactly one saved supplicant network")
    fields = networks[0].split("\t")
    if len(fields) != 4 or not fields[0].isdigit() or fields[3] != "[CURRENT]":
        raise RuntimeError("mesh recovery requires one current supplicant network")
    network = int(fields[0])
    properties = {key: control(remote, interface, f"GET_NETWORK {network} {key}")
                  for key in ("mode", "mesh_fwding", "key_mgmt", "frequency", "ssid")}
    if (properties["mode"] != "5" or properties["mesh_fwding"] != "0"
            or properties["key_mgmt"] != "SAE" or not properties["frequency"].isdigit()
            or properties["ssid"] == "FAIL"):
        raise RuntimeError("saved mesh must use SAE and disable layer-two forwarding")
    status = control(remote, interface, "STATUS").splitlines()
    if "wpa_state=COMPLETED" not in status or f"id={network}" not in status:
        raise RuntimeError("supplicant mesh is not joined")
    return {"network_id": network, "frequency": int(properties["frequency"]),
            "ssid_sha256": hashlib.sha256(properties["ssid"].encode()).hexdigest(),
            "ifindex": int(remote(["cat", str(SYS_NET / interface / "ifindex")])),
            "mac": remote(["cat", str(SYS_NET / interface / "address")]).decode().strip()}


def helpers(interface, saved):
    """Shared by normal recovery and the independent, lock-serialized guard."""
    net = SYS_NET / interface
    network, frequency = saved["network_id"], saved["frequency"]
    return f"""mesh_control() {{
  mesh_reply=$(ubus -t 2 call wpa_supplicant.{interface} control "{{\\\"command\\\":\\\"$1\\\"}}") || return 1
  printf '%s\\n' "$mesh_reply" | jsonfilter -e '@.result'
}}
mesh_identity() {{
  test "$(cat {net}/ifindex)" = {saved['ifindex']} &&
  test "$(cat {net}/address)" = {shlex.quote(saved['mac'])}
}}
mesh_profile() {{
  mesh_identity || return 1
  mesh_networks=$(mesh_control LIST_NETWORKS) || return 1
  printf '%s\\n' "$mesh_networks" | awk -F '\\t' '
    NR > 1 {{ rows++; if (NF != 4 || $1 != {network} || ($4 != "" && $4 != "[CURRENT]")) bad=1 }}
    END {{ exit bad || rows != 1 }}' || return 1
  test "$(mesh_control 'GET_NETWORK {network} mode')" = 5 || return 1
  test "$(mesh_control 'GET_NETWORK {network} mesh_fwding')" = 0 || return 1
  test "$(mesh_control 'GET_NETWORK {network} key_mgmt')" = SAE || return 1
  test "$(mesh_control 'GET_NETWORK {network} frequency')" = {frequency} || return 1
  mesh_ssid=$(mesh_control 'GET_NETWORK {network} ssid') || return 1
  test "$(printf '%s' "$mesh_ssid" | sha256sum | cut -d ' ' -f 1)" = {saved['ssid_sha256']}
}}
mesh_joined() {{
  mesh_identity || return 1
  test "$(cat {net}/carrier)" = 1 || return 1
  test "$(iw dev {interface} get mesh_param mesh_fwding)" = 0 || return 1
  mesh_status=$(mesh_control STATUS) || return 1
  printf '%s\\n' "$mesh_status" | grep -Fxq 'wpa_state=COMPLETED' &&
  printf '%s\\n' "$mesh_status" | grep -Fxq 'id={network}' &&
  printf '%s\\n' "$mesh_status" | grep -Fxq 'freq={frequency}'
}}
mesh_restore() {{
  mesh_profile || return 1
  if mesh_joined; then return 0; fi
  test "$(mesh_control 'MESH_GROUP_ADD {network}')" = OK || return 1
  for mesh_attempt in $(seq 1 {JOIN_ATTEMPTS}); do
    if mesh_joined; then return 0; fi
    sleep 1
  done
  return 1
}}
"""
