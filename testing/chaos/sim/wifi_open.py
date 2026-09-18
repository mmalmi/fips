"""Temporary, owner-tagged open mesh using the existing radio cleanup guard."""

import hashlib
import re
import shlex

from .wifi_mesh import control
from . import wifi_mesh


PEER_LIMIT = 8
PEER_IDLE_SECONDS = 60


def snapshot(remote, interface):
    saved = {}
    for field in ("max_peer_links", "mesh_max_inactivity", "user_mpm"):
        value = control(remote, interface, "GET " + field)
        if not value.isdigit():
            raise RuntimeError("supplicant cannot expose the original mesh limits")
        saved[field] = int(value)
    for field in ("mesh_max_peer_links", "mesh_plink_timeout"):
        value = remote(["iw", "dev", interface, "get", "mesh_param", field]).decode().strip()
        # iw renders this nl80211 field in seconds, including disabled value 0.
        pattern = r"([0-9]+) seconds" if field == "mesh_plink_timeout" else r"([0-9]+)"
        match = re.fullmatch(pattern, value)
        if not match:
            raise RuntimeError("kernel cannot expose the original mesh limits")
        saved[field] = int(match[1])
    return saved


def helpers(interface, saved, directory, name, owner, isolation_table, isolation_owner):
    """Called only under Router's live-lease lock; cleanup uses the same lock."""
    def kernel_value(key, value):
        return f"{value} seconds" if key == "mesh_plink_timeout" else str(value)

    original = saved["network_id"]
    net = wifi_mesh.SYS_NET / interface
    caps = saved["open_limits"]
    name_hash = hashlib.sha256(('"' + name + '"').encode()).hexdigest()
    owner_value = shlex.quote('"' + owner + '"')
    globals_restore = "\n".join(
        f'  test "$(mesh_control \'SET {key} {caps[key]}\')" = OK || return 1'
        for key in ("max_peer_links", "mesh_max_inactivity"))
    kernel_restore = "\n".join(
        f'  iw dev {interface} set mesh_param {key} {caps[key]} || return 1'
        for key in ("mesh_max_peer_links", "mesh_plink_timeout"))
    original_caps = "\n".join(
        [f'  test "$(mesh_control \'GET {key}\')" = {caps[key]} || return 1'
         for key in ("max_peer_links", "mesh_max_inactivity", "user_mpm")]
        + [f'  test "$(iw dev {interface} get mesh_param {key})" = "{kernel_value(key, caps[key])}" || return 1'
           for key in ("mesh_max_peer_links", "mesh_plink_timeout")])
    mutable_caps = "\n".join(
        f'  case "$(mesh_control \'GET {key}\')" in {caps[key]}|{limit}) ;; *) return 1;; esac'
        for key, limit in (("max_peer_links", PEER_LIMIT), ("mesh_max_inactivity", PEER_IDLE_SECONDS)))
    mutable_kernel = "\n".join(
        f'    case "$(iw dev {interface} get mesh_param {key})" in "{kernel_value(key, caps[key])}"|"{kernel_value(key, limit)}") ;; *) return 1;; esac'
        for key, limit in (("mesh_max_peer_links", PEER_LIMIT), ("mesh_plink_timeout", PEER_IDLE_SECONDS)))
    return f"""
original_isolated() {{
  test -f {directory}/original-isolated || return 1
  owner=$(nft -j list table netdev {isolation_table} | jsonfilter -e '@.nftables[*].table.comment') || return 1
  test "$owner" = {shlex.quote(isolation_owner)}
}}
open_id() {{
  test -f {directory}/open-id || return 1
  open_network=$(cat {directory}/open-id) || return 1
  case "$open_network" in ''|*[!0-9]*) return 1;; esac
  test "$open_network" != {original}
}}
open_owner() {{
  open_id || return 1
  test "$(mesh_control "GET_NETWORK $open_network id_str")" = {owner_value}
}}
open_networks() {{
  open_id || return 1
  mesh_networks=$(mesh_control LIST_NETWORKS) || return 1
  printf '%s\\n' "$mesh_networks" | awk -F '\\t' -v own="$open_network" '
    NR > 1 {{ rows++; if ($1 == {original}) old++; if ($1 == own) test++;
      if (NF != 4 || ($1 != {original} && $1 != own) || ($4 != "" && $4 != "[CURRENT]" && $4 != "[DISABLED]")) bad=1 }}
    END {{ exit bad || rows != 2 || old != 1 || test != 1 }}'
}}
open_caps_owned() {{
  test "$(mesh_control 'GET user_mpm')" = {caps['user_mpm']} || return 1
{mutable_caps}
  # Linux reports default mesh parameters while disconnected, not saved limits.
  if [ "$(cat {net}/carrier)" = 1 ]; then
{mutable_kernel}
    test "$(iw dev {interface} get mesh_param mesh_fwding)" = 0 || return 1
  fi
}}
open_original_caps() {{
{original_caps}
}}
open_profile() {{
  mesh_saved_profile && open_owner && open_networks && open_caps_owned || return 1
  test "$(mesh_control "GET_NETWORK $open_network mode")" = 5 || return 1
  test "$(mesh_control "GET_NETWORK $open_network key_mgmt")" = NONE || return 1
  test "$(mesh_control "GET_NETWORK $open_network mesh_fwding")" = 0 || return 1
  test "$(mesh_control "GET_NETWORK $open_network frequency")" = {saved['frequency']} || return 1
  open_ssid=$(mesh_control "GET_NETWORK $open_network ssid") || return 1
  test "$(printf '%s' "$open_ssid" | sha256sum | cut -d ' ' -f 1)" = {name_hash}
}}
open_joined() {{
  mesh_identity && open_id || return 1
  test "$(cat {net}/carrier)" = 1 || return 1
  test "$(iw dev {interface} get mesh_param mesh_fwding)" = 0 || return 1
  test -z "$(ip -o addr show dev {interface})" || return 1
  test ! -e {net}/master || return 1
  mesh_status=$(mesh_control STATUS) || return 1
  printf '%s\\n' "$mesh_status" | grep -Fxq 'wpa_state=COMPLETED' &&
  printf '%s\\n' "$mesh_status" | grep -Fxq "id=$open_network" &&
  printf '%s\\n' "$mesh_status" | grep -Fxq 'freq={saved['frequency']}'
}}
open_limited() {{
  test "$(mesh_control 'GET max_peer_links')" = {PEER_LIMIT} &&
  test "$(mesh_control 'GET mesh_max_inactivity')" = {PEER_IDLE_SECONDS} &&
  test "$(iw dev {interface} get mesh_param mesh_max_peer_links)" = {PEER_LIMIT} &&
  test "$(iw dev {interface} get mesh_param mesh_plink_timeout)" = "{PEER_IDLE_SECONDS} seconds"
}}
open_join() {{
  original_isolated && open_profile || return 1
  test "$(mesh_control 'SET max_peer_links {PEER_LIMIT}')" = OK || return 1
  test "$(mesh_control 'SET mesh_max_inactivity {PEER_IDLE_SECONDS}')" = OK || return 1
  test "$(mesh_control "MESH_GROUP_ADD $open_network")" = OK || return 1
  for open_attempt in $(seq 1 {wifi_mesh.JOIN_ATTEMPTS}); do
    if open_joined; then
      # OpenWrt reapplies saved kernel settings at COMPLETED; limit them after it.
      iw dev {interface} set mesh_param mesh_max_peer_links {PEER_LIMIT} || return 1
      iw dev {interface} set mesh_param mesh_plink_timeout {PEER_IDLE_SECONDS} || return 1
      open_profile && open_joined && open_limited
      return $?
    fi
    sleep 1
  done
  return 1
}}
open_begin() {{
  mesh_profile && mesh_joined && open_original_caps || return 1
  test ! -f {directory}/open-armed || return 1
  touch {directory}/open-armed
  echo creating >{directory}/open-phase
  open_network=$(mesh_control ADD_NETWORK) || return 1
  case "$open_network" in ''|*[!0-9]*) return 1;; esac
  test "$open_network" != {original} || return 1
  printf '%s\\n' "$open_network" >{directory}/open-id
  test "$(mesh_control "SET_NETWORK $open_network id_str {owner.encode().hex()}")" = OK || return 1
  for open_setting in 'mode 5' 'key_mgmt NONE' 'mesh_fwding 0' \\
      'frequency {saved['frequency']}' 'ssid {name.encode().hex()}'; do
    test "$(mesh_control "SET_NETWORK $open_network $open_setting")" = OK || return 1
  done
  open_profile || return 1
  echo joining >{directory}/open-phase
  test "$(mesh_control 'MESH_GROUP_REMOVE {interface}')" = OK || return 1
  open_join || return 1
  echo active >{directory}/open-phase
}}
open_resume() {{
  test "$(cat {directory}/open-phase)" = active || return 1
  open_join
}}
open_restore_original() {{
  mesh_saved_profile && open_caps_owned || return 1
  open_phase=$(cat {directory}/open-phase) || return 1
  case "$open_phase" in creating|joining|active|restoring) ;; *) return 1;; esac
  if open_id; then
    if mesh_control LIST_NETWORKS | awk -F '\\t' -v own="$open_network" 'NR > 1 && $1 == own {{ found=1 }} END {{ exit !found }}'; then
      # Even a partially configured profile requires its unique ownership tag.
      open_owner && open_networks || return 1
      open_remove=1
    else
      test "$open_phase" = restoring || return 1
      mesh_profile || return 1
      open_remove=0
    fi
  else
    # ADD_NETWORK may have succeeded without returning its ID. Do not guess.
    test "$open_phase" = creating && mesh_profile && mesh_joined || return 1
    open_remove=0
  fi
  echo restoring >{directory}/open-phase
  if ! mesh_joined; then
    test "$(mesh_control 'MESH_GROUP_REMOVE {interface}')" = OK || return 1
  fi
{globals_restore}
  if ! mesh_joined; then
    test "$(mesh_control 'MESH_GROUP_ADD {original}')" = OK || return 1
  fi
  for open_attempt in $(seq 1 {wifi_mesh.JOIN_ATTEMPTS}); do
    if mesh_joined; then break; fi
    sleep 1
  done
  mesh_joined || return 1
{kernel_restore}
  if [ "$open_remove" = 1 ]; then
    open_owner || return 1
    test "$(mesh_control "REMOVE_NETWORK $open_network")" = OK || return 1
  fi
  mesh_profile && mesh_joined && open_original_caps || return 1
  rm -f {directory}/open-armed {directory}/open-id {directory}/open-phase {directory}/mesh-down
}}
"""
