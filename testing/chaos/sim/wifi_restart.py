"""Crash one verified candidate while retaining its guard and persistent accounts."""

import shlex

from .wifi_remote import checked_path


def crash_profile(node, before_sample):
    """Signal once under the existing lease lock; an ambiguous reply stays failed."""
    if not isinstance(before_sample, dict) or not isinstance(before_sample.get("host_process"), dict):
        raise ValueError("crash requires a sampled candidate epoch")
    identity = before_sample.get("host_process", {})
    pid, start = identity.get("pid"), identity.get("start_ticks")
    if (not isinstance(node.npub, str) or not node.npub
            or before_sample.get("npub") != node.npub
            or type(pid) is not int or pid <= 1
            or type(start) is not int or start <= 0):
        raise ValueError("crash requires a matching sampled candidate epoch")
    temporary = shlex.quote(checked_path(node.temporary))
    binary = shlex.quote(checked_path(node.binary))
    config = shlex.quote(checked_path(node.config))
    # The primary and auxiliary profiles share their owner's lease/operation lock.
    owner = getattr(node, "owner", node)
    command = f"""set -efu
target_pid={pid}
target_start={start}
read_epoch() {{
  record=$(cat /proc/$target_pid/stat) || return 1
  test "${{record%% (*}}" = "$target_pid" || return 1
  tail=${{record##*) }}
  test "$tail" != "$record" || return 1
  set -- $tail
  test "$#" -ge 20 || return 1
  process_state=$1
  shift 19
  test "$1" = "$target_start"
}}
owned() {{
  test "$(cat {temporary}/process.pid)" = "$target_pid"
  test "$(readlink /proc/$target_pid/exe)" = {binary}
  actual=$(sha256sum </proc/$target_pid/cmdline)
  expected=$(printf '%s\\000' {binary} run {config} | sha256sum)
  test "$actual" = "$expected"
  read_epoch
  test "$process_state" != Z
}}
owned
# A four-second monotonic deadline leaves room below the five-second limit.
deadline=$(( $(cut -d . -f 1 /proc/uptime) + 4 ))
owned
kill -KILL "$target_pid"
while :; do
  if test ! -d /proc/$target_pid; then
    stopped=gone
    break
  fi
  if read_epoch; then
    if test "$process_state" = Z; then
      stopped=zombie
      break
    fi
  else
    # A reused PID or unreadable live epoch is never another signal target.
    test ! -d /proc/$target_pid
    stopped=gone
    break
  fi
  test "$(cut -d . -f 1 /proc/uptime)" -lt "$deadline"
  sleep .05
done
printf '%s\\000' "$target_pid" "$target_start" "$stopped"
"""
    raw = owner.guarded(command, timeout=10)
    parts = raw.decode("utf-8").split("\0")
    if (len(parts) != 4 or parts[-1] or parts[:2] != [str(pid), str(start)]
            or parts[2] not in ("gone", "zombie")):
        raise RuntimeError("crash response did not verify the sampled process stopped")
    return {"pid": pid, "start_ticks": start, "stopped": True, "state": parts[2]}
