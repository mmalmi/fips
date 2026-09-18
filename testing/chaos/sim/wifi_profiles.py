"""Isolated relay profiles sharing one router's executable and recovery lease."""

import json
import shlex


class RelayCommands:
    def control(self, kind, original=False, action="ctl", **fields):
        binary = self.original_binary if original else self.binary
        config = self.original_config if original else self.config
        return json.loads(self.remote([binary, action, config],
                                     json.dumps({"type": kind, **fields}).encode(), timeout=45))

    def native(self, command):
        return json.loads(self.remote([self.binary, "native", self.config],
                                     json.dumps(command).encode()))

    def start(self):
        self.remote(f"setsid sh {self.temporary}/start.sh </dev/null "
                    f">>{self.temporary}/process.log 2>&1 &")

    def monetary_journals(self):
        result = {name: json.loads(self.remote(["cat", self.state + "/" + path]))
                  for name, path in (("buyer", "buyer/buyer.json"),
                                     ("seller", "seller/ledger.json"),
                                     ("controller", "controller/controller.json"))}
        for field in ("selling_stopped", "renewals_paused", "watched_routes"):
            result["controller"].pop(field, None)
        return result


class AuxiliaryProfile(RelayCommands):
    def __init__(self, owner, name):
        self.owner = owner
        self.parent = owner.parent + "/aux-" + name
        self.state = self.parent + "/state"
        self.config = self.parent + "/config.json"
        self.temporary = owner.temporary + "/aux-" + name
        self.binary = owner.binary
        self.output = owner.output / ("aux-" + name)
        self.output.mkdir(mode=0o700)
        self.npub = None

    def remote(self, *args, **kwargs):
        return self.owner.remote(*args, **kwargs)

    def prepare(self, config):
        if config["state_directory"] != self.state:
            raise ValueError("auxiliary profile must use its own fresh account directory")
        owner = self.owner
        owner.guarded(shlex.join(["mkdir", "-m", "700", self.parent, self.temporary]))
        owner.guarded("umask 077; set -C; cat > " + shlex.quote(self.config),
                      json.dumps(config).encode())
        self.npub = owner.guarded(shlex.join([self.binary, "init", self.config]),
                                  timeout=45).decode().strip()
        owner.guarded("umask 077; set -C; cat > " + self.temporary + "/start.sh",
                      owner.start_script(self))


def process_helpers(router, stop_seconds):
    """Freeze the exact profile set into the guard before any process can start."""
    calls = "\n".join('  "$@" ' + shlex.join([profile.temporary + "/process.pid",
                                             profile.config, profile.temporary + "/start.sh"])
                      for profile in router.profiles())
    t = router.temporary
    return f"""
each_candidate() {{
{calls}
}}
owned_candidate() {{
  [ -f "$1" ] || return 1
  pid=$(cat "$1")
  case "$pid" in ''|*[!0-9]*|0|1) return 1;; esac
  [ -r /proc/$pid/cmdline ] || return 1
  actual=$(tr '\\000' '\\n' </proc/$pid/cmdline)
  expected=$(printf '%s\\n' {router.binary} run "$2")
  [ "$actual" = "$expected" ] && return 0
  expected=$(printf '%s\\n' sh "$3")
  [ "$actual" = "$expected" ]
}}
observe_candidate() {{
  if [ -n "$candidate_config" ] && [ "$candidate_config" != "$2" ]; then return 0; fi
  candidate_known=1
  if owned_candidate "$@"; then candidates_alive=1; fi
}}
candidates_running() {{
  candidate_config=${{1:-}}
  candidate_known=0
  candidates_alive=0
  each_candidate observe_candidate
  [ "$candidates_alive" = 1 ]
}}
signal_candidate() {{
  if owned_candidate "$@"; then kill -"$signal" "$pid" || :; fi
}}
stop_candidate() {{
  # Signal every profile before waiting; all share one bounded shutdown window.
  signal=TERM
  each_candidate signal_candidate
  for attempt in $(seq 1 {stop_seconds}); do
    candidates_running || return 0
    sleep 1
  done
  if candidates_running; then
    touch {t}/candidate-forced-stop
    signal=KILL
    each_candidate signal_candidate
    for attempt in $(seq 1 5); do
      candidates_running || return 0
      sleep 1
    done
  fi
  if candidates_running; then touch {t}/candidate-stop-failed; fi
}}
"""
