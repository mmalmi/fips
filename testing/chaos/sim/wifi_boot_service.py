"""Temporarily select one paid account for the installed OpenWrt boot service."""

import json
from pathlib import Path

from .paid_settlement import require
from .wifi_remote import Router, digest


INIT = '/etc/init.d/fips-relay'
UCI = '/etc/config/fips-relay'
WRAPPER = '/usr/libexec/fips-relay-openwrt'
PROC = '/proc'


def restore_script(node, saved_hash):
    """Refuse changed configuration or service ownership before any mutation."""
    return f'''#!/bin/sh
set -eu
parent={node.parent}
test -f "$parent/boot-armed" || exit 0
test "$(sha256sum <"$parent/boot-uci")" = "{saved_hash}  -"
test -z "$(uci changes fips-relay)"
current=$(sha256sum <{UCI})
original='{saved_hash}  -'
armed=$(cat "$parent/boot-armed")
test "$current" = "$original" || test "$current" = "$armed"
service_command() {{
  value=$(ubus call service list '{{"name":"fips-relay"}}') || return 1
  printf '%s' "$value" | jsonfilter -e '@["fips-relay"].instances.main.command[*]' || [ "$?" = 1 ]
}}
command=$(service_command)
candidate=$(printf '%s\\n' {WRAPPER} {node.original_binary} {node.config})
saved=$(printf '%s\\n' {WRAPPER} {node.original_binary} {node.original_config})
test -z "$command" || test "$command" = "$candidate" || test "$command" = "$saved"
paid_process_running() {{
  expected=$(printf '%s\\n' {node.original_binary} run {node.config})
  for file in {PROC}/[0-9]*/cmdline; do
    [ -r "$file" ] || continue
    actual=$(tr '\\000' '\\n' <"$file" 2>/dev/null || :)
    [ "$actual" != "$expected" ] || return 0
  done
  return 1
}}
case "${{1:-}}" in
  stop) test "$current" = "$armed"; test -z "$command" || test "$command" = "$candidate";;
  restore) :;;
  *) exit 1;;
esac
if [ "$command" = "$candidate" ]; then
  {INIT} stop
fi
stopped=0
for attempt in $(seq 1 70); do
  remaining=''
  if [ "$command" != "$saved" ]; then
    remaining=$(service_command)
    test -z "$remaining" || test "$remaining" = "$candidate"
  fi
  if [ -z "$remaining" ] && ! paid_process_running; then stopped=1; break; fi
  sleep 1
done
test "$stopped" = 1
if [ "$1" = restore ]; then
  if [ "$current" != "$original" ]; then
    cp "$parent/boot-uci" "$parent/boot-restoring"
    test "$(sha256sum <{UCI})" = "$current"
    mv "$parent/boot-restoring" {UCI}
  fi
  test "$(sha256sum <{UCI})" = "$original"
  if [ "$command" != "$saved" ]; then {INIT} start; fi
  rm -f "$parent/boot-armed"
fi
'''.encode()


class BootRouter(Router):
    """The client/lease remains in RAM; procd executes the installed binary."""

    boot_observed = False

    def prepare(self, binary, config):
        source = Path(__file__).resolve().parents[3] / 'crates/fips-relay/openwrt'
        for local, remote in ((source / 'fips-relay.init', INIT),
                              (source / 'fips-relay-openwrt', WRAPPER),
                              (source / '90-fips-relay-ntp', '/etc/hotplug.d/ntp/90-fips-relay')):
            require(self.remote(['sha256sum', remote]).decode().split()[0] == digest(local.read_bytes()),
                    'installed boot integration differs from the source under test')
        require(self.remote(['sha256sum', self.original_binary]).decode().split()[0] == digest(binary),
                'installed service binary differs from the candidate')
        self.remote('set -eu; ' + INIT + ' enabled; test -z "$(uci changes fips-relay)"')
        super().prepare(binary, config)
        saved = self.remote(['cat', UCI])
        self.write(self.parent + '/boot-uci', saved)
        self.write(self.parent + '/boot-service.sh', restore_script(self, digest(saved)))
        selected = ("config relay 'main'\n\toption enabled '1'\n"
                    f"\toption executable '{self.original_binary}'\n\toption config '{self.config}'\n")
        self.write(self.parent + '/boot-selected', selected.encode())

    def guard_script(self):
        script = super().guard_script()
        hook = (f'  if [ -f {self.parent}/boot-service.sh ]; then\n'
                f'    sh {self.parent}/boot-service.sh restore\n  fi\n').encode()
        require(script.count(b'  stop_candidate\n') == 1, 'guard cleanup boundary changed')
        return script.replace(b'  stop_candidate\n', hook + b'  stop_candidate\n')

    def arm_boot(self):
        # Only the next boot changes service ownership; the current instance stays up.
        self.guarded(f'''test "$(sha256sum <{UCI})" = "$(sha256sum <{self.parent}/boot-uci)"
test -z "$(uci changes fips-relay)"
test ! -f {self.parent}/boot-armed
sha256sum <{self.parent}/boot-selected >{self.parent}/boot-armed
cp {self.parent}/boot-selected {self.parent}/boot-applying
test "$(sha256sum <{UCI})" = "$(sha256sum <{self.parent}/boot-uci)"
mv {self.parent}/boot-applying {UCI}
sync
''')

    def observe_service(self):
        """Observe the daemon before creating a RAM guard or issuing a start."""
        service = json.loads(self.remote(['ubus', 'call', 'service', 'list',
                                         json.dumps({'name': 'fips-relay'})]))
        instance = service.get('fips-relay', {}).get('instances', {}).get('main', {})
        require(instance.get('running') and type(instance.get('pid')) is int,
                'installed boot service is not running')
        require(instance.get('command') == [WRAPPER, self.original_binary, self.config],
                'installed service is not configured for the original paid account')
        pid = instance['pid']
        require(pid > 1, 'invalid supervised process')
        self.remote(f'''set -eu
test -f /var/run/fips-relay.time-valid
test "$(readlink /proc/{pid}/exe)" = {self.original_binary}
test "$(sha256sum </proc/{pid}/cmdline)" = "$(printf '%s\\000' {self.original_binary} run {self.config} | sha256sum)"
test "$(sha256sum <{UCI})" = "$(cat {self.parent}/boot-armed)"
test -z "$(tr '\\000' '\\n' </proc/{pid}/environ | sed -n 's/^RUST_LOG=//p')"
''')
        status = json.loads(self.remote([self.original_binary, 'ctl', self.config], b'{"type":"status"}'))
        require(status['npub'] == self.npub, 'boot changed the paid identity')
        return {'instance': instance, 'status': status, 'logging': 'default warn'}

    def stop(self):
        if self.boot_observed:
            self.guarded(f'sh {self.parent}/boot-service.sh stop', timeout=90)
        super().stop()

    def cleanup(self):
        if not self.guard_ready and self.created:
            # A failed boot can leave procd owning the account with no RAM guard.
            self.remote(['sh', self.parent + '/boot-service.sh', 'restore'], timeout=90)
        super().cleanup()
