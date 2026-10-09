"""Controlled Wi-Fi reconnection with an independent device restoration timer."""
import ipaddress
import re
import time
import uuid

from .paid_relay import eventually
from .paid_settlement import require
from .phone_diagnostics import native


def port(phone):
    adapters = native(phone, 'show_transports')['data']['transports']
    require(len(adapters) == 1 and adapters[0]['type'] == 'udp', 'unexpected phone carrier')
    value = int(adapters[0]['local_addr'].rsplit(':', 1)[1])
    require(0 < value <= 65535, 'unbound phone UDP port')
    return value


def reconnect(run, row):
    phone = run.phone
    require(':' not in phone.serial, 'radio changes require USB management')
    row['port_before'] = port(phone)
    row['wifi_before'] = phone.shell('cmd', 'wifi', 'status').decode()
    require('wifi is enabled' in row['wifi_before'].lower(), 'Wi-Fi must be enabled initially')
    token = uuid.uuid4().hex
    prefix = '/data/local/tmp/fips-reconnect-' + token
    row['guard_prefix'] = prefix
    run.save()
    # Re-enable Wi-Fi on the device even if the controller or USB disappears.
    script = f'''#!/system/bin/sh
sleep 45
if [ "$(cat {prefix}.armed 2>/dev/null)" = "{token}" ]; then
  svc wifi enable
  rm -f {prefix}.armed
fi
printf restored > {prefix}.done
'''
    install = f'''set -eu
umask 077
set -C
cat > {prefix}.sh <<'GUARD'
{script}GUARD
printf %s {token} > {prefix}.armed
nohup sh {prefix}.sh > {prefix}.log 2>&1 < /dev/null &
echo $!
'''
    row['guard_pid'] = int(phone.shell('sh', '-c', install).strip())
    row['started_at'] = time.monotonic()
    run.save()
    try:
        phone.shell('svc', 'wifi', 'disable')
        def disabled():
            value = phone.shell('cmd', 'wifi', 'status').decode()
            return value if 'wifi is disabled' in value.lower() else None
        row['wifi_disabled'] = eventually('Wi-Fi disabled through USB', disabled, 10)
        time.sleep(2)
    finally:
        phone.shell('svc', 'wifi', 'enable')
    def connected():
        value = phone.shell('cmd', 'wifi', 'status').decode()
        found = re.search(r'IP: /(\d+\.\d+\.\d+\.\d+)', value)
        if 'SSID: "' + run.customer['ssid'] + '"' not in value or found is None:
            return None
        ip = ipaddress.IPv4Address(found[1])
        subnet = ipaddress.IPv4Interface(run.customer['cidr'])
        return str(ip) if ip in subnet.network and ip not in (
            subnet.ip, subnet.network.network_address, subnet.network.broadcast_address) else None
    row['reconnected_source'] = eventually('original Wi-Fi and on-link entry restored', connected, 40)
    def rebound():
        current = port(phone)
        return current if current != row['port_before'] else None
    row['port_after'] = eventually('Android callback changes native UDP socket', rebound, 30)
    row['seconds_to_rebind'] = time.monotonic() - row['started_at']
    run.save()


def finish_guard(run, row):
    prefix = row['guard_prefix']
    def restored():
        return run.phone.shell('sh', '-c', f'cat {prefix}.done 2>/dev/null || true').strip() == b'restored'
    eventually('independent Wi-Fi restoration timer finished', restored, 50)
    run.phone.shell('sh', '-c', f'test ! -e {prefix}.armed; rm {prefix}.sh {prefix}.log {prefix}.done')
    row['guard_finished_and_removed'] = True
    run.save()
