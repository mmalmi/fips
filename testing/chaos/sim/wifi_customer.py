"""Owned customer entry/mint exceptions under the existing radio guard lease."""

import ipaddress
import json
import shlex
from urllib.parse import urlsplit

from .wifi_remote import checked_name


CHAINS = {"udp": "input_fips_customer", "tcp": "forward_fips_customer", "snat": "srcnat_lan"}


def guard_helpers(directory, owner):
    """Fixed guard code; intent files are data, never sourced as shell code."""
    status = "\n".join(f'''  {kind}=false
  if [ -f {directory}/customer-{kind}.rule ]; then
    handle=$(customer_handle {kind} {chain}) || return 1
    test -z "$handle" || {kind}=true
  fi''' for kind, chain in CHAINS.items())
    return f"""
customer_handle() {{
  kind=$1; chain=$2
  expected=$(cat {directory}/customer-$kind.rule) || return 1
  token='comment "{owner}-customer-'$kind'"'
  case "$expected" in *"$token") ;; *) return 1;; esac
  nft -a -nn list chain inet fw4 "$chain" >{directory}/customer-current || return 1
  found=$(awk -v expected="$expected" -v token="$token" '
    {{ line=$0; sub(/^[[:space:]]+/, "", line)
      if (index(line, token)) {{
        count++; clean=line; sub(/[[:space:]]+# handle [0-9]+$/, "", clean)
        if (clean != expected || line !~ /# handle [0-9]+$/) bad=1
        handle=line; sub(/^.*# handle /, "", handle)
      }}
    }}
    END {{ if (bad || count > 1) exit 1; if (count == 1) print handle }}' {directory}/customer-current) || return 1
  saved=$(cat {directory}/customer-$kind.handle 2>/dev/null || :)
  if [ -n "$saved" ] && [ "$saved" != "$found" ]; then
    # A replaced/comment-changed rule is foreign; never delete its reused handle.
    test -z "$found" || return 1
    if grep -Eq "# handle $saved$" {directory}/customer-current; then return 1; fi
  fi
  printf '%s\\n' "$found"
}}
customer_remove() {{
  kind=$1; chain=$2
  test -f {directory}/customer-$kind.rule || return 0
  handle=$(customer_handle "$kind" "$chain") || return 1
  if [ -n "$handle" ]; then
    nft delete rule inet fw4 "$chain" handle "$handle" || return 1
  fi
  handle=$(customer_handle "$kind" "$chain") || return 1
  test -z "$handle" || return 1
  rm -f {directory}/customer-$kind.rule
}}
customer_cleanup() {{
  test -f {directory}/customer-intent || return 0
  customer_failed=0
  customer_remove udp {CHAINS['udp']} || customer_failed=1
  if [ "$(cat {directory}/customer-release 2>/dev/null || :)" = '{owner}' ]; then
    customer_remove tcp {CHAINS['tcp']} || customer_failed=1
    customer_remove snat {CHAINS['snat']} || customer_failed=1
  else
    touch {directory}/customer-mint-retained
  fi
  if [ "$customer_failed" != 0 ]; then
    touch {directory}/customer-cleanup-failed
    return 1
  fi
  rm -f {directory}/customer-cleanup-failed
  if [ ! -f {directory}/customer-tcp.rule ] && [ ! -f {directory}/customer-snat.rule ]; then
    rm -f {directory}/customer-intent {directory}/customer-mint-retained
  fi
}}
customer_status() {{
{status}
  retained=false; failed=false
  test ! -f {directory}/customer-mint-retained || retained=true
  test ! -f {directory}/customer-cleanup-failed || failed=true
  printf '{{"udp_rule":%s,"tcp_rule":%s,"snat_rule":%s,"mint_access_retained":%s,"cleanup_failed":%s}}\\n' "$udp" "$tcp" "$snat" "$retained" "$failed"
}}
customer_bind() {{
  for pair in 'udp {CHAINS['udp']}' 'tcp {CHAINS['tcp']}' 'snat {CHAINS['snat']}'; do
    set -- $pair
    handle=$(customer_handle "$1" "$2") || return 1
    test -n "$handle" || return 1
    printf '%s\\n' "$handle" >{directory}/customer-$1.handle
  done
}}
"""


class CustomerAccess:
    def __init__(self, router, guest_interface, guest_cidr, entry_port, mint_url):
        self.router = router
        self.guest_interface = checked_name(guest_interface)
        self.guest = ipaddress.IPv4Interface(guest_cidr)
        parsed = urlsplit(mint_url)
        mint = ipaddress.IPv4Address(parsed.hostname)
        if (self.guest_interface in (router.interface, router.management)
                or self.guest.ip in (self.guest.network.network_address, self.guest.network.broadcast_address)
                or parsed.scheme != "http" or not parsed.port or parsed.username or parsed.password
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment
                or not mint.is_private or mint.is_loopback or mint.is_unspecified or mint.is_multicast
                or mint in self.guest.network
                or type(entry_port) is not int or not 1024 <= entry_port <= 65535):
            raise ValueError("customer access requires separate explicit guest and private mint endpoints")
        self.mint_url = f"http://{mint}:{parsed.port}"
        self.owner = router.table_owner
        if not self.owner.startswith("fips-wifi-owner-") or not self.owner[16:].isalnum():
            raise ValueError("customer access requires the router's original guard owner")
        source = f'ip saddr {self.guest.network}'
        guest = f'iifname "{self.guest_interface}" {source}'
        target = f'ip daddr {mint} tcp dport {parsed.port}'
        self.rules = {
            "udp": f'{guest} ip daddr {self.guest.ip} udp dport {entry_port} accept',
            "tcp": f'{guest} {target} accept',
            "snat": f'oifname "{router.management}" {source} {target} masquerade',
        }
        self.rules = {kind: rule + f' comment "{self.owner}-customer-{kind}"'
                      for kind, rule in self.rules.items()}
        self.info = {"owner": self.owner, "mint_url": self.mint_url,
                     "guest_interface": self.guest_interface, "guest_cidr": str(self.guest),
                     "entry_port": entry_port, "guard_directory": router.temporary}

    def enable(self):
        t = self.router.temporary
        commands = [f'test ! -e {t}/customer-intent', f'test ! -e {t}/customer-release',
                    f'test ! -e {t}/customer-mint-url',
                    f'ip -o -4 addr show dev {self.guest_interface} | '
                    f"awk '$3 == \"inet\" && $4 == \"{self.guest}\" {{ found++ }} END {{ exit found != 1 }}'"]
        for kind, chain in CHAINS.items():
            # No prior same-owner rule may be adopted, even if its terms match.
            commands += [f'nft -a -nn list chain inet fw4 {chain} >{t}/customer-before',
                         f'if grep -Fq {shlex.quote(self.owner + "-customer-")} '
                         f'{t}/customer-before; then exit 1; fi',
                         f'test ! -e {t}/customer-{kind}.rule']
        commands.append('set -C')
        commands.append(f'printf "%s\\n" {shlex.quote(self.mint_url)} >{t}/customer-mint-url')
        for kind, rule in self.rules.items():
            commands.append(f'printf "%s\\n" {shlex.quote(rule)} >{t}/customer-{kind}.rule')
        # The complete intent precedes the atomic kernel transaction. An uncertain
        # response can therefore be cleaned without retrying rule insertion.
        commands += [f'touch {t}/customer-intent', 'nft -f -']
        batch = '\n'.join(f'insert rule inet fw4 {CHAINS[kind]} {rule}'
                          for kind, rule in self.rules.items()) + '\n'
        self.router.guarded('\n'.join(commands), batch.encode())
        self.router.remote(["sh", t + "/guard.sh", "customer-bind"])
        state = self.observe()
        if not all(state[kind + "_rule"] for kind in CHAINS):
            raise RuntimeError("customer exceptions were not installed exactly")
        return state

    def observe(self):
        t = self.router.temporary
        # Read-only observation remains available after the lease has expired.
        result = self.router.remote(["sh", t + "/guard.sh", "customer-status"])
        state = json.loads(result)
        self.info.update(state)
        return self.info

    def release_mint(self, terminal_report):
        """RemoteMint must prove terminal process exit before issuing this report."""
        issued, collected = terminal_report.get("issued_sat"), terminal_report.get("collected_sat")
        if (terminal_report.get("url") != self.mint_url
                or any(terminal_report.get(key) is not True for key in ("test_only", "conserved", "stopped"))
                or type(issued) is not int or type(collected) is not int or issued < 0 or issued != collected):
            raise ValueError("mint access requires the pinned mint's terminal conserved report")
        t = self.router.temporary
        # This terminal, removal-only decision may follow lease expiry. Never
        # write it from a reusable zero-issued report while the mint can issue.
        self.router.remote(f"set -eu; exec 9>{t}/operation.lock; flock -x 9; "
                           f"test \"$(cat {t}/customer-mint-url)\" = {shlex.quote(self.mint_url)}; "
                           f"test -f {t}/customer-intent || "
                           f"test \"$(cat {t}/customer-release 2>/dev/null || :)\" = {shlex.quote(self.owner)}; "
                           f"printf '%s\\n' {shlex.quote(self.owner)} >{t}/customer-release.new; "
                           f"mv {t}/customer-release.new {t}/customer-release")
        self.router.remote(["sh", t + "/guard.sh", "customer-cleanup"])
        state = self.observe()
        if state["tcp_rule"] or state["snat_rule"] or state["cleanup_failed"]:
            raise RuntimeError("owned mint access remains after terminal release")
        return state
