# Local UDP customer entry

Customer entry is opt-in. It lets a previously unconfigured customer use the
existing FIPS quote, acceptance and payment services over a direct UDP link.
The customer still funds its own channel and authorizes its sending direction.
Joining the network or requesting a quote creates no forwarding allowance and
does not authorize spending from the router's wallet.

## Configuration

Add a customer subnet to a relay's service configuration, and bind UDP to its
specific address on that subnet. For example, with documentation addresses:

```json
{
  "transports": {
    "udp": {"bind_addr": "192.0.2.1:39211", "advertise_on_nostr": false}
  },
  "customer_network": "192.0.2.0/24"
}
```

These fields supplement the rest of the service configuration. The chosen
address must exist on the host. A missing UDP listener, wildcard bind, multicast
address, default route or listener outside the customer subnet is rejected.
IPv4 and IPv6 subnets are supported. Omit `customer_network` to keep the existing
configured-neighbor behavior. Changing network settings never resets saved
financial terms, channel history, capital or lifetime spending limits.

`neighbors` continues to identify the peers from which the router may buy onward
service. Do not add arbitrary customers to that list to permit incoming payment
requests. A new customer only needs the entry's public identity and UDP address
to establish its authenticated link. It also needs the intended destination,
accepted mint and its own explicit price/budget limits before purchasing a route.
An invitation or local profile can carry those public bootstrap details.

## Admission and financial boundaries

Each new customer control connection must match a currently authenticated,
connected UDP peer whose observed address lies in `customer_network`. A remote
end-to-end FIPS session arriving through another router is insufficient. The
request body's claimed identity or address is not used to establish this access.
Configured neighbors retain their existing access, including over native Wi-Fi.

Customer entry enables the existing three FIPS control ports for quotes,
acceptance/settlement and payment updates. They are carried inside authenticated
FIPS over the configured UDP listener; they are not host TCP listeners. Private
operator and native-management sockets remain inside the protected state directory.

Each control service admits at most eight simultaneous customer exchanges within
its existing 32-connection application limit. Customer requests share a token
bucket with a burst of 16 and refill of one per 100 ms, as well as individual
identity buckets. Identity churn cannot grow the 64-entry customer bucket map or
reset the shared bucket. Records remain capped at 64 KiB with 30-second exchange
deadlines and bounded queues. These are resource bounds, not a denial-of-service
availability guarantee.

Customer-mode native limits are also finite: the configured neighbor count plus
16 authenticated peers, twice that number of links/handshake connections, 16
pending inbound handshakes and 128 sessions. Existing native handshake and session
rate limits still apply. These prototype limits are fixed rather than additional
operator tuning settings.

Admission permits a request to reach its existing handler. It does not bypass
offer validation, authenticated payer binding, mint/funding verification, local
buyer evidence, account capacity or lifetime budgets. Incoming service payments
do not grant permission to initiate purchases from an unconfigured provider.
Return traffic requires its own sender authorization; reception creates none.
This includes FIPS session replies: the destination must explicitly fund its
return route even when application data primarily travels toward it. A forward
purchase cannot authorize spending by the destination.

The [Android bench customer](../fips-relay-app/README.md) embeds this same service
and provides profile preview, funding, purchase, traffic and settlement controls.

## Wi-Fi and mint bootstrap

The service does not configure Wi-Fi, DHCP, firewall rules or Internet forwarding.
For the physical customer flow, put the customer SSID on an isolated subnet and
allow only the local bootstrap services, the selected FIPS UDP listener and a
bounded route to the accepted test mint. Keep management LAN services unreachable
from that subnet. The mint path must work before an ordinary Internet purchase;
otherwise a customer cannot fund or recover its forwarding channel independently.

Ordinary Internet entitlement remains a separate service. Do not convert a FIPS
payment into an unrestricted firewall allowance. The phone client, isolated SSID,
mint bootstrap and physical isolation passed the bounded three-router/Pixel run;
see [the acceptance report](PROTOTYPE-RESULTS.md) for scope and limitations.

## Verification

```sh
cargo test -p fips-relay --lib --test control_transport --test service
```

Control tests exercise an unconfigured direct UDP customer, a rejected address
outside the allowed subnet, explicit-neighbor access, rejection of a proven
multi-hop session as a direct customer, and the customer connection cap while a
configured neighbor remains serviceable. They also verify that incoming customer
access cannot initiate an outbound purchase.

The forwarding-attempt process scenario omits the customer from the first router's
configured neighbors. It first checks that unpaid traffic opens no channels and
arrives nowhere. The customer then purchases traffic through three independently
paid relays; both sending directions, long streams, process restart, middle-router
crash and final test-mint settlement use the existing service implementation.
Peer checks compare exact connected identities against the intended line.

These software checks complement the subsequent physical customer Wi-Fi and
phone demonstration in [the acceptance report](PROTOTYPE-RESULTS.md).
