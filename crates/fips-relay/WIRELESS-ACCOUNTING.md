# Wireless forwarding-attempt accounting

The r5 package built from `a360eb634ec441b2a7ae41115440867e6f4dc479` removes
the completed-packet history ceiling for explicitly agreed forwarding-attempt
accounts. Five new test accounts exercised the same three OpenWrt relays and
two isolated endpoints. The endpoints shared one host clock; inter-router
traffic used native FIPS frames over isolated 5 GHz Wi-Fi. The middle relay had
no UDP transport. Connected FIPS peers matched the intended line before and
after every stream, and kernel mesh forwarding remained disabled.

## Delivered traffic

All application payloads were 1,000 bytes. These are paced offered rates, not
maximum-throughput measurements. Each stream lasted at most 24 seconds; gaps
between streams allowed observations and rearming the receiver.

| Direction | Offered rate | Packets sent / received | Mean one-way delay | p95 histogram bound |
|---|---:|---:|---:|---:|
| Forward | 2 Mbit/s | 6,000 / 6,000 | 4.533 ms | 10 ms |
| Reverse | 2 Mbit/s | 6,000 / 6,000 | 4.437 ms | 10 ms |
| Forward | 4 Mbit/s | 12,000 / 12,000 | 5.001 ms | 10 ms |
| Reverse | 4 Mbit/s | 12,000 / 12,000 | 4.651 ms | 10 ms |
| Forward | 8 Mbit/s | 12,000 / 12,000 | 6.370 ms | 20 ms |
| Reverse | 8 Mbit/s | 12,000 / 12,000 | 6.034 ms | 20 ms |

These six streams had no missing or duplicate application packets. They crossed
the old 4,096-record ceiling without raising it or resetting any account.

## Renewal and recovery

The sources had explicit automatic renewal at 80% of a 128-test-sat channel.
Another 6,000 packets each way triggered one replacement source channel in each
direction. Histories retained the original channels, lifetime budgets decreased,
and each source returned to 128 test sats of locked capital after refund recovery.
The other four neighbor channels were reused.

The streams spanning renewal delivered 5,649/6,000 forward and 5,516/6,000 reverse.
The current stop/settle/fund/accept sequence permits a service interruption;
renewal is not lossless. A subsequent 1,000-packet stream in each direction
delivered all packets without another purchase command. In total, 73,165 of
74,000 submitted application packets arrived across ten measured streams.
Application sequence counts do not prove the exact duration or location of
every individual drop. Delivery receipts remain optional.

## CPU, memory and accounting size

CPU cost is process user-plus-system CPU seconds divided by GiB of application
data successfully received. Tick frequency was read from each Linux process's
auxiliary vector. This includes the relay's control work and the observation
window, including a short drain period. It excludes work charged to other
processes and does not measure whole-device energy. Host load was also recorded;
unrelated services remained available.

At 8 Mbit/s, individual relays consumed 772–905 process CPU seconds per GiB
delivered. Their sampled utilization was 64.3–80.3% of one CPU core and sampled
resident memory was 17.55–18.66 MiB. At 2 Mbit/s the corresponding CPU cost was
1,120–1,315 seconds/GiB: fixed control and observation costs are amortized over
fewer bytes. Comparisons must hold path, direction, offered rate, packet size,
loss and observation method constant. These results are an optimization baseline,
not a speedup claim for the subsequent module refactor.

Stopped buyer journals were at most 2,402 bytes; stopped seller journals were at
most 3,144 bytes. All completed packet records were absent and cumulative totals
remained. This excludes wallet, funding and other service files. Contract/channel
history still has separate limits; removing the packet ceiling does not establish
indefinite operation through unbounded renewals or route changes.

## Settlement and preserved services

All eight channel generations settled. Starting wallets each held 512 test sats;
final balances were `[400, 587, 586, 587, 400]`. Relay net earnings were therefore
75, 74 and 75 test sats. All 2,560 test sats were collected through the same
isolated mint, leaving participant wallets empty. Across bench phases the mint
reported 8,960 issued and collected test sats. Its Lightning backend is simulated.

Original router accounts were restored on r5 with unchanged identities, histories
and remaining budgets. Stopped-account backups preserve the older journal formats.
Network, Wi-Fi, DHCP and firewall files matched those backups; isolated native
peering, stable radio addresses, AP operation, DNS/HTTPS, boot enablement and
the existing endpoint-host web service passed final checks. All test endpoints
were stopped and only this run's verified temporary package files were removed.

The executable is 20,012,448 bytes and the APK is 9,324,799 bytes. The r5 checks
do not repeat the earlier r3 full-router reboot experiment. Public customer UDP
entry, the unrooted-phone demonstration, broader financial recovery cases and
profiling-guided optimization remain separate work.
