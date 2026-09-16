# Payment and checkpoint cadence

The adaptive scheduler batches cumulative payments per neighbor channel and
paying direction. It uses the existing buyer's local priced submission evidence
and durable signed liability. It does not add a receipt protocol, change the
billing tariff, grant an advance or authorize purchases.

## Configuration

The optional top-level service setting is local runtime policy:

```json
{
  "payment_cadence": {
    "max_delay_ms": 500,
    "unpaid_percent": 50
  }
}
```

Omission selects those defaults. The allowed ranges are 50–10,000 ms and 1–75%
respectively. This setting is outside saved financial terms; changing it on
restart does not change price, grace, capacity, budgets or channel history.
Default serialization omits the field, preserving old customer profile configs.
An older executable cannot read a configuration with the explicit new field.

Every 50 ms the local scheduler checks active channel evidence. A channel gets
one initial reconciliation on startup or first use. Subsequently it requests
usage and, when needed, sends a signed cumulative payment when either:

- Evidence or an unacknowledged signed liability exceeds acknowledged payment
  by `unpaid_percent` of the channel's agreed grace; or
- New outstanding liability reaches `max_delay_ms` in age.

The first trigger uses monetary value, not a universal byte count. All flows
sharing the same neighbor channel share the trigger. Whole-sat payment rounding
can cover later fractional usage, which should not cause another payment.
Confirmed idle channels send no payment-control polls. Outstanding local evidence
that the provider has not claimed remains reconcilable; it is not declared paid
just to make the connection quiet.

After a failed exchange the scheduler retries after 500 ms without requiring
another data packet. Its cache contains no financial authority and is discarded
on restart; the durable buyer/seller journals remain authoritative. Explicit
flush and settlement paths still reconcile regardless of normal cadence.

`max_delay_ms` is a scheduling target, not a bound on network or disk latency.
The scan adds up to 50 ms, and control, signing or disk work can delay it.
Each channel has its own payment worker, bounded by the existing 16-channel
account limit. A network await on one channel does not block payment checks or
exchanges for another. Payment and settlement share a lock only for the same
channel; queued work rechecks that the channel is still active before signing.
The wallet and journal writers remain serialized for financial consistency.
Existing hard credit, window and budget gates can stop forwarding regardless of
the selected timing.
The nominal grace threshold also does not model the exact residual allowance
lost to earlier crash exposure; safe low-credit latency prediction remains work.

Graceful runtime shutdown drains the in-flight exchanges. Forced cancellation
aborts owned network tasks even if a drain was already waiting; it cannot detach
them to keep acting after controller ownership is returned. Already-started
blocking disk work retains its existing locks until completion. Durable financial
intents still require the existing recovery procedures. The explicit flush visits
all selected channels before returning; unrelated background workers keep running
while it waits. Route recovery and renewal are separate workers and do not yet
have a demonstrated fairness bound under many simultaneous unavailable peers.

The shared control transport keeps the existing 32 total / four-per-peer TCP
connection limits. Up to 16 live outgoing requests, including queued requests,
may wait within the existing 30-second deadline. A full peer's slots do not block
another peer's connection attempt. Only a pre-connection capacity refusal is
retried, at most every 50 ms; no transmitted RPC is replayed by this queue.
Canceled queued requests are discarded before transmission. This also handles
the short period when successfully closed streams still occupy TCP slots.

## Independent durable windows

A separate local worker scans saved forwarding windows every 50 ms. Once new
reservations consume at least half a window, it checkpoints before publishing
more allowance. No new reservation means no periodic checkpoint write. The
worker cannot create credit or exceed the existing reservation limit, and a
crash still consumes the unrecorded persisted window as unbilled exposure.

Usage replies still checkpoint before reporting claims, and verified balance
updates still persist before exposing credit. Those durability requirements are
independent of the decision to ask for another payment. Forwarding callbacks
continue using only the previously persisted allowance while disk work runs.

Window and grace must cover the desired bursts and actual control/disk delays
at the aggregate price. Merely selecting a longer payment interval can exhaust
credit. There is no automatic increase of unpaid exposure to hide such drops.

## Verification and measurement scope

Focused tests cover idle suppression, value-triggered payments, deadlines,
whole-sat quantization, independent schedules, failed-exchange retries, retained
signed liability and compatible configuration. A durable integration check
advances a window with no payment and then proves crash exposure is preserved.
The actual customer/mint test checks payment-control counters remain unchanged
during an idle period after paid delivery and app reopen; final settlement still
conserves funds. Multi-process tests exercise paid traffic and router recovery.

The first milestone passed 43 focused tests: 21 library, two customer lifecycle,
12 durable-accounting, three multi-process service and five controller tests.
Controller cases include route repricing, automatic renewal, recovery with an
evidence gap and bidirectional payments. Strict relay Clippy, the production
library/binary check, Android ARM64 app Clippy, formatting and source-size checks
also passed. The changed runtime has not yet been deployed to the physical bench.

The subsequent slow-neighbor regression holds real payment and settlement control
requests in a five-node, test-mint scenario. It requires repeated paid deliveries
through the healthy neighbor during both holds, retains unresolved capital, then
releases the requests and completes normal account settlement/conservation. This
models a delayed control path, not physical radio movement or permissionless
discovery. A cancellation check also covers an interrupted graceful drain.
A real three-node control test fills one neighbor's four slots, cancels an
unsent queued request, completes another neighbor's request, then proves the
remaining queued request connects once a slot is released. All seven control
transport integration cases pass, including existing customer isolation checks.

Probe delivery and timing validity are independent checks. Every expected packet
must arrive in the local long-stream regression, while each one-way timestamp is
either accepted into the latency histogram or counted as invalid. Wall clocks
can change even on a single host. Rejected timestamps stay visible and do not
become fabricated delay samples; usable one-way timing still requires the stated
clock assumption. This measurement check does not relax packet delivery counts.

The independent-worker milestone passed 43 focused tests: 22 library, seven
control-transport, three probe, two customer, three multi-process service and six
controller cases. Strict relay Clippy, Android ARM64 app Clippy, production
library/binary checks, formatting and the source-size gate passed. The physical
routers still run the earlier build; no hardware speedup or ad hoc radio joining
is claimed by these software checks.

No new CPU or throughput saving is claimed by these checks. The next measurement
must compare 250/500/1000/2000-ms policies with identical terms and workloads,
including idle, burst, high-rate and impaired links. Count payment messages,
crypto work, storage writes and complete wire overhead separately. The older
[performance report](PERFORMANCE.md) is a baseline for the former fixed polling
implementation, not a measurement of this scheduler.
