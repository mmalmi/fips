# Multi-peer forwarding fairness benchmark

This production-like Linux Docker lab checks that one saturated transit peer
does not starve another peer or FIPS control traffic:

```text
A -- ab --\
           B -- bc -- C
D -- db --/
```

Each line is a distinct internal Docker bridge. A, C, and D have one underlay
each; only B is multi-homed. The topology verifier and six cross-underlay ping
probes fail closed if a leaf-to-leaf bypass exists.

Run it on an otherwise-idle Linux Docker host:

```sh
testing/forwarding/multipeer/benchmark.sh --build
```

The measured phase runs A→C TCP with eight streams while D concurrently sends
a 10 Mbit/s UDP flow and frequent pings to C. It records idle and loaded D ping
latency/loss, both iperf JSON documents, B cgroup CPU, B forwarding counters,
and before/after peer connectivity for every node. `summary.json` and
`summary.md` include conservative, host-speed-independent starvation gates.
All three B peers and all leaf sessions must remain connected after load; this
is the control/liveness priority gate.

Useful overrides:

```sh
FIPS_FAIR_DURATION=20 \
FIPS_FAIR_D_RATE=10M \
FIPS_FAIR_D_MIN_MBIT=1 \
testing/forwarding/multipeer/benchmark.sh
```

Analyzer unit tests intentionally model a healthy run, a fully starved D flow,
and a lost B peer:

```sh
python3 -m unittest discover -s testing/forwarding/multipeer -p 'test_*.py'
```
