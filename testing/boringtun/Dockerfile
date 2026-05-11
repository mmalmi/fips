# Minimal boringtun-cli image for throughput benchmarking against FIPS.
# Userspace WireGuard (boringtun) + wireguard-tools + iperf3 in one
# image. Run two containers on a docker bridge, configure a WG peer
# between them, then iperf3 client→server across the tunnel.

FROM rust:1-bookworm AS build
RUN cargo install --version 0.6.0 boringtun-cli

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iperf3 \
        iproute2 \
        wireguard-tools \
        iputils-ping \
        netcat-openbsd \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/cargo/bin/boringtun-cli /usr/local/bin/boringtun-cli
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
