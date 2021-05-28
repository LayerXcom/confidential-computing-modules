# A dockerfile for a non-sgx environment to communicate with enclave

FROM rust:1.52.1
LABEL maintainer="div-labs@layerx.co.jp"

RUN rustup component add rustfmt && \
    GRPC_HEALTH_PROBE_VERSION=v0.4.2 && \
    wget -qO/bin/grpc_health_probe https://github.com/grpc-ecosystem/grpc-health-probe/releases/download/${GRPC_HEALTH_PROBE_VERSION}/grpc_health_probe-linux-amd64 && \
    chmod +x /bin/grpc_health_probe
