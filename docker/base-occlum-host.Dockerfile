# A dockerfile for a non-sgx environment to communicate with enclave

FROM rust:1.52.1
LABEL maintainer="div-labs@layerx.co.jp"

WORKDIR /tmp/grpcurl
RUN rustup component add rustfmt && \
    GRPCURL_VERSION=1.8.0 && \
    wget -q https://github.com/fullstorydev/grpcurl/releases/download/v${GRPCURL_VERSION}/grpcurl_${GRPCURL_VERSION}_linux_x86_64.tar.gz && \
    tar xvf grpcurl_${GRPCURL_VERSION}_linux_x86_64.tar.gz && \
    cp grpcurl /usr/bin/ && \
    chmod +x /usr/bin/grpcurl && \
    rm -rf /tmp/grpcurl

WORKDIR /root
