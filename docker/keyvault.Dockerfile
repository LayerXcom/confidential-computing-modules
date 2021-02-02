# inherit the baidu sdk image
FROM baiduxlab/sgx-rust:1804-1.1.3 as builder
LABEL maintainer="osuke.sudo@layerx.co.jp"

SHELL ["/bin/bash", "-c"]

RUN set -x && \
    rm -rf /root/sgx && \
    apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends libzmq3-dev llvm clang-3.9 llvm-3.9-dev libclang-3.9-dev software-properties-common nodejs && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /root/.cargo/registry && rm -rf /root/.cargo/git && \
    git clone --depth 1 -b v1.1.3 https://github.com/baidu/rust-sgx-sdk.git sgx

COPY . /root/anonify
WORKDIR /root/anonify

RUN source /opt/sgxsdk/environment && \
    source /root/.cargo/env && \
    export SGX_MODE=HW && \
    export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3 && \
    cd scripts && \
    make ENCLAVE_DIR=nodes/key-vault/enclave ENCLAVE_PKG_NAME=secret_backup CARGO_FLAGS=--release && \
    cd ../nodes/key-vault/server && \
    RUST_BACKTRACE=1 RUST_LOG=debug /root/.cargo/bin/cargo build --release

# ===== SECOND STAGE ======
FROM baiduxlab/sgx-rust:1804-1.1.3
LABEL maintainer="osuke.sudo@layerx.co.jp"

WORKDIR /root/anonify

RUN cd /root/anonify
COPY --from=builder /root/anonify/.anonify/secret_backup.signed.so ./.anonify/secret_backup.signed.so
COPY --from=builder /root/anonify/target/release/key-vault-node-server ./target/release/

CMD ["./target/release/key-vault-node-server"]
