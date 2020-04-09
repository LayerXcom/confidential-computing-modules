# inherit the baidu sdk image
FROM baiduxlab/sgx-rust:1804-1.1.0 as builder
LABEL maintainer="osuke.sudo@layerx.co.jp"

SHELL ["/bin/bash", "-c"]

RUN set -x && \
    rm -rf /root/sgx && \
    apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends libzmq3-dev llvm clang-3.9 llvm-3.9-dev libclang-3.9-dev software-properties-common nodejs && \
    curl -o- -L https://yarnpkg.com/install.sh | bash && \
    export PATH="$HOME/.yarn/bin:$PATH" && \
    yarn global add ganache-cli && \
    rm -rf /var/lib/apt/lists/* && \
    curl -o /usr/bin/solc -fL https://github.com/ethereum/solidity/releases/download/v0.5.16/solc-static-linux && \
    chmod u+x /usr/bin/solc && \
    rm -rf /root/.cargo/registry && rm -rf /root/.cargo/git && \
    /root/.cargo/bin/cargo install bindgen && \
    git clone --depth 1 -b v1.1.0 https://github.com/baidu/rust-sgx-sdk.git sgx

COPY . /root/anonify
WORKDIR /root/anonify

RUN source /opt/sgxsdk/environment && \
    source /root/.cargo/env && \
    export PATH="$HOME/.cargo/bin:$PATH" && \
    export SGX_MODE=HW && \
    export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3 && \
    solc -o build --bin --abi --optimize --overwrite contracts/Anonify.sol && \
    cd core && \
    make DEBUG=1 && \
    cd example/server && \
    RUST_BACKTRACE=1 RUST_LOG=debug /root/.cargo/bin/cargo build

# ===== SECOND STAGE ======
FROM baiduxlab/sgx-rust:1804-1.1.0
LABEL maintainer="osuke.sudo@layerx.co.jp"

WORKDIR /root/anonify/example/server
COPY --from=builder /root/anonify/build/Anonify.abi ../../build/
COPY --from=builder /root/anonify/build/Anonify.bin ../../build/
COPY --from=builder /root/anonify/core/bin/enclave.signed.so ../bin/
COPY --from=builder /root/anonify/example/server/target/debug/anonify-server ./target/debug/

CMD ["./target/debug/anonify-server"]
