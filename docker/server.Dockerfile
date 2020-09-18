# inherit the baidu sdk image
FROM baiduxlab/sgx-rust:1804-1.1.2 as builder
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
    git clone --depth 1 -b v1.1.2 https://github.com/baidu/rust-sgx-sdk.git sgx

COPY . /root/anonify
WORKDIR /root/anonify

RUN source /opt/sgxsdk/environment && \
    source /root/.cargo/env && \
    export PATH="$HOME/.cargo/bin:$PATH" && \
    export SGX_MODE=HW && \
    export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3 && \
    solc -o build --bin --abi --optimize --overwrite contracts/Anonify.sol && \
    cd scripts && \
    make DEBUG=1 ENCLAVE_DIR=example/erc20/enclave && \
    cd ../example/erc20/server && \
    RUST_BACKTRACE=1 RUST_LOG=debug /root/.cargo/bin/cargo build

# ===== SECOND STAGE ======
FROM baiduxlab/sgx-rust:1804-1.1.2
LABEL maintainer="osuke.sudo@layerx.co.jp"

WORKDIR /root/anonify
COPY --from=builder ./contract-build/Anonify.abi ./contract-build/
COPY --from=builder ./contract-build/Anonify.bin ./contract-build/
COPY --from=builder ./.anonify/enclave.signed.so ./.anonify/enclave.signed.so
COPY --from=builder ./target/debug/erc20-server ./target/debug/

CMD ["./target/debug/erc20-server"]
