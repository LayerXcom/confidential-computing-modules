# inherit the baidu sdk image
FROM baiduxlab/sgx-rust:1804-1.1.3 as builder
LABEL maintainer="osuke.sudo@layerx.co.jp"

ENV PJ_NAME=anonify
ENV PJ_ROOT=/root/$PJ_NAME

SHELL ["/bin/bash", "-c"]

RUN set -x && \
    rm -rf /root/sgx && \
    apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends libzmq3-dev llvm clang-3.9 llvm-3.9-dev libclang-3.9-dev software-properties-common nodejs && \
    rm -rf /var/lib/apt/lists/* && \
    curl -o /usr/bin/solc -fL https://github.com/ethereum/solidity/releases/download/v0.7.4/solc-static-linux && \
    chmod u+x /usr/bin/solc && \
    rm -rf /root/.cargo/registry && rm -rf /root/.cargo/git && \
    git clone --depth 1 -b v1.1.3 https://github.com/baidu/rust-sgx-sdk.git sgx

COPY . $PJ_ROOT
WORKDIR $PJ_ROOT

RUN source /opt/sgxsdk/environment && \
    source /root/.cargo/env && \
    export SGX_MODE=HW && \
    export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3 && \
    solc -o contract-build --bin --abi --optimize --overwrite ethereum/contracts/Anonify.sol ethereum/contracts/Factory.sol

RUN cd $PJ_ROOT/frame/types/ && \
    /root/.cargo/bin/cargo build

RUN cd $PJ_ROOT/ethereum/deployer && \
    RUST_BACKTRACE=1 RUST_LOG=debug /root/.cargo/bin/cargo build --release

# ===== SECOND STAGE ======
FROM baiduxlab/sgx-rust:1804-1.1.3
LABEL maintainer="osuke.sudo@layerx.co.jp"

ENV PJ_NAME=anonify
ENV PJ_ROOT=/root/$PJ_NAME

WORKDIR $PJ_ROOT

RUN cd $PJ_ROOT
COPY --from=builder $PJ_ROOT/target/release/eth-deployer ./target/release/
COPY --from=builder $PJ_ROOT/contract-build/Anonify.abi ./contract-build/
COPY --from=builder $PJ_ROOT/contract-build/Anonify.bin ./contract-build/
COPY --from=builder $PJ_ROOT/contract-build/DeployAnonify.abi ./contract-build/
COPY --from=builder $PJ_ROOT/contract-build/DeployAnonify.bin ./contract-build/

ENTRYPOINT ["./target/release/eth-deployer"]
CMD ["$1"]