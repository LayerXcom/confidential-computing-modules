# inherit the baidu sdk image
FROM baiduxlab/sgx-rust:1804-1.1.0 as builder
LABEL maintainer="osuke.sudo@layerx.co.jp"
WORKDIR /root

RUN rm -rf /root/sgx && \
    echo 'source /opt/sgxsdk/environment' >> /root/.docker_bashrc && \
    echo 'source /root/.cargo/env' >> /root/.docker_bashrc

RUN set -x && \
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
    git clone --depth 1 -b v1.1.0 https://github.com/baidu/rust-sgx-sdk.git sgx && \
    source /root/.docker_bashrc

WORKDIR /root/anonify

ENV SGX_MODE HW
RUN solc -o build --bin --abi --optimize --overwrite contracts/Anonify.sol && \
    cd core && \
    make DEBUG=1
COPY /core/bin/ /example/bin/
RUN cd example/server && cargo build

# ===== SECOND STAGE ======
FROM baiduxlab/sgx-rust:1804-1.1.0
LABEL maintainer="osuke.sudo@layerx.co.jp"
WORKDIR /root/anonify

COPY --from=builder /example/target/debug/anonify-server /usr/local/bin

RUN LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service

WORKDIR /usr/local/bin
CMD ["anonify-server"]