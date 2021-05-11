# inherit the baidu sdk image
FROM baiduxlab/sgx-rust:1804-1.1.3 as builder
LABEL maintainer="osuke.sudo@layerx.co.jp"

SHELL ["/bin/bash", "-c"]

RUN set -x && \
    rm -rf /root/sgx && \
    apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends libzmq3-dev llvm clang-3.9 llvm-3.9-dev libclang-3.9-dev software-properties-common nodejs python3-pip python3-setuptools && \
    python3 -m pip install -U pip && \
    python3 -m pip install --upgrade pip --target /usr/lib64/az/lib/python3.6/site-packages/ && \
    rm -rf /var/lib/apt/lists/* && \
    curl -o /usr/bin/solc -fL https://github.com/ethereum/solidity/releases/download/v0.7.4/solc-static-linux && \
    chmod u+x /usr/bin/solc && \
    rm -rf /root/.cargo/registry && rm -rf /root/.cargo/git && \
    git clone --depth 1 -b v1.1.3 https://github.com/baidu/rust-sgx-sdk.git sgx

COPY . /root/anonify
WORKDIR /root/anonify

# Define environment variables
ARG AZ_KV_ENDPOINT
ARG AZURE_CLIENT_ID
ARG AZURE_CLIENT_SECRET
ARG AZURE_TENANT_ID
ARG PROD_ID
ARG ISVSVN
ENV AZ_KV_ENDPOINT=$AZ_KV_ENDPOINT \
    AZURE_CLIENT_ID=$AZURE_CLIENT_ID \
    AZURE_CLIENT_SECRET=$AZURE_CLIENT_SECRET \
    AZURE_TENANT_ID=$AZURE_TENANT_ID \
    PROD_ID=$PROD_ID \
    ISVSVN=$ISVSVN

RUN source /opt/sgxsdk/environment && \
    source /root/.cargo/env && \
    export SGX_MODE=HW && \
    export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3 && \
    git clone --depth 1 -b v0.5.10 https://github.com/LayerXcom/anonify-contracts && \
    solc -o contract-build --bin --abi --optimize --overwrite \
        anonify-contracts/contracts/AnonifyWithTreeKem.sol \
        anonify-contracts/contracts/AnonifyWithEnclaveKey.sol \
        anonify-contracts/contracts/Factory.sol && \
    /root/.cargo/bin/cargo build -p frame-types --release && \
    cd scripts && \
    pip3 install azure-keyvault-keys azure-identity && \
    ./gen-enclave-config.sh && \
    make prd-signed.so ENCLAVE_DIR=example/erc20/enclave ENCLAVE_PKG_NAME=erc20 CARGO_FLAGS=--release && \
    make prd-signed.so ENCLAVE_DIR=example/key-vault/enclave ENCLAVE_PKG_NAME=key_vault CARGO_FLAGS=--release && \
    cd ../example/erc20/server && \
    RUST_BACKTRACE=1 RUST_LOG=debug /root/.cargo/bin/cargo build --release

# ===== SECOND STAGE ======
FROM baiduxlab/sgx-rust:1804-1.1.3
LABEL maintainer="osuke.sudo@layerx.co.jp"

WORKDIR /root/anonify

RUN cd /root/anonify
COPY --from=builder /root/anonify/config/ias_root_cert.pem ./config/ias_root_cert.pem
COPY --from=builder /root/anonify/.anonify/erc20.signed.so ./.anonify/erc20.signed.so
COPY --from=builder /root/anonify/.anonify/erc20_measurement.txt ./.anonify/erc20_measurement.txt
COPY --from=builder /root/anonify/.anonify/key_vault_measurement.txt ./.anonify/key_vault_measurement.txt
COPY --from=builder /root/anonify/target/release/erc20-server ./target/release/
COPY --from=builder /root/anonify/contract-build/AnonifyWithEnclaveKey.abi ./contract-build/
COPY --from=builder /root/anonify/contract-build/AnonifyWithEnclaveKey.bin ./contract-build/
COPY --from=builder /root/anonify/contract-build/AnonifyWithTreeKem.abi ./contract-build/
COPY --from=builder /root/anonify/contract-build/AnonifyWithTreeKem.bin ./contract-build/
COPY --from=builder /root/anonify/contract-build/DeployAnonify.abi ./contract-build/
COPY --from=builder /root/anonify/contract-build/DeployAnonify.bin ./contract-build/

CMD ["./target/release/erc20-server"]
