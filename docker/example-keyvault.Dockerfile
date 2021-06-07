ARG user_name=anonify-dev
ARG group_name=anonify-dev

FROM anonify.azurecr.io/anonify-dev:latest as builder
LABEL maintainer="osuke.sudo@layerx.co.jp"

SHELL ["/bin/bash", "-c"]

RUN set -x && \
    sudo apt-get update && \
    sudo apt-get upgrade -y --no-install-recommends && \
    sudo apt-get install -y --no-install-recommends python3-pip python3-setuptools && \
    sudo python3 -m pip install -U pip && \
    sudo python3 -m pip install --upgrade pip --target /usr/lib64/az/lib/python3.6/site-packages/ && \
    sudo rm -rf /var/lib/apt/lists/*

ARG user_name
ARG group_name
COPY --chown=${user_name}:${group_name} . ${HOME}/anonify
WORKDIR ${HOME}/anonify

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

RUN set -x && \
    export SGX_MODE=HW && \
    export RUSTFLAGS=-Ctarget-feature=+aes,+sse2,+sse4.1,+ssse3 && \
    cargo build -p frame-types --release && \
    cd scripts && \
    pip3 install azure-keyvault-keys azure-identity && \
    ./gen-enclave-config.sh && \
    make prd-signed.so ENCLAVE_DIR=example/erc20/enclave ENCLAVE_PKG_NAME=erc20 CARGO_FLAGS=--release && \
    make prd-signed.so ENCLAVE_DIR=example/key-vault/enclave ENCLAVE_PKG_NAME=key_vault CARGO_FLAGS=--release && \
    cd ../example/key-vault/server && \
    RUST_BACKTRACE=1 RUST_LOG=debug cargo build --release

# ===== SECOND STAGE ======
FROM anonify.azurecr.io/anonify-dev:latest
LABEL maintainer="osuke.sudo@layerx.co.jp"

WORKDIR ${HOME}/anonify

ARG user_name
ARG group_name

COPY --from=builder --chown=${user_name}:${group_name} ${HOME}/anonify/config/ias_root_cert.pem ./config/ias_root_cert.pem
COPY --from=builder --chown=${user_name}:${group_name} ${HOME}/anonify/.anonify/key_vault.signed.so ./.anonify/key_vault.signed.so
COPY --from=builder --chown=${user_name}:${group_name} ${HOME}/anonify/.anonify/erc20_measurement.txt ./.anonify/erc20_measurement.txt
COPY --from=builder --chown=${user_name}:${group_name} ${HOME}/anonify/.anonify/key_vault_measurement.txt ./.anonify/key_vault_measurement.txt
COPY --from=builder --chown=${user_name}:${group_name} ${HOME}/anonify/target/release/key-vault-server ./target/release/
COPY --from=builder --chown=${user_name}:${group_name} ${HOME}/fixuid.bash ./

RUN sudo chown ${user_name}:${group_name} .

CMD ["./target/release/key-vault-server"]
