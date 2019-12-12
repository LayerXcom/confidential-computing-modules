# inherit the baidu sdk image
FROM baiduxlab/sgx-rust:1804-1.0.9 as builder
LABEL maintainer="osuke.sudo@layerx.co.jp"
WORKDIR /root
RUN rm -rf /root/sgx

COPY . /root/anonify

ENV PATH "$PATH:/root/.cargo/bin"

RUN set -x && \
    apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends libzmq3-dev llvm clang-3.9 llvm-3.9-dev libclang-3.9-dev software-properties-common nodejs && \
    curl -o- -L https://yarnpkg.com/install.sh | bash && \
    export PATH="$HOME/.yarn/bin:$PATH" && \
    yarn global add ganache-cli && \
    rm -rf /var/lib/apt/lists/* && \
    add-apt-repository -y ppa:ethereum/ethereum && \
    apt-get install -y solc

RUN cargo install bindgen cargo-audit && \
    rm -rf /root/.cargo/registry && rm -rf /root/.cargo/git && \
    git clone --depth 1 -b v1.0.9 https://github.com/baidu/rust-sgx-sdk.git sgx

WORKDIR /root/anonify
ARG PROFILE=release

ENV SGX_MODE HW
RUN cd core && make
COPY /core/bin/ /example/bin/
RUN cd example/server && cargo build --$PROFILE

# ===== SECOND STAGE ======
FROM baiduxlab/sgx-rust:1804-1.0.9
LABEL maintainer="osuke.sudo@layerx.co.jp"
WORKDIR /root/anonify
ARG PROFILE=release

COPY --from=builder /core/bin/ /example/bin/
COPY --from=builder /example/target/$PROFILE/anonify-server /usr/local/bin

RUN LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service

WORKDIR /usr/local/bin
CMD ["anonify-server"]