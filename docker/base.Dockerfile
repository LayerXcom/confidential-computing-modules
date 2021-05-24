# inherit the baidu sdk image
FROM baiduxlab/sgx-rust:1804-1.1.3

RUN sudo rm -rf /root/sgx

RUN set -x && \
    apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends libzmq3-dev llvm clang-3.9 llvm-3.9-dev libclang-3.9-dev software-properties-common nodejs && \
    rm -rf /var/lib/apt/lists/* && \
    curl -o /usr/bin/solc -fL https://github.com/ethereum/solidity/releases/download/v0.7.4/solc-static-linux && \
    chmod u+x /usr/bin/solc

ARG user_name=anonify-dev
ARG user_id=61000
ARG group_name=anonify-dev
ARG group_id=61000

RUN groupadd -g ${group_id} ${group_name}
RUN useradd -g ${group_id} -l -m -s /bin/false -u ${user_id} ${user_name}
USER ${user_name}
WORKDIR /home/${user_name}
ENV HOME /home/${user_name}

RUN echo 'source /opt/sgxsdk/environment' >> ~/.bashrc && \
    echo 'source ~/.cargo/env' >> ~/.bashrc

ARG rust_toolchain=nightly-2020-10-25

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain ${rust_toolchain}
ENV PATH $PATH:$HOME/.cargo/bin

RUN rustup component add rust-src rls rust-analysis clippy rustfmt && \
    cargo install xargo bindgen cargo-audit && \
    rm -rf ~/.cargo/registry && rm -rf ~/.cargo/git

RUN git clone --depth 1 -b v1.1.3 https://github.com/baidu/rust-sgx-sdk.git sgx
