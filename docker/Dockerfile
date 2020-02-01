# inherit the baidu sdk image
FROM baiduxlab/sgx-rust:1804-1.1.0
MAINTAINER osuke
WORKDIR /root
RUN rm -rf /root/sgx

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

RUN /root/.cargo/bin/cargo install bindgen cargo-audit && \
    rm -rf /root/.cargo/registry && rm -rf /root/.cargo/git && \
    git clone --depth 1 -b v1.1.0 https://github.com/baidu/rust-sgx-sdk.git sgx
