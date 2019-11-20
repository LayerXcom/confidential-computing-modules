# inherit the baidu sdk image
FROM baiduxlab/sgx-rust:1804-1.0.9
MAINTAINER osuke
WORKDIR /root
RUN rm -rf /root/sgx

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends libzmq3-dev llvm clang-3.9 llvm-3.9-dev libclang-3.9-dev && \
    apt-get install -y nodejs && \
    curl -o- -L https://yarnpkg.com/install.sh | bash && \
    export PATH="$HOME/.yarn/bin:$PATH" && \
    yarn global add ganache-cli && \
    rm -rf /var/lib/apt/lists/*

RUN /root/.cargo/bin/cargo install bindgen cargo-audit && \
    rm -rf /root/.cargo/registry && rm -rf /root/.cargo/git

# solc, ganache

RUN git clone --depth 1 -b v1.0.9 https://github.com/baidu/rust-sgx-sdk.git sgx
