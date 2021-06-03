FROM anonify.azurecr.io/rust-sgx-sdk-rootless:latest

WORKDIR ${HOME}

RUN set -x && \
    sudo apt-get update && \
    sudo apt-get upgrade -y --no-install-recommends && \
    sudo apt-get install -y --no-install-recommends libzmq3-dev llvm clang-3.9 llvm-3.9-dev libclang-3.9-dev software-properties-common nodejs && \
    sudo rm -rf /var/lib/apt/lists/* && \
    sudo curl -o /usr/bin/solc -fL https://github.com/ethereum/solidity/releases/download/v0.7.4/solc-static-linux && \
    sudo chmod 755 /usr/bin/solc

RUN git clone --depth 1 -b v1.1.3 https://github.com/baidu/rust-sgx-sdk.git sgx

CMD ["bash"]
