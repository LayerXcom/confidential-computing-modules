# inherit the baidu sdk image
FROM baiduxlab/sgx-rust:1804-1.1.3
LABEL maintainer="osuke.sudo@layerx.co.jp"

WORKDIR /root/anonify/example/erc20/server
COPY ./contract-build/Anonify.abi ../../../contract-build/
COPY ./contract-build/Anonify.bin ../../../contract-build/
COPY /root/.anonify/enclave.signed.so /root/.anonify/enclave.signed.so
COPY ./target/debug/erc20-server ./target/debug/

CMD ["./target/debug/erc20-server"]
