# inherit the baidu sdk image
FROM baiduxlab/sgx-rust:1804-1.1.2
LABEL maintainer="osuke.sudo@layerx.co.jp"

WORKDIR /root/anonify/example/erc20/server
COPY /root/anonify/contract-build/Anonify.abi ../../../contract-build/
COPY /root/anonify/contract-build/Anonify.bin ../../../contract-build/
COPY /root/.anonify/enclave.signed.so /root/.anonify/enclave.signed.so
COPY /root/anonify/target/debug/erc20-server ./target/debug/

CMD ["./target/debug/erc20-server"]
