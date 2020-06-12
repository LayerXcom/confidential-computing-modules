# inherit the baidu sdk image
FROM baiduxlab/sgx-rust:1804-1.1.2
LABEL maintainer="osuke.sudo@layerx.co.jp"

WORKDIR /root/anonify/example/erc20/server
COPY ./build/Anonify.abi ../../../build/
COPY ./build/Anonify.bin ../../../build/
COPY ./core/bin/enclave.signed.so ../../bin/
COPY ./example/erc20/server/target/debug/anonify-server ./target/debug/

CMD ["./target/debug/anonify-server"]
