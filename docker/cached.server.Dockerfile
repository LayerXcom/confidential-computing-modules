# inherit the baidu sdk image
FROM baiduxlab/sgx-rust:1804-1.1.2
LABEL maintainer="osuke.sudo@layerx.co.jp"

WORKDIR /root/anonify/example/erc20/server
COPY --from=builder /root/anonify/contract-build/Anonify.abi ../../../contract-build/
COPY --from=builder /root/anonify/contract-build/Anonify.bin ../../../contract-build/
COPY --from=builder /root/.anonify/enclave.signed.so /root/.anonify/enclave.signed.so
COPY --from=builder /root/anonify/target/debug/erc20-server ./target/debug/

CMD ["./target/debug/erc20-server"]
