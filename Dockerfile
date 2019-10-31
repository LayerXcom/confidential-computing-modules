# inherit the baidu sdk image
FROM baiduxlab/sgx-rust:1804-1.0.9
MAINTAINER osuke
WORKDIR /root
RUN rm -rf /root/sgx

RUN git clone --depth 1 -b v1.0.9 https://github.com/baidu/rust-sgx-sdk.git sgx
