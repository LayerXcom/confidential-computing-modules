# A dockerfile for developing in the occlum-enable environment

FROM ubuntu:18.04
LABEL maintainer="div-labs@layerx.co.jp"

RUN apt update && DEBIAN_FRONTEND="noninteractive" apt install -y --no-install-recommends \
        alien \
        astyle \
        autoconf \
        automake \
        bison \
        build-essential \
        ca-certificates \
        cmake \
        curl \
        debhelper \
        expect \
        g++ \
        gawk \
        gdb \
        git-core \
        golang-go \
        jq \
        kmod \
        lcov \
        libboost-system-dev \
        libboost-thread-dev \
        libcurl4-openssl-dev \
        libfuse-dev \
        libjsoncpp-dev \
        liblog4cpp5-dev \
        libprotobuf-c0-dev \
        libprotobuf-dev \
        libssl-dev \
        libtool \
        libxml2-dev \
        nano \
        ocaml \
        ocamlbuild \
        pkg-config \
        protobuf-compiler \
        python \
        python-pip \
        sudo \
        unzip \
        uuid-dev \
        vim \
        wget \
        zip \
        gnupg \
        aptitude \
        && \
    apt clean && \
    rm -rf /var/lib/apt/lists/*

RUN echo "ca_directory=/etc/ssl/certs" >> /etc/wgetrc && \
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | tee /etc/apt/sources.list.d/intel-sgx.list &&\
    wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key --no-check-certificate | apt-key add -

# Install cpuid tool for tests
WORKDIR /tmp
RUN wget http://www.etallen.com/cpuid/cpuid-20200211.x86_64.tar.gz && \
    tar -xf ./cpuid-20200211.x86_64.tar.gz && \
    cp ./cpuid-20200211/cpuid /usr/bin/ && \
    rm -rf /tmp/cpuid-20200211*

# Install SGX PSW
RUN apt update && aptitude install -y \
        libsgx-launch-dev=2.13.100.4-bionic1 \
        libsgx-epid-dev=2.13.100.4-bionic1 \
        libsgx-quote-ex-dev=2.13.100.4-bionic1 \
        libsgx-urts=2.13.100.4-bionic1 \
        libsgx-enclave-common=2.13.100.4-bionic1 \
        libsgx-uae-service=2.13.100.4-bionic1 \
        libsgx-ae-epid=2.13.100.4-bionic1 \
        libsgx-ae-le=2.13.100.4-bionic1 \
        libsgx-ae-pce=2.13.100.4-bionic1 \
        libsgx-aesm-launch-plugin=2.13.100.4-bionic1 \
        sgx-aesm-service=2.13.100.4-bionic1 \
        libsgx-aesm-launch-plugin=2.13.100.4-bionic1 \
        libsgx-aesm-pce-plugin=2.13.100.4-bionic1 \
        libsgx-aesm-ecdsa-plugin=2.13.100.4-bionic1 \
        libsgx-aesm-epid-plugin=2.13.100.4-bionic1 \
        libsgx-aesm-quote-ex-plugin=2.13.100.4-bionic1 \
        libsgx-dcap-quote-verify=1.10.100.4-bionic1 \
        libsgx-dcap-quote-verify-dev=1.10.100.4-bionic1 \
        libsgx-dcap-ql=1.10.100.4-bionic1 \
        libsgx-dcap-ql-dev=1.10.100.4-bionic1 \
        libsgx-epid=2.13.100.4-bionic1 \
        libsgx-quote-ex=2.13.100.4-bionic1 \
        libsgx-pce-logic=1.10.100.4-bionic1 \
        libsgx-qe3-logic=1.10.100.4-bionic1 \
        libsgx-launch=2.13.100.4-bionic1 \
        libsgx-dcap-default-qpl=1.10.100.4-bionic1 \
        && \
    apt clean && \
    rm -rf /var/lib/apt/lists/* && \
    ln -s /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so.1 /usr/lib/x86_64-linux-gnu/libsgx_enclave_common.so

# Install SGX SDK
WORKDIR /tmp
RUN git clone --depth 1 -b sgx_2.13_for_occlum https://github.com/occlum/linux-sgx && \
    mkdir /etc/init && \
    cd linux-sgx && \
    make preparation && \
    ./compile_and_install.sh no_mitigation USE_OPT_LIBS=2 && \
    echo 'source /opt/intel/sgxsdk/environment' >> /root/.bashrc && \
    rm -rf /tmp/linux-sgx

# Install Rust
ENV PATH="/root/.cargo/bin:$PATH"
ENV OCCLUM_RUST_VERSION=nightly-2020-09-08
RUN curl https://sh.rustup.rs -sSf | \
        sh -s -- --default-toolchain ${OCCLUM_RUST_VERSION} -y && \
    rm -rf /root/.cargo/registry && rm -rf /root/.cargo/git && \
    cargo -V

# Install Occlum toolchain (Rust)
WORKDIR /root
RUN git clone --depth 1 -b 0.22.0 https://github.com/occlum/occlum && \
    cd occlum/tools/toolchains && \
    ./musl-gcc/build.sh && \
    ./musl-gcc/install_zlib.sh && \
    ./glibc/build.sh && \
    ./rust/build.sh && \
    export PATH="/opt/occlum/build/bin:/usr/local/occlum/bin:/opt/occlum/toolchains/rust/bin:$PATH" && \
    cd /root/occlum && \
    make submodule && \
    OCCLUM_RELEASE_BUILD=1 make && \
    make install && \
    rm -rf /root/occlum

ENV PATH="/opt/occlum/build/bin:/usr/local/occlum/bin:/opt/occlum/toolchains/rust/bin:$PATH"

# Download and Build OpenSSL 1.1.1 for musl
WORKDIR /root/deps/musl
RUN wget https://github.com/openssl/openssl/archive/OpenSSL_1_1_1f.tar.gz && \
    tar zxvf OpenSSL_1_1_1f.tar.gz && \
    cd openssl-OpenSSL_1_1_1f && \
    CC="occlum-gcc -fPIE -pie" ./Configure no-shared no-async --prefix=/root/deps/musl --openssldir=/root/deps/musl/ssl --with-rand-seed=rdcpu linux-x86_64 && \
    make depend && \
    make -j$(nproc) && \
    make install
ENV PKG_CONFIG_ALLOW_CROSS=1
ENV OPENSSL_STATIC=true
ENV OPENSSL_DIR=/root/deps/musl

WORKDIR /root
