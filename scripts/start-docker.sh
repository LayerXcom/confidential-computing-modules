#!/bin/bash

set -e

# The SDK Driver creates a device at `/dev/sgx`, non-DCAP systems using IAS.
# docker run -v `pwd`:/root/anonify -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket --device /dev/sgx --net=test-network --name sgx --rm -it osuketh/anonify

docker run -v `pwd`:/root/anonify -v /var/run/aesmd:/var/run/aesmd --device /dev/sgx/enclave --privileged --net=test-network --name anonify --rm -it osuketh/anonify
SGX_MODE=HW
