#!/bin/bash

set -e

# The SDK Driver creates a device at `/dev/sgx`, non-DCAP systems using IAS.
docker run -v `pwd`:/root/anonify --device /dev/sgx --net=test-network --name sgx --rm -it osuketh/anonify
SGX_MODE=HW
# After entering docker container, the very first thing is to start aesm service daemon.
LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service

