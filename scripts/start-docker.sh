#!/bin/bash

set -e

docker run -v `pwd`:/root/anonify --device /dev/sgx --net=test-network --name sgx --rm -it osuketh/anonify
LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service