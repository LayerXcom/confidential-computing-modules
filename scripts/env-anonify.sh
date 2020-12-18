#!/bin/bash

set -e

export ETH_URL=http://172.18.0.2:8545
export ANONIFY_URL=172.18.0.3:8080 # depends on the container's ip in the docker network
export ABI_PATH=../../../contract-build/Anonify.abi
export BIN_PATH=../../../contract-build/Anonify.bin
export MY_ROSTER_IDX=0
export MAX_ROSTER_IDX=2
export CONFIRMATIONS=1
export ACCOUNT_INDEX=1
export PASSWORD=anonify0101

export SPID=
export IAS_URL=https://api.trustedservices.intel.com/sgx/dev/attestation/v3/report
export SUB_KEY=
export MRA_TLS_SERVER_ADDRESS=localhost:12345
