#!/bin/bash

set -e

export ETH_URL=http://172.18.0.2:8545
export ANONIFY_URL=172.18.0.3:8080 # depends on the container's ip in the docker network
export ANONYMOUS_ASSET_ABI_PATH="../../../contract-build/Anonify.abi"
export MY_ROSTER_IDX=0
export MAX_ROSTER_IDX=2
export CONFIRMATIONS=1
export ACCOUNT_INDEX=1
export PASSWORD=anonify0101

export SPID=2C149BFC94A61D306A96211AED155BE9
export IAS_URL=https://api.trustedservices.intel.com/sgx/dev/attestation/v3/report
export SUB_KEY=77e2533de0624df28dc3be3a5b9e50d9