#!/bin/bash

set -e

export ETH_URL=http://172.18.0.2:8545
export ANONYMOUS_ASSET_ABI_PATH="../../../contract-build/Anonify.abi"
export MY_ROSTER_IDX=0
export MAX_ROSTER_IDX=2
export ANONIFY_URL=172.18.0.2:8080 # depends on the container's ip in the docker network
