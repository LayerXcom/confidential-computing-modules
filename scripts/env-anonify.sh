#!/bin/bash

set -e

export ETH_URL=https://osuke.blockchain.azure.com:3200/IPYUwQVjYBCw6fXnoyQ2L9sH
export ANONIFY_URL=172.18.0.2:8080 # depends on the container's ip in the docker network
export ANONYMOUS_ASSET_ABI_PATH="../../../contract-build/Anonify.abi"
export MY_ROSTER_IDX=0
export MAX_ROSTER_IDX=2
export CONFIRMATIONS=1
export ACCOUNT_INDEX=1
export PASSWORD=anonify0101