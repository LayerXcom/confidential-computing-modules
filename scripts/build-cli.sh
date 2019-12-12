#!/bin/bash

set -eu

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/../example/cli"
echo $PWD
SGX_MODE=HW
export ANONIFY_URL=172.18.0.3:8080
export ETH_URL=172.18.0.2:8545

cargo build --release