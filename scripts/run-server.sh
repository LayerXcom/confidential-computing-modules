#!/bin/bash

set -eu

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/../core"
echo $PWD
SGX_MODE=HW
ANONIFY_URL=172.18.0.3:8080
ETH_URL=172.18.0.2:8545

echo "Start building core components."
make

cp -r bin/ ../example/bin/
cd ../example/server
cargo run