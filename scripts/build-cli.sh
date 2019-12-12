#!/bin/bash

set -eu

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/../example/cli"
echo $PWD
SGX_MODE=HW
export ANONIFY_URL=http://172.18.0.3:8080

cargo build --release