#!/bin/bash

set -eu

dirpath=$(cd $(dirname $0) && pwd)
cd "${dirpath}/../core"
echo $PWD
export SGX_MODE=HW

echo "Start building core components."
make

cp -r bin/ ../example/bin/
cd ../example/server
cargo run