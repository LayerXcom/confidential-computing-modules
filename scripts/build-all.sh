#!/bin/bash

set -eu

dirpath=$(cd $(dirname $0) && pwd)

cd "${dirpath}/../core"
make DEBUG=1

cd ../
RUST_BACKTRACE=1 cargo build

cd example/server
RUST_BACKTRACE=1 cargo build
