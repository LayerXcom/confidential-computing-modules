#!/bin/bash

set -e

ANONIFY_ROOT="$(cd $(dirname $0); pwd)/.."

rustup component add rustfmt
cd "$ANONIFY_ROOT"
cargo test -p occlum-host-node -- --nocapture
