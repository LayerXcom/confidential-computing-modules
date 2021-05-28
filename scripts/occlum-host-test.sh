#!/bin/bash

set -e

ANONIFY_ROOT="$(cd $(dirname $0); pwd)/.."

cd "$ANONIFY_ROOT"
cargo test -p occlum-host-node -- --nocapture
