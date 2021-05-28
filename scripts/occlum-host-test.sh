#!/bin/bash

set -ex

ANONIFY_ROOT="$(cd $(dirname $0); pwd)/.."

# Wait until the enclave is healthy
set +e
while true;
do
    grpc_health_probe -addr "$OCCLUM_ENCLAVE_IP_ADDRESS:$OCCLUM_ENCLAVE_PORT"
    if [[ $? -eq 0 ]];
    then
        echo "enclave is ready"
        break;
    fi
    sleep 5
done
set -e

cd "$ANONIFY_ROOT"
cargo test -p occlum-host-node -- --nocapture
