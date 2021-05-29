#!/bin/bash

set -ex

ANONIFY_ROOT="$(cd $(dirname $0); pwd)/.."

# Wait until the enclave is healthy
set +e
while true;
do
    grpcurl -plaintext -d '{ "service": "helloworld.Greeter" }' "$OCCLUM_ENCLAVE_IP_ADDRESS:$OCCLUM_ENCLAVE_PORT" grpc.health.v1.Health/Check
    if [[ $? -eq 0 ]];
    then
        echo "enclave is ready"
        break;
    fi
    sleep 10
done
set -e

cd "$ANONIFY_ROOT"
cargo test -p occlum-host-node -- --nocapture
