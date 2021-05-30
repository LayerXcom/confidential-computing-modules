#!/bin/bash

set -e

ANONIFY_ROOT="$(cd $(dirname $0); pwd)/.."

i=0
MAX_TRIES=40
# Wait until the enclave is healthy
set +e
while true;
do
    grpcurl -plaintext -d '{ "service": "helloworld.Greeter" }' "$OCCLUM_ENCLAVE_IP_ADDRESS:$OCCLUM_ENCLAVE_PORT" grpc.health.v1.Health/Check
    if [ $? -eq 0 ]; then
        echo "enclave is ready"
        break;
    fi

    ((i=i+1))
    if [ $i -gt $MAX_TRIES ]; then
        echo "The number of trials has exceeded the maximum." >&2
        exit 1
    fi

    echo "Tried health check to the enclave $i times..."
    sleep 10
done
set -e

cd "$ANONIFY_ROOT"
cargo test -p occlum-host-node -- --nocapture
