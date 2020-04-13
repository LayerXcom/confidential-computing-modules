#!/bin/bash

set -e

ANONIFY_URL=http://172.28.1.1:8080 ./target/debug/anonify-cli anonify set_contract_addr -c ${CONTRACT_ADDR}
ANONIFY_URL=http://172.28.1.2:8080 ./target/debug/anonify-cli anonify set_contract_addr -c ${CONTRACT_ADDR}
ANONIFY_URL=http://172.28.1.3:8080 ./target/debug/anonify-cli anonify set_contract_addr -c ${CONTRACT_ADDR}
ANONIFY_URL=http://172.28.1.1:8080 ./target/debug/anonify-cli anonify start_polling -c ${CONTRACT_ADDR}
ANONIFY_URL=http://172.28.1.2:8080 ./target/debug/anonify-cli anonify start_polling -c ${CONTRACT_ADDR}
ANONIFY_URL=http://172.28.1.3:8080 ./target/debug/anonify-cli anonify start_polling -c ${CONTRACT_ADDR}
