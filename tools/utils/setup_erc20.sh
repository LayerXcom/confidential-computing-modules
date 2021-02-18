#!/bin/bash

export ANONIFY_URL=http://172.38.1.1:8080

contract_address=$(curl ${ANONIFY_URL}/api/v1/deploy -k -s -X POST -H "Content-Type: application/json" -d '' | jq .contract_address | sed 's/"//g')

curl ${ANONIFY_URL}/api/v1/set_contract_address -k -s -X GET -H "Content-Type: application/json" -d "{\"contract_addr\":\"${contract_address}\"}"

curl ${ANONIFY_URL}/api/v1/start_sync_bc -k -s -X GET -H "Content-Type: application/json" -d ''

curl ${ANONIFY_URL}/api/v1/enclave_encryption_key -k -s -X GET -H "Content-Type: application/json" -d '' > pubkey.json

cd ~/anonify
./enc ./pubkey.json ./init.json

curl ${ANONIFY_URL}/api/v1/state -k -s -X POST -H "Content-Type: application/json" -d @encrypted_init.json

./enc ./pubkey.json ./blob.10.json
#curl ${ANONIFY_URL}/api/v1/state -k -s -X POST -H "Content-Type: application/json" -d @encrypted_blob.10.json

cp encrypted_blob.10.json /root/anonify/tools/vegeta/
cd /root/anonify/tools/vegeta

