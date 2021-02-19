#!/bin/bash

export ANONIFY_URL=http://172.38.1.1:8080

## preparation

which jq > /dev/null 2>&1
if [ $? = 1 ]; then
    /root/anonify/tools/utils/install_jq.sh
else
    echo 'jq is already installed, skipping installation'
fi

## set up erc20 application

echo 'deploying...'
contract_address=$(curl ${ANONIFY_URL}/api/v1/deploy -k -s -X POST -H "Content-Type: application/json" -d '' | jq .contract_address | sed 's/"//g')
echo "got contract_address: ${contract_address}"

echo 'set contract_address'
curl ${ANONIFY_URL}/api/v1/set_contract_address -k -s -X GET -H "Content-Type: application/json" -d "{\"contract_addr\":\"${contract_address}\"}"

echo 'start_sync_bc...'
curl ${ANONIFY_URL}/api/v1/start_sync_bc -k -s -X GET -H "Content-Type: application/json" -d ''

sleep 2;

echo 'get enclave_encryption_key and save to ~/anonify/pubkey.json'
curl ${ANONIFY_URL}/api/v1/enclave_encryption_key -k -s -X GET -H "Content-Type: application/json" -d '' > ~/anonify/pubkey.json

cd ~/anonify
echo 'enc init.json'
./enc ./pubkey.json ./init.json

sleep 2;

echo 'init_state...'
curl ${ANONIFY_URL}/api/v1/state -k -s -X POST -H "Content-Type: application/json" -d @encrypted_init.json

sleep 2;

echo 'enc blob'
./enc ./pubkey.json ./blob.10.json
#curl ${ANONIFY_URL}/api/v1/state -k -s -X POST -H "Content-Type: application/json" -d @encrypted_blob.10.json

cp encrypted_blob.10.json /root/anonify/tools/vegeta/
# cd /root/anonify/tools/vegeta

