#!/bin/bash

export ANONIFY_URL=http://172.38.1.1:8080
export TOOLS_DIR=/root/anonify/tools

## preparation

### install jq
which jq > /dev/null 2>&1
if [ $? = 1 ]; then
    ${TOOLS_DIR}/utils/install_jq.sh
else
    echo 'jq is already installed, skipping installation'
fi

### copy fixtures to tmp directory
working_dir=${TOOLS_DIR}/utils/tmp

if [ ! -d ${working_dir} ]; then
    mkdir ${working_dir}
fi

cp -r ${TOOLS_DIR}/fixtures ${working_dir}
if [ $? = 1 ]; then
    echo 'failed to copy fixtures'
    exit 1
fi

### building enc

cd ${TOOLS_DIR}/enc
RUST_BACKTRACE=1 cargo build
if [ $? = 1 ]; then
    echo 'failed to build enc'
    exit 1
fi
cp ./target/debug/enc ${working_dir}
if [ $? = 1 ]; then
    echo 'failed to copy enc'
    exit 1
fi

cd ${working_dir}

## set up erc20 application

echo 'deploying...'
contract_address=$(curl ${ANONIFY_URL}/api/v1/deploy -k -s -X POST -H "Content-Type: application/json" -d '' | jq .contract_address | sed 's/"//g')
echo "got contract_address: ${contract_address}"

echo 'set contract_address'
curl ${ANONIFY_URL}/api/v1/set_contract_address -k -s -X GET -H "Content-Type: application/json" -d "{\"contract_addr\":\"${contract_address}\"}"

echo 'start_sync_bc...'
curl ${ANONIFY_URL}/api/v1/start_sync_bc -k -s -X GET -H "Content-Type: application/json" -d ''

sleep 2;

echo 'get enclave_encryption_key and save is as pubkey.json'
curl ${ANONIFY_URL}/api/v1/enclave_encryption_key -k -s -X GET -H "Content-Type: application/json" -d '' > ${working_dir}/pubkey.json

echo 'enc init.json'
./enc ./pubkey.json ./fixtures/init.json
if [ $? = 1 ]; then
    echo 'failed to enc init.json'
    exit 1
fi

sleep 2;

echo 'init_state...'
curl ${ANONIFY_URL}/api/v1/state -k -s -X POST -H "Content-Type: application/json" -d @encrypted_init.json

sleep 2;

echo 'enc blob'
./enc ./pubkey.json ./fixtures/blob.100.json
if [ $? = 1 ]; then
    echo 'failed to enc blob'
    exit 1
fi
#curl ${ANONIFY_URL}/api/v1/state -k -s -X POST -H "Content-Type: application/json" -d @encrypted_blob.10.json

cp encrypted_blob.100.json ${TOOLS_DIR}/vegeta/
if [ $? = 1 ]; then
    echo 'failed to copy blob to vegeta'
    exit 1
fi
# cd ${TOOLS_DIR}/vegeta

echo 'finished setup erc20 application, you can send blob.'
