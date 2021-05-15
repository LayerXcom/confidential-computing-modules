#!/bin/bash
set -e

ANONIFY_ROOT=$(pwd)
echo "$ANONIFY_ROOT"

ANONIFY_TAG=v0.5.12
#ANONIFY_ROOT=/root/anonify
STATE_RUNTIME_URL=http://172.16.14.3:18550
ETH_URL=http://172.16.14.2:8545

echo "ganache is starting..."
docker-compose -f e2e-docker-compose.yml up -d ganache
sleep 5

echo "deploying factory contract..."
FACTORY_CONTRACT_ADDRESS=$(docker run --network s_e2e_test_net -e CONFIRMATIONS=0 -e ETH_URL="$ETH_URL" --rm anonify.azurecr.io/deployer:$ANONIFY_TAG factory)
export FACTORY_CONTRACT_ADDRESS=$FACTORY_CONTRACT_ADDRESS
echo "FACTORY_CONTRACT_ADDRESS: ""$FACTORY_CONTRACT_ADDRESS"

echo "deploying anonify contract..."
docker run --network s_e2e_test_net -e CONFIRMATIONS=0 -e ETH_URL="$ETH_URL" --rm anonify.azurecr.io/deployer:$ANONIFY_TAG anonify_ek "$FACTORY_CONTRACT_ADDRESS"

sleep 10

echo "key_vault is starting..."
FACTORY_CONTRACT_ADDRESS=$FACTORY_CONTRACT_ADDRESS docker-compose -f e2e-docker-compose.yml up -d key_vault

sleep 10

echo "state_runtime_1 is starting..."
FACTORY_CONTRACT_ADDRESS=$FACTORY_CONTRACT_ADDRESS docker-compose -f e2e-docker-compose.yml up -d state_runtime
sleep 10

# create working directory
#if [ ! -d "$ANONIFY_ROOT"/_work ]; then
#  mkdir "$ANONIFY_ROOT"/_work
#else
#  echo "_work directory already exists"
#fi
#cd "$ANONIFY_ROOT"/_work


#cd $HOME
#if [ ! -d ${ANONIFY_ROOT} ]; then
#    git clone -b $ANONIFY_TAG https://github.com/LayerXcom/anonify.git
#else
#    cd ${ANONIFY_ROOT}
#    tag_id=`git show $ANONIFY_TAG | grep commit | cut -f 2 -d ' '`
#    current_commit_id=`git rev-parse HEAD`
#    if [ $tag_id = $current_commit_id ]; then
#        echo "already cloned anonify(skipped)"
#    else
#        echo "already exists anonify directory, but doesn't match commit id with specified by tag"
#        exit 1
#    fi
#fi
#
#if ! curl "$STATE_RUNTIME_URL"/api/v1/enclave_encryption_key -s -f -k -X GET -H "Content-Type: application/json" -d '' 1> pubkey.json; then
#  echo "failed to fetch pubkey.json"
#  exit 1
#fi
#"$ANONIFY_ROOT"/target/debug/perf-cli fixture enc -k pubkey.json -i "$ANONIFY_ROOT"/tools/fixtures/init.json
#
#if ! curl "$STATE_RUNTIME_URL"/api/v1/state -k -s -X POST -H "Content-Type: application/json" -d @encrypted_init.json; then
#  echo "failed to send init.json"
#  exit 1
#fi
