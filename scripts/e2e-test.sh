#!/bin/bash
set -e

export ANONIFY_TAG=v0.5.10
export DEPLOYER_TAG=v0.5.12
export STATE_RUNTIME_URL=http://0.0.0.0:18550
export ETH_URL=http://172.16.14.2:8545
export COMPOSE_NETWORK_PREFIX=s
CI_ROOT_DIR=$(pwd)

echo "ganache is starting..."
docker-compose -f e2e-docker-compose.yml up -d ganache
sleep 5

echo "deploying factory contract..."
FACTORY_CONTRACT_ADDRESS=$(docker run --network "$COMPOSE_NETWORK_PREFIX"_e2e_test_net -e CONFIRMATIONS=0 -e ETH_URL="$ETH_URL" --rm anonify.azurecr.io/deployer:$DEPLOYER_TAG factory)
export FACTORY_CONTRACT_ADDRESS=$FACTORY_CONTRACT_ADDRESS
echo "FACTORY_CONTRACT_ADDRESS: ""$FACTORY_CONTRACT_ADDRESS"

echo "deploying anonify contract..."
docker run --network "$COMPOSE_NETWORK_PREFIX"_e2e_test_net -e CONFIRMATIONS=0 -e ETH_URL="$ETH_URL" --rm anonify.azurecr.io/deployer:$DEPLOYER_TAG anonify_ek "$FACTORY_CONTRACT_ADDRESS"

echo "key_vault is starting..."
FACTORY_CONTRACT_ADDRESS=$FACTORY_CONTRACT_ADDRESS docker-compose -f e2e-docker-compose.yml up -d key_vault
sleep 5

echo "state_runtime_1 is starting..."
FACTORY_CONTRACT_ADDRESS=$FACTORY_CONTRACT_ADDRESS docker-compose -f e2e-docker-compose.yml up -d state_runtime
sleep 10

cd "$CI_ROOT_DIR"

pubkey=$(curl "$STATE_RUNTIME_URL"/api/v1/enclave_encryption_key -s -f -k -X GET -H "Content-Type: application/json" -d '')
if [[ $pubkey == *"enclave_encryption_key"* ]]; then
  echo $pubkey
else
  echo "failed to fetch enclave_encryption_key"
  exit 1
fi

cd "$CI_ROOT_DIR"
npm init -y
npm install axios
npm install libsodium-wrappers

if ! node ./scripts/client.js; then
    echo "js client failed..."
    exit 1
fi