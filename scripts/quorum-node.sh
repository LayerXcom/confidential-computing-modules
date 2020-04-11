UDS_WAIT=10
for i in $$(seq 1 100)
do
    set -e
    if [ -S $${PRIVATE_CONFIG} ] && \
        [ "I'm up!" == "$$(wget --timeout $${UDS_WAIT} -qO- --proxy off 172.16.239.10$${NODE_ID}:9000/upcheck)" ];
    then break
    else
        echo "Sleep $${UDS_WAIT} seconds. Waiting for TxManager."
        sleep $${UDS_WAIT}
    fi
done
DDIR=/qdata/dd
rm -rf $${DDIR}
mkdir -p $${DDIR}/keystore
mkdir -p $${DDIR}/geth
cp /examples/raft/nodekey$${NODE_ID} $${DDIR}/geth/nodekey
cp /examples/keys/key$${NODE_ID} $${DDIR}/keystore/
cat /examples/permissioned-nodes.json | sed 's/^\(.*\)@.*\?\(.*\)raftport=5040\([0-9]\)\(.*\)$$/\1@172.16.239.1\3:21000?discport=0\&raftport=50400\4/g' > $${DDIR}/static-nodes.json
cp $${DDIR}/static-nodes.json $${DDIR}/permissioned-nodes.json
cat $${DDIR}/static-nodes.json
GENESIS_FILE="/examples/istanbul-genesis.json"
if [ "${QUORUM_CONSENSUS:-istanbul}" == "raft" ]; then
    GENESIS_FILE="/examples/genesis.json"
fi
NETWORK_ID=$$(cat $${GENESIS_FILE} | grep chainId | awk -F " " '{print $$2}' | awk -F "," '{print $$1}')
GETH_ARGS_raft="--raft --raftport 50400"
GETH_ARGS_istanbul="--emitcheckpoints --istanbul.blockperiod 1 --mine --minerthreads 1 --syncmode full"
geth --datadir $${DDIR} init $${GENESIS_FILE}
geth \
    --identity node$${NODE_ID}-${QUORUM_CONSENSUS:-istanbul} \
    --datadir $${DDIR} \
    --permissioned \
    --nodiscover \
    --verbosity 5 \
    --networkid $${NETWORK_ID} \
    --rpc \
    --rpcvhosts=* \
    --rpcaddr 0.0.0.0 \
    --rpcport 8545 \
    --rpcapi admin,db,eth,debug,miner,net,shh,txpool,personal,web3,quorum,${QUORUM_CONSENSUS:-istanbul} \
    --port 21000 \
    --unlock 0 \
    --password /examples/passwords.txt \
    ${QUORUM_GETH_ARGS:-} $${GETH_ARGS_${QUORUM_CONSENSUS:-istanbul}}
    