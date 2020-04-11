DDIR=/qdata/tm
rm -rf $${DDIR}
mkdir -p $${DDIR}
DOCKER_IMAGE="${QUORUM_TX_MANAGER_DOCKER_IMAGE:-quorumengineering/tessera:0.10.0}"
TX_MANAGER=$$(echo $${DOCKER_IMAGE} | sed 's/^.*\/\(.*\):.*$$/\1/g')
echo "TxManager: $${TX_MANAGER}"
case $${TX_MANAGER}
in
tessera)
    cp /examples/keys/tm$${NODE_ID}.pub $${DDIR}/tm.pub
    cp /examples/keys/tm$${NODE_ID}.key $${DDIR}/tm.key
    #extract the tessera version from the jar
    TESSERA_VERSION=$$(unzip -p /tessera/tessera-app.jar META-INF/MANIFEST.MF | grep Tessera-Version | cut -d" " -f2)
    echo "Tessera version (extracted from manifest file): $${TESSERA_VERSION}"
    # sorting versions to target correct configuration
    V08=$$(echo -e "0.8\n$${TESSERA_VERSION}" | sort -n -r -t '.' -k 1,1 -k 2,2 | head -n1)
    V09AndAbove=$$(echo -e "0.9\n$${TESSERA_VERSION}" | sort -n -r -t '.' -k 1,1 -k 2,2 | head -n1)
    TESSERA_CONFIG_TYPE="-09"
    case "$${TESSERA_VERSION}" in
        "$${V09AndAbove}")
            TESSERA_CONFIG_TYPE="-09"
            ;;
    esac

    echo Config type $${TESSERA_CONFIG_TYPE}

    #generating the two config flavors
    cat <<EOF > $${DDIR}/tessera-config-09.json
    {
    "useWhiteList": false,
    "jdbc": {
        "username": "sa",
        "password": "",
        "url": "jdbc:h2:./$${DDIR}/db;MODE=Oracle;TRACE_LEVEL_SYSTEM_OUT=0",
        "autoCreateTables": true
    },
    "serverConfigs":[
    {
        "app":"ThirdParty",
        "enabled": true,
        "serverAddress": "http://$$(hostname -i):9080",
        "communicationType" : "REST"
    },
    {
        "app":"Q2T",
        "enabled": true,
        "serverAddress": "unix:$${DDIR}/tm.ipc",
        "communicationType" : "REST"
    },
    {
        "app":"P2P",
        "enabled": true,
        "serverAddress": "http://$$(hostname -i):9000",
        "sslConfig": {
        "tls": "OFF"
        },
        "communicationType" : "REST"
    }
    ],
    "peer": [
        {
            "url": "http://txmanager1:9000"
        },
        {
            "url": "http://txmanager2:9000"
        },
        {
            "url": "http://txmanager3:9000"
        }
    ],
    "keys": {
        "passwords": [],
        "keyData": [
        {
            "config": $$(cat $${DDIR}/tm.key),
            "publicKey": "$$(cat $${DDIR}/tm.pub)"
        }
        ]
    },
    "alwaysSendTo": []
    }
EOF
    cat $${DDIR}/tessera-config$${TESSERA_CONFIG_TYPE}.json
    java -Xms128M -Xmx128M -jar /tessera/tessera-app.jar -configfile $${DDIR}/tessera-config$${TESSERA_CONFIG_TYPE}.json
    ;;
constellation)
    echo "socket=\"$${DDIR}/tm.ipc\"\npublickeys=[\"/examples/keys/tm$${NODE_ID}.pub\"]\n" > $${DDIR}/tm.conf
    constellation-node \
    --url=http://$$(hostname -i):9000/ \
    --port=9000 \
    --socket=$${DDIR}/tm.ipc \
    --othernodes=http://172.16.239.101:9000/,http://172.16.239.102:9000/,http://172.16.239.103:9000/,http://172.16.239.104:9000/,http://172.16.239.105:9000/ \
    --publickeys=/examples/keys/tm$${NODE_ID}.pub \
    --privatekeys=/examples/keys/tm$${NODE_ID}.key \
    --storage=$${DDIR} \
    --verbosity=4
    ;;
*)
    echo "Invalid Transaction Manager"
    exit 1
    ;;
esac
