const sodium = require('libsodium-wrappers');
const axiosBase = require('axios');

const encrypt = ([pubkey, msg]) => {
    const pk_server_raw = Buffer.from(
        JSON.parse(pubkey).enclave_encryption_key
    ).toString('hex');
    const pair_client = sodium.crypto_box_keypair();
    const sk_client = pair_client.privateKey;
    const pk_client = pair_client.publicKey;

    const pk_server = sodium.from_hex(pk_server_raw);

    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES);

    const ciphertext = sodium.crypto_box_easy(msg, nonce, pk_server, sk_client);
    const encrypted = {
        "ciphertext": Buffer.from(ciphertext).toString('hex'),
        "ephemeral_public_key": Buffer.from(pk_client).toString('hex'),
        "nonce": Buffer.from(nonce).toString('hex')
    };

    return JSON.stringify(encrypted);
};

const generate_init_state_request = () => {
    const init = {
        "access_policy": {
            "account_id": [216, 211, 74, 222, 192, 13, 199, 12, 37, 58, 141, 38, 252, 74, 55, 83, 152, 119, 212, 147]
        },
        "runtime_params": {
            "total_supply": 100,
        },
        "cmd_name": "construct",
        "counter": 1,
    };
    return JSON.stringify(init);
}

const generate_balance_of_request = () => {
    const init = {
        "access_policy": {
            "account_id": [216, 211, 74, 222, 192, 13, 199, 12, 37, 58, 141, 38, 252, 74, 55, 83, 152, 119, 212, 147]
        },
        "runtime_params": {},
        "state_name": "balance_of",
    };
    return JSON.stringify(init);
}


(async () => {
    const axios = axiosBase.create({
        baseURL: 'http://0.0.0.0:18550',
        headers: {
            'Content-Type': 'application/json',
        },
        responseType: 'json'
    });

    // init state
    axios.get('/api/v1/enclave_encryption_key')
        .then((res) => { return [JSON.stringify(res.data), generate_init_state_request()]; })
        .catch((err) => {
            console.log('ERROR in enclave_encryption_key: ' + err);
            process.exit(1);
        })
        .then(encrypt)
        .then(
            (encrypted) => {
                axios.post('/api/v1/state', encrypted)
                    .then((res) => { return JSON.stringify(res.data); })
                    .catch((err) => {
                        console.log('ERROR in init_state: ' + err);
                        process.exit(1);
                    })
            }
        );

    // confirm whether the state is updated or not
    setTimeout(() => {
        axios.get('/api/v1/enclave_encryption_key')
            .then((res) => { return [JSON.stringify(res.data), generate_balance_of_request()]; })
            .catch((err) => {
                console.log('ERROR in enclave_encryption_key: ' + err);
                process.exit(1);
            })
            .then(encrypt)
            .then(async (encrypted) => {
                const state = await axios.get('/api/v1/state', { data: encrypted, })
                    .then((res) => { return JSON.stringify(res.data); })
                    .catch((err) => {
                        console.log('ERROR in balance_of: ' + err);
                        process.exit(1);
                    });
                return state;
            })
            .then((result) => {
                const balance = JSON.parse(result).state;
                if (balance !== 100) {
                    console.log('go unexpected balance');
                    process.exit(1);
                }
            })
    }, 1000);
})();
