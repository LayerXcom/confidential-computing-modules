# anonify
A trusted anonymization tool for any blockchain

## Directory structure
wip

## Setup
```
$ docker pull osuketh/anonify
$ git clone git@github.com:LayerXcom/anonify.git
$ cd anonify
```

Building contracts
```
$ solc -o build --bin --abi --optimize --overwrite contracts/Anonify.sol
```

## Building in SW
You can just build the core component in simulation mode which allows us to run on macOS.

```
$ docker run -v `pwd`:/root/anonify --rm -it osuketh/anonify
$ cd anonify/core
$ make DEBUG=1
```

## Testing in HW
Assumed your hardware supports Intel SGX or run it on [Azure Confidential Computing](https://azure.microsoft.com/ja-jp/solutions/confidential-compute/).

The very first thing you need to do is starting aesm service in a SGX-enabled environment. For more details, see: https://github.com/apache/incubator-teaclave-sgx-sdk/blob/master/documents/sgx_in_mesalock_linux.md#solution-overview
```
LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service
```

If you haven't create a docker network for testing:
```
$ docker network create --subnet=172.18.0.0/16 test-network
```

Running ganache-cli
```
$ docker run -d --name ganache --net=test-network --rm -it trufflesuite/ganache-cli
```

Running intel SGX environment
```
$ ./scripts/start-docker.sh
```

and then, you can build in HW mode.
```
$ cd anonify/core
$ make DEBUG=1
```

Finally, you can test SGX parts.
```
$ cd host
$ cargo test
```

## Running anonify server

### Using docker
```
$ docker-compose -f docker/docker-compose-anonify.yml up -d
```

### Non-docker
```
$ ./scripts/run-server.sh
```

If you want to build artifacts in release mode, pass a `--release` argument. Any enclave needs to be whitelisted to be able to be launched in release mode.
```
$ ./scripts/run-server.sh --release
```

## CLI Usage
You can use anonify-cli to communicate with a whole anonify system.

Build anonify's command line utilities.
```
$ ./scripts/build-cli.sh
```

If you want to build artifacts in release mode, pass a `--release` argument.
```
$ ./scripts/build-cli.sh --release
```

### Wallet operations

- Initialize a new wallet
```
$ ./target/debug/anonify-cli wallet init
```

- Add a new account into your wallet
```
$  ./target/debug/anonify-cli wallet add-account
```

- Show a list of your accounts
```
$ ./target/debug/anonify-cli wallet list
```

### Anonify operations

- Deploy a anonymous-asset contract
```
$ ./target/debug/anonify-cli anonify deploy
```
return: a contract address
You can set the contract address to a environment variable `CONTRACT_ADDR`.

- Register a enclave integrity to contract
```
$ ./target/debug/anonify-cli anonify register
```

- Initialize state
```
$ ./target/debug/anonify-cli anonify init_state -t <TOTAL SUPPLY>
```
Default `<AMOUNT>` is 100.

- Transfer
```
$ ./target/debug/anonify-cli anonify transfer -a <AMOUNT> -t <TARGET_ACCOUNT>
```
Default `<AMOUNT>` is 10.

- Get state from enclave
```
$ ./target/debug/anonify-cli anonify get_state -i <KEYFILE_INDEX>
```
Default `<KEYFILE_INDEX>` is 0.

- Start fetching events
```
$ ./target/debug/anonify-cli anonify start_polling
```

- Key rotation
```
$ ./target/debug/anonify-cli anonify key_rotation
```

## Acknowledgements

- [Rust SGX SDK](https://github.com/apache/incubator-teaclave-sgx-sdk)
- [Molasses](https://github.com/trailofbits/molasses)
