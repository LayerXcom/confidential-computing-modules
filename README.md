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

Copy files of environment variables.
```
$ cp .env.template .env
$ cp example/server/.env.template example/server/.env
```

## Building contracts
```
$ solc -o build --bin --abi --optimize --overwrite contracts/AnonymousAsset.sol
```

## Running

### SW
You can just build the core component in simulation mode which allows us to run on macos.

```
$ docker run -v `pwd`:/root/anonify --rm -it osuketh/anonify
$ cd anonify/core
$ make DEBUG=1
```

### HW
Assumed your hardware supports Intel SGX or run it on [Azure Confidential Computing](https://azure.microsoft.com/ja-jp/solutions/confidential-compute/).

If you don't have a docket network for testing: (Docker compose doesn't be working currently due to AESM service deamon.)
```
$ docker network create --subnet=172.18.0.0/16 test-network
```

Running ganache-cli
```
$ docker run -d --name ganache --net=test-network --rm -it trufflesuite/ganache-cli
```

Running intel SGX environment
```
$ docker run -v `pwd`:/root/anonify --device /dev/isgx --net=test-network --name sgx --rm -it osuketh/anonify
```
- The SDK Driver creates a device at `/dev/isgx`, non-DCAP systems using IAS.


### Test

After entering docker container, the very first thing is to start aesm service daemon.

```
$ LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service
```

and then, you can run build in HW mode.
```
$ export SGX_MODE=HW
$ cd anonify/core
$ make DEBUG=1
```

Finally, you can test in core-host.
```
$ cd host
$ cargo test
```

### Running server
```
$ ./scripts/run-server.sh
```

If you want to build artifacts in release mode, pass a `--release` argument. Any enclave needs to be whitelisted to be able to be launched in release mode.
```
$ ./scripts/run-server.sh --release
```

### CLI Usage
You can use anonify-cli to communicate with a whole anonify system.

Build anonify's command line utilities.
```
$ ./scripts/build-cli.sh
```

If you want to build artifacts in release mode, pass a `--release` argument.
```
$ ./scripts/build-cli.sh --release
```

#### Wallet operations

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

#### Anonify operations

- Deploy a anonymous-asset contract
```
$ ./target/debug/anonify-cli anonify deploy -t <TOTAL SUPPLY>
```

- Get state from enclave
```
$ ./target/debug/anonify-cli anonify state -c <CONTRACT ADDRESS w/o "0x">
```

- Transfer assets
```
$ ./target/debug/anonify-cli anonify send -a <AMOUNT> -t <TARGET_ACCOUNT> -c <CONTRACT ADDRESS w/o "0x">
```
