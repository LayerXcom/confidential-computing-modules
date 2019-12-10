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
Assumed your hardware supports Intel SGX or run in on [Azure Confidential Computing](https://azure.microsoft.com/ja-jp/solutions/confidential-compute/).

```
$ docker run -v `pwd`:/root/anonify --device /dev/isgx --network="host" --rm -it osuketh/anonify
```
- The SDK Driver creates a device at `/dev/isgx`, non-DCAP systems using IAS.
- Use `--network="host"` for Docker-for-Linux, then `127.0.0.1` in your docker container will point to your docker host. It'll be used by the ganache-cli testing.

After entering docker container, the very first thing is to start aesm service daemon.

```
$ LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service
```

and then, you can run build and test in HW mode.
```
$ export SGX_MODE=HW
$ cd anonify/core
$ make DEBUG=1
$ cd host
$ cargo test
```
