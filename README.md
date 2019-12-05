# anonify
A trusted anonymization tool for any blockchain

## Setup
```
$ docker pull osuketh/anonify
$ git clone git@github.com:LayerXcom/anonify.git
$ cd anonify
$ docker run -v `pwd`:/root/anonify --rm -it osuketh/anonify
```

## Building contracts
```
$ solc -o build --bin --abi --optimize --overwrite contracts/AnonymousAsset.sol
```

## Running

### SW
This tutorial works in simulation mode, so you can run it on macos.

* Core

```
$ cd anonify/core
$ export SGX_MODE=SW
$ make
$ cd bin && ./anonify-host
```

### HW
Assumed your hardware supports Intel SGX.

```
$ docker run -v `pwd`:/root/anonify --device /dev/isgx  --rm -it osuketh/anonify
```

After entering docker container, the very first thing is to start aesm service daemon.

```
$ LD_LIBRARY_PATH=/opt/intel/libsgx-enclave-common/aesm /opt/intel/libsgx-enclave-common/aesm/aesm_service
```
