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
$ solc -o build --bin --abi --optimize --overwrite contracts/AnonymousERC20.sol
```

## Running
This tutorial works in simulation mode, so you can run it on macos.

* Helloworld

```
$ cd anonify/helloworld
$ export SGX_MODE=SW
$ make
$ cd bin && ./app
```

* Core

```
$ cd anonify/core
$ export SGX_MODE=SW
$ make
$ cd bin && ./anonify-app
```
