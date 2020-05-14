# anonify
A blockchain-agnostic execution environment with privacy and auditability

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

## Running anonify server
Using docker-compose, you can start server.
```
$ docker-compose -f docker/docker-compose-anonify.yml up -d
```

If you want to build artifacts in release mode, pass a `--release` argument. Any enclave needs to be whitelisted to be able to be launched in release mode.
```
$ ./scripts/run-server.sh --release
```

## Building CLI
You can use anonify-cli to communicate with a whole anonify system.

Build anonify's command line utilities.
```
$ ./scripts/build-cli.sh
```

If you want to build artifacts in release mode, pass a `--release` argument.
```
$ ./scripts/build-cli.sh --release
```

## Documentations

- [Anonify-book](https://layerxcom.github.io/anonify-book/)


## License

Anonify is primarily distributed under the terms of the [Apache License (Version 2.0)], see [LICENSE](https://github.com/LayerXcom/anonify/blob/master/LICENSE) for details.